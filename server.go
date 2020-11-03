package yaop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/handlers"
	"github.com/vmihailenco/msgpack/v5"
)

type cookieEncodeDecoder interface {
	Decode(name, value string, std interface{}) error
	Encode(name string, value interface{}) (string, error)
}

type formDecoder interface {
}

type Server struct {
	mux             http.Handler
	config          *ServerConfig
	providerStorage ProviderStorage
	settionStorage  SessionStorage
}

var _ http.Handler = (*Server)(nil)

func NewServer(ctx context.Context, config *ServerConfig, providerStorage ProviderStorage, sessionStorage SessionStorage) (*Server, error) {
	s := new(Server)

	r := chi.NewRouter()
	r.Use(
		middleware.Recoverer,
		middleware.RealIP,
		handlers.ProxyHeaders,
		noCache,
		middleware.Logger,
	)
	r.Get(s.config.Prefix+"/start", s.Start)
	r.Group(func(r chi.Router) {
		// POST or GET
		r.Get(s.config.Prefix+"/callback", s.Callback)
		r.Post(s.config.Prefix+"/callback", s.Callback)
	})
	r.Get(s.config.Prefix+"/auth", s.Auth)
	r.Route("/api/v0/providers", func(r chi.Router) {
		r.Put("/", s.PutProvider)
		r.Get("/", s.GetProviders)
		r.Get("/{name}", s.GetProvider)
		r.Delete("/{name}", s.DeleteProvider)
	})

	s.mux = r
	s.providerStorage = providerStorage
	s.settionStorage = sessionStorage
	s.config = config

	return s, nil
}

func (s *Server) PutProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var pj providerJSON
	if err := json.NewDecoder(r.Body).Decode(&pj); err != nil {
		log.Printf("[INFO] invalid body: %v", err)
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	p, err := DecodeProvider(&pj)
	if err != nil {
		log.Printf("[INFO] invalid provider: %v", err)
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}
	if err := s.providerStorage.Store(ctx, p.GetName(), p); err != nil {
		log.Printf("[ERROR] failed to store provider: %v", err)
		http.Error(w, "failed to store provider", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providers, err := s.providerStorage.LoadAll(ctx)
	if err != nil {
		log.Printf("[ERROR] failed to load providers: %v", err)
		http.Error(w, "failed to load providers", http.StatusInternalServerError)
		return
	}
	respondJSON(w, providers, http.StatusOK)
}

func (s *Server) GetProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	p, err := s.providerStorage.Load(ctx, name)
	if err != nil {
		log.Printf("[INFO] provider %s was not found: %v", name, err)
		http.Error(w, "no provider", http.StatusNotFound)
		return
	}
	respondJSON(w, p, http.StatusOK)
}

func (s *Server) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	if err := s.providerStorage.Delete(ctx, name); err != nil {
		log.Printf("[INFO] provider %s was not found: %v", name, err)
		http.Error(w, "no provider", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type csrfCookieValue struct {
	EncodedState string `msgpack:"encodedState"`
}

func newCsrfCookieValue(state string) *csrfCookieValue {
	return &csrfCookieValue{EncodedState: state}
}

func decodeCsrfCookieValue(raw string) (*csrfCookieValue, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var v csrfCookieValue
	if err := msgpack.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (v *csrfCookieValue) EncodeToString() (string, error) {
	b, err := msgpack.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *Server) Start(w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		http.Error(w, "no providers were specified", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	p, err := s.providerStorage.Load(ctx, providerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	next, err := s.getNext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state := newState(next)
	encodedState, err := state.EncodeToString()
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	encodedCookieValue, err := newCsrfCookieValue(encodedState).EncodeToString()
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.setCsrfCookie(w, r, encodedCookieValue, 1*time.Hour)

	http.Redirect(
		w, r,
		p.AuthCodeURL(encodedState, s.getCallbackURL(r)),
		http.StatusFound,
	)
}

func (s *Server) getNext(r *http.Request) (string, error) {
	next := r.URL.Query().Get("next")
	if next == "" {
		return "/", nil
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		log.Println(err)
		return "", errors.New("invalid next url")
	}
	switch nextURL.Host {
	// same host?
	case r.Host, r.URL.Host:
		return nextURL.String(), nil
	}
	// is relative?
	if nextURL.Host == "" && strings.HasPrefix(nextURL.Path, "/") {
		return nextURL.String(), nil
	}
	return "", errors.New("invalid next url")
}

func (s *Server) getCallbackURL(r *http.Request) string {
	clone := *r.URL
	clone.Path = s.config.Prefix + "/callback"
	clone.Fragment = ""
	clone.RawQuery = ""
	return clone.String()
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name string, value string, expiresIn time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  timeNow().Add(expiresIn),
		SameSite: s.config.Cookie.SameSite,
		HttpOnly: s.config.Cookie.HttpOnly,
		Secure:   s.config.Cookie.Secure,
		Path:     "/",
		Domain:   r.URL.Hostname(),
	})
}

func (s *Server) setCsrfCookie(w http.ResponseWriter, r *http.Request, value string, expiresIn time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.config.CsrfCookieName(),
		Value:    value,
		Expires:  timeNow().Add(expiresIn),
		SameSite: http.SameSiteNoneMode, // cross site cookie
		HttpOnly: s.config.Cookie.HttpOnly,
		Secure:   s.config.Cookie.Secure,
		Path:     s.config.Prefix + "/callback",
		Domain:   r.URL.Hostname(),
	})
}

func decodeStateFromForm(r *http.Request) (*state, string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, "", err
	}

	errString := r.Form.Get("error")
	if errString != "" {
		return nil, "", fmt.Errorf("callback error: %s", errString)
	}

	code := r.Form.Get("code")
	if code == "" {
		return nil, "", errors.New("no code in form")
	}

	encodedState := r.Form.Get("state")
	if encodedState == "" {
		return nil, "", errors.New("no state in form")
	}

	formState, err := decodeState(encodedState)
	if err != nil {
		return nil, "", err
	}
	return formState, code, nil
}

func (s *Server) decodeStateFromCsrfCookie(r *http.Request) (*state, error) {
	csrfCookie, err := r.Cookie(s.config.CsrfCookieName())
	if err != nil {
		return nil, err
	}

	csrfCookieValue, err := decodeCsrfCookieValue(csrfCookie.Value)
	if err != nil {
		return nil, err
	}

	cookieState, err := decodeState(csrfCookieValue.EncodedState)
	if err != nil {
		return nil, err
	}
	return cookieState, nil
}

func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
	// clear csrf cookie
	defer s.setCsrfCookie(w, r, "", -1*time.Hour)

	formState, code, err := decodeStateFromForm(r)
	if err != nil {
		log.Printf("[ERROR] failed to decode state from form")
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	cookieState, err := s.decodeStateFromCsrfCookie(r)
	if err != nil {
		http.Error(w, "invalid csrf cookie", http.StatusBadRequest)
		return
	}

	if formState.CsrfToken != cookieState.CsrfToken {
		http.Error(w, "invalid csrf token", http.StatusBadRequest)
		return
	}
	if formState.Next != cookieState.Next {
		http.Error(w, "invalid next url", http.StatusBadRequest)
		return
	}

	st := formState
	ctx := r.Context()
	p, err := s.providerStorage.Load(ctx, st.Provider)
	if err != nil {
		log.Printf("[ERROR] no provider %s %v", st.Provider, err)
		http.Error(w, fmt.Sprintf("provider %s does not exist", st.Provider), http.StatusInternalServerError)
		return
	}

	token, err := p.Exchange(ctx, code, s.getCallbackURL(r))
	if err != nil {
		log.Printf("[ERROR] exchange error %v", err)
		http.Error(w, "exchange error", http.StatusInternalServerError)
		return
	}

	email, err := p.GetEmailAddress(ctx, token)
	if err != nil {
		log.Printf("[ERROR] get email error %v", err)
		http.Error(w, "get email error", http.StatusInternalServerError)
		return
	}

	sess := newSession(email, token)
	cookieValue, err := s.settionStorage.Store(ctx, sess)
	if err != nil {
		log.Printf("[ERROR] store session error %v", err)
		http.Error(w, "store session error", http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, s.config.Cookie.Name, cookieValue, s.config.Cookie.ExpiresIn)

	http.Redirect(w, r, st.Next, http.StatusFound)
}

func (s *Server) Auth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(s.config.Cookie.Name)
	if err != nil {
		http.Error(w, "no cookie", http.StatusUnauthorized)
		return
	}
	sess, err := s.settionStorage.Load(ctx, c.Value)
	if err != nil {
		log.Printf("[ERROR] loading session %v", err)
		http.Error(w, "error at loading session", http.StatusInternalServerError)
		return
	}
	log.Printf("%v", sess)
	w.WriteHeader(http.StatusOK)
}

type state struct {
	CsrfToken string `msgpack:"csrfToken"`
	Next      string `msgpack:"next"`
	Provider  string `msgpack:"provider"`
}

func newState(next string) *state {
	return &state{CsrfToken: genSecret(), Next: next}
}

func (s *state) EncodeToString() (string, error) {
	b, err := msgpack.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func decodeState(raw string) (*state, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var st state
	if err := msgpack.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

type ServerConfig struct {
	Prefix       string
	ProviderType string

	Cookie *CookieConfig

	httpClient *http.Client // customizable

	AllowedDomains []string
}

func (c *ServerConfig) CsrfCookieName() string {
	return c.Cookie.Name + c.Cookie.CsrfSuffix
}

type CookieConfig struct {
	HashKey  string
	BlockKey string

	Name       string
	CsrfSuffix string
	ExpiresIn  time.Duration
	SameSite   http.SameSite
	HttpOnly   bool
	Secure     bool
}
