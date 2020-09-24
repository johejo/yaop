package yaop

import (
	"context"
	"encoding/base64"
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
	mux       http.Handler
	config    *ServerConfig
	providers ProviderStorage
}

var _ http.Handler = (*Server)(nil)

func NewServer(ctx context.Context, config *ServerConfig, providers ProviderStorage) (*Server, error) {
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
	r.Get(s.config.Prefix+"/api/v0/token", s.Token)
	s.mux = r
	s.providers = providers

	return s, nil
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
	p, err := s.providers.Load(ctx, providerName)
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
		Path:     s.config.Prefix + "/callback",
		Domain:   getDomain(r),
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
		Domain:   getDomain(r),
	})
}

func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
	// clear csrf cookie
	defer s.setCsrfCookie(w, r, "", -1*time.Hour)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request param", http.StatusBadRequest)
		return
	}

	errString := r.Form.Get("error")
	if errString != "" {
		log.Printf("[ERROR] callback error: %v", errString)
		http.Error(w, "callback error", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		log.Printf("[ERROR] code does not exist in callback: %v", code)
		http.Error(w, "no code", http.StatusBadRequest)
		return
	}

	encodedState := r.Form.Get("state")
	if encodedState == "" {
		log.Printf("[ERROR] state does not exist in callback")
		http.Error(w, "no state", http.StatusBadRequest)
		return
	}

	formState, err := decodeState(encodedState)
	if err != nil {
		log.Printf("[ERROR] invalid state signature: %v", encodedState)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	csrfCookie, err := r.Cookie(s.config.CsrfCookieName())
	if err != nil {
		http.Error(w, "no csrf cookie", http.StatusBadRequest)
		return
	}

	csrfCookieValue, err := decodeCsrfCookieValue(csrfCookie.Value)
	if err != nil {
		http.Error(w, "invalid csrf cookie", http.StatusBadRequest)
		return
	}

	cookieState, err := decodeState(csrfCookieValue.EncodedState)
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
	p, err := s.providers.Load(ctx, st.Provider)
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
	_ = email
}

func (s *Server) Auth(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {

}

type state struct {
	CsrfToken string `msgpack:"csrf_token"`
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

func getDomain(r *http.Request) string {
	return r.URL.Hostname()
}
