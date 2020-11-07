package yaop

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/handlers"
	"golang.org/x/oauth2"
)

var (
	//go:embed static/sign_in.html
	signInTmplContent string
)

type Server struct {
	mux             http.Handler
	config          ServerConfig
	providerStorage ProviderStorage
	sessionStorage  SessionStorage

	cookieConfig   CookieConfig
	upstreamConfig UpstreamConfig

	signInTmpl *template.Template

	httpClient *http.Client
}

func NewServer(ctx context.Context, config ServerConfig, cookieConfig CookieConfig, providerStorage ProviderStorage, sessionStorage SessionStorage, opts ...ServerOption) (*Server, error) {
	optionalConfig := new(serverOptionalConfig)
	for _, opt := range append([]ServerOption{
		WithSignInTmpl(template.Must(template.New("sign-in").Parse(signInTmplContent))),
		WithHTTPClient(http.DefaultClient),
	}, opts...) {
		opt(optionalConfig)
	}
	s := new(Server)
	s.config = config
	s.signInTmpl = optionalConfig.signInTmpl
	s.httpClient = optionalConfig.httpClient

	r := chi.NewRouter()
	r.Use(
		middleware.Recoverer,
		middleware.RealIP,
		handlers.ProxyHeaders,
		noCache,
		middleware.Logger,
		s.ctxWithHTTPClient,
	)
	r.Route(s.config.Prefix, func(r chi.Router) {
		r.Get("/sign-in", s.SignIn)
		r.Get("/sign-out", s.SignIn)
		r.Get("/start", s.Start)
		// POST or GET
		r.Group(func(r chi.Router) {
			r.Use(noCache)
			r.Get("/callback/{providerName}", s.Callback)
			r.Post("/callback/{providerName}", s.Callback)
			r.Get("/auth/{providerName}", s.Auth)
		})

		r.Route("/api/v0/providers", func(r chi.Router) {
			r.Use(noCache)
			r.Put("/", s.PutProvider)
			r.Get("/", s.GetProviders)
			r.Get("/{name}", s.GetProvider)
			r.Delete("/{name}", s.DeleteProvider)
		})

	})
	r.Group(func(r chi.Router) {
		r.Use(s.ctxWithSession)
		if optionalConfig.protected != nil {
			r.Mount("/", optionalConfig.protected)
		}
	})

	if optionalConfig.upstream.URL != "" {
		u, err := url.Parse(optionalConfig.upstream.URL)
		if err != nil {
			return nil, err
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.Director = s.director(u)
		r.Group(func(r chi.Router) {
			r.Use(s.ctxWithSession)
			r.Mount("/", proxy)
		})
		s.upstreamConfig = optionalConfig.upstream
	}

	s.mux = r
	s.providerStorage = providerStorage
	s.sessionStorage = sessionStorage
	s.config = config
	s.cookieConfig = cookieConfig

	return s, nil
}

func (s *Server) director(target *url.URL) func(r *http.Request) {
	// Copied from net/http/httputil reverseproxy.go
	targetQuery := target.RawQuery
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		ctx := req.Context()
		sess, err := SessionFromContext(ctx)
		if err != nil {
			return
		}
		v, err := encodeSessionToString(sess)
		if err != nil {
			return
		}
		req.Header.Set(s.upstreamConfig.PropergateSession.HeaderKey, v)
	}
}

var _ http.Handler = (*Server)(nil)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type signInTmplData struct {
	Names  []string
	Prefix string
	Next   string
}

func (s *Server) SignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	next, err := s.getNext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	providers, err := s.providerStorage.LoadAll(ctx)
	if err != nil {
		log.Printf("[ERROR] failed to load providers: %v", err)
		http.Error(w, "failed to load providers", http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.GetName())
	}
	data := signInTmplData{
		Names:  names,
		Prefix: s.config.Prefix,
		Next:   next,
	}

	if err := s.signInTmpl.ExecuteTemplate(w, "sign-in", data); err != nil {
		log.Printf("[ERROR] template exection error: %v", err)
	}
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

func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	log.Printf("[INFO] start server at %s", addr)
	return http.ListenAndServe(addr, s.mux)
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

	state := newState(next, providerName)
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
		return s.config.FirstPage, nil
	}
	nextURL, err := url.Parse(next)
	if err != nil {
		log.Println(err)
		return "", errors.New("invalid next url")
	}
	// TODO open redirect vulnerability ?
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
	clone.Host = r.Host
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
		SameSite: http.SameSite(s.cookieConfig.SameSite),
		HttpOnly: s.cookieConfig.HttpOnly,
		Secure:   s.cookieConfig.Secure,
		Path:     "/",
		Domain:   r.URL.Hostname(),
	})
}

func (s *Server) setCsrfCookie(w http.ResponseWriter, r *http.Request, value string, expiresIn time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieConfig.CsrfCookieName(),
		Value:    value,
		Expires:  timeNow().Add(expiresIn),
		SameSite: http.SameSiteNoneMode, // cross site cookie
		HttpOnly: s.cookieConfig.HttpOnly,
		Secure:   s.cookieConfig.Secure,
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
	csrfCookie, err := r.Cookie(s.cookieConfig.CsrfCookieName())
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

	providerName := chi.URLParam(r, "providerName")

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

	sess := newSession(email, providerName, token)
	cookieValue, err := s.sessionStorage.Store(ctx, sess)
	if err != nil {
		log.Printf("[ERROR] store session error %v", err)
		http.Error(w, "store session error", http.StatusInternalServerError)
		return
	}

	s.setCookie(w, r, s.cookieConfig.Name, cookieValue, s.cookieConfig.ExpiresIn)

	http.Redirect(w, r, st.Next, http.StatusFound)
}

func (s *Server) Auth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(s.cookieConfig.Name)
	if err != nil {
		http.Error(w, "no cookie", http.StatusUnauthorized)
		return
	}
	sess, err := s.sessionStorage.Load(ctx, c.Value)
	if err != nil {
		log.Printf("[ERROR] loading session %v", err)
		http.Error(w, "error at loading session", http.StatusInternalServerError)
		return
	}
	log.Printf("%v", sess)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) ctxWithHTTPClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, s.httpClient)))
	})
}

func (s *Server) ctxWithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		c, err := r.Cookie(s.cookieConfig.Name)
		if err != nil {
			http.Redirect(w, r, s.config.Prefix+"/sign-in", http.StatusFound)
			return
		}
		sess, err := s.sessionStorage.Load(ctx, c.Value)
		if err != nil {
			http.Redirect(w, r, s.config.Prefix+"/sign-in", http.StatusFound)
			return
		}
		log.Printf("[DEBUG] session: ok id=%s, email=%s, token=%s", sess.ID, sess.Email, sess.Token)
		next.ServeHTTP(w, r.WithContext(ContextWithSession(ctx, sess)))
	})
}
