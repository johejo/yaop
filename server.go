package yaop

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	gogithub "github.com/google/go-github/v32/github"
	"github.com/gorilla/handlers"
	"github.com/gorilla/securecookie"
	"github.com/sethvargo/go-password/password"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type Server struct {
	mux          http.Handler
	config       *ServerConfig
	providers    ProviderStorage
	secureCookie *securecookie.SecureCookie
}

var _ http.Handler = (*Server)(nil)

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
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

	s.secureCookie = securecookie.New([]byte(config.Cookie.HashKey), []byte(config.Cookie.BlockKey))
	s.secureCookie.SetSerializer(msgpackSerializer{})

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
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
	stateBytes, err := msgpack.Marshal(state)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stateString := base64.URLEncoding.EncodeToString(stateBytes)
	domain := r.URL.Hostname()
	if domain == "" {
		_host := strings.Split(r.Host, ":")
		if len(_host) >= 1 {
			domain = _host[0]
		}
	}
	csrfCookie := &http.Cookie{
		Name:     s.config.Cookie.Name + "_csrf",
		Value:    stateString,
		Expires:  timeNow().Add(1 * time.Hour),
		SameSite: s.config.Cookie.SameSite,
		HttpOnly: s.config.Cookie.HttpOnly,
		Secure:   s.config.Cookie.Secure,
		Path:     s.config.Prefix + "/callback",
		Domain:   domain,
	}
	http.SetCookie(w, csrfCookie)

	http.Redirect(
		w, r,
		p.AuthCodeURL(stateString, s.getCallbackURL(r)),
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

func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) Auth(w http.ResponseWriter, r *http.Request) {

}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {

}

type state struct {
	Secret string `msgpack:"secret"`
	Next   string `msgpack:"next"`
}

func newState(next string) *state {
	return &state{Secret: genSecret(), Next: next}
}

func genSecret() string {
	return password.MustGenerate(32, 8, 0, false, false)
}

type ServerConfig struct {
	Prefix       string
	ProviderType string

	Cookie *CookieConfig

	httpClient *http.Client // customizable

	AllowedDomains []string
}

type CookieConfig struct {
	HashKey  string
	BlockKey string

	Name      string
	ExpiresIn time.Duration
	SameSite  http.SameSite
	HttpOnly  bool
	Secure    bool
}

type ProviderStorage interface {
	Load(ctx context.Context, name string) (Provider, error)
}

var _ ProviderStorage = (*InMemoryProviderStorage)(nil)

type InMemoryProviderStorage struct {
	store sync.Map
}

func (ps *InMemoryProviderStorage) Load(ctx context.Context, name string) (Provider, error) {
	_p, ok := ps.store.Load(name)
	if !ok {
		return nil, fmt.Errorf("specified provider %s was not found", name)
	}
	p, ok := _p.(Provider)
	if !ok {
		return nil, errors.New("invalid provider")
	}
	return p, nil

}

type Provider interface {
	Name() string
	AuthCodeURL(state string, redirectURL string) string
	GetEmailAddress(ctx context.Context, sess *Session) (string, error)
}

var _ Provider = (*GitHubProvider)(nil)

type GitHubProvider struct {
	name   string
	config *GitHubProviderConfig
}

type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	Login        string
	AllowSignup  bool
}

func (p *GitHubProvider) Name() string {
	return p.name
}

func NewDefaultGitHubProvider(ctx context.Context, config *GitHubProviderConfig) (*GitHubProvider, error) {
	return NewGitHubProvider(ctx, "GitHub", config)
}

func NewGitHubProvider(ctx context.Context, name string, config *GitHubProviderConfig) (*GitHubProvider, error) {
	return &GitHubProvider{
		name:   name,
		config: config,
	}, nil
}

func (p *GitHubProvider) AuthCodeURL(state string, redirectURL string) string {
	config := &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.config.Scopes,
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("allow_signup", strconv.FormatBool(p.config.AllowSignup)),
		oauth2.SetAuthURLParam("nonce", genSecret()),
	}
	if p.config.Login != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login", p.config.Login))
	}
	return config.AuthCodeURL(state, opts...)
}

func (p *GitHubProvider) GetEmailAddress(ctx context.Context, sess *Session) (string, error) {
	// TODO support Team, Organization, Collaborator
	client := gogithub.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(sess.Token)))
	me, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", err
	}
	return me.GetEmail(), nil
}

type Session struct {
	Token *oauth2.Token
}

type ProviderConfig struct{}

type msgpackSerializer struct{}

var _ securecookie.Serializer = (*msgpackSerializer)(nil)

func (msgpackSerializer) Serialize(v interface{}) ([]byte, error) {
	return msgpack.Marshal(v)
}

func (msgpackSerializer) Deserialize(data []byte, dst interface{}) error {
	return msgpack.Unmarshal(data, dst)
}

type yaopError struct {
	httpStatus int
	msg        string
	err        error
}

var _ error = (*yaopError)(nil)

func (e *yaopError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("msg=%s, err=%v", e.msg, e.err.Error())
	}
	return fmt.Sprintf("msg=%s", e.msg)
}

func (e *yaopError) Unrap() error {
	if e.err != nil {
		return e.err
	}
	return nil
}

func wrapErr(httpStatus int, msg string, err error) error {
	return &yaopError{httpStatus: httpStatus, msg: msg, err: err}
}

func newErr(httpStatus int, msg string) error {
	return &yaopError{httpStatus: httpStatus, msg: msg}
}

var nowFunc func() time.Time = nil

func timeNow() time.Time {
	if nowFunc == nil {
		return time.Now()
	}
	return nowFunc()
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
