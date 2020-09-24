package yaop

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	gogithub "github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type Provider interface {
	Name() string
	AuthCodeURL(state string, redirectURL string) string
	Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error)
	GetEmailAddress(ctx context.Context, token *oauth2.Token) (string, error)
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
	}
	if p.config.Login != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login", p.config.Login))
	}
	return config.AuthCodeURL(state, opts...)
}

func (p *GitHubProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.config.Scopes,
	}
	return config.Exchange(ctx, code)
}

func (p *GitHubProvider) GetEmailAddress(ctx context.Context, token *oauth2.Token) (string, error) {
	// TODO support Team, Organization, Collaborator
	client := gogithub.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)))
	me, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", err
	}
	return me.GetEmail(), nil
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
