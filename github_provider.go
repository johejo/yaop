package yaop

import (
	"context"
	"strconv"

	gogithub "github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var _ Provider = (*GitHubProvider)(nil)

type GitHubProvider struct {
	Name   string                `json:"name,omitempty"`
	config *GitHubProviderConfig `json:"config,omitempty"`
}

type GitHubProviderConfig struct {
	ClientID     string   `json:"clientId,omitempty"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Login        string   `json:"login,omitempty"`
	AllowSignup  bool     `json:"allowSignup,omitempty"`
}

func (p *GitHubProvider) GetName() string {
	return p.Name
}

func NewDefaultGitHubProvider(ctx context.Context, config *GitHubProviderConfig) (*GitHubProvider, error) {
	return NewGitHubProvider(ctx, "GitHub", config)
}

func NewGitHubProvider(ctx context.Context, name string, config *GitHubProviderConfig) (*GitHubProvider, error) {
	return &GitHubProvider{
		Name:   name,
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
