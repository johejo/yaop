package yaop

import (
	"context"

	gogithub "github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	_ Provider             = (*GitHubProvider)(nil)
	_ ProviderConfigDetail = (*GitHubProviderConfig)(nil)
)

type GitHubProvider struct {
	Name   string                `json:"name,omitempty"`
	Config *GitHubProviderConfig `json:"config,omitempty"`
}

func (p *GitHubProvider) GetName() string {
	return p.Name
}

func (p *GitHubProvider) GetType() string {
	return p.Config.Type()
}

func (p *GitHubProvider) oauth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
	}
}

func (p *GitHubProvider) AuthCodeURL(state string, redirectURL string) string {
	config := p.oauth2Config(redirectURL)
	var opts []oauth2.AuthCodeOption
	if p.Config.AllowSignup != "" {
		opts = append(opts, oauth2.SetAuthURLParam("allow_signup", p.Config.AllowSignup))
	}
	if p.Config.Login != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login", p.Config.Login))
	}
	return config.AuthCodeURL(state, opts...)
}

func (p *GitHubProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	return p.oauth2Config(redirectURL).Exchange(ctx, code)
}

func (p *GitHubProvider) GetMe(ctx context.Context, token *oauth2.Token) (*Me, error) {
	// TODO support Team, Organization, Collaborator
	client := gogithub.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)))
	me, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := mapstructureDecodeJson(me, &raw); err != nil {
		return nil, err
	}
	return &Me{
		Email:       me.GetEmail(),
		DisplayName: me.GetName(),
		Raw:         raw,
	}, nil
}

// https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps
type GitHubProviderConfig struct {
	ClientID     string `json:"clientId,omitempty" yaml:"clientId" vavalidate:"required"`
	ClientSecret string `json:"clientSecret,omitempty" yaml:"clientSecret" validate:"required"`
	// https://docs.github.com/en/free-pro-team@latest/developers/apps/scopes-for-oauth-apps#available-scopes
	Scopes      []string `json:"scopes,omitempty" yaml:"scopes"`
	Login       string   `json:"login,omitempty" yaml:"login"`
	AllowSignup string   `json:"allowSignup,omitempty" yaml:"allowSignup" validate:"omitempty,true|false"`
}

func (c *GitHubProviderConfig) FillDefaults() error {
	c.Scopes = append(c.Scopes, "read:user")
	return nil
}

func (c *GitHubProviderConfig) Type() string {
	return "github"
}
