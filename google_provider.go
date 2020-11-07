package yaop

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoauth2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

var (
	_ Provider             = (*GoogleProvider)(nil)
	_ ProviderConfigDetail = (*GitHubProviderConfig)(nil)
)

type GoogleProvider struct {
	Name   string                `json:"name,omitempty"`
	Config *GoogleProviderConfig `json:"config,omitempty"`
}

func (p *GoogleProvider) GetName() string {
	return p.Name
}

func (p *GoogleProvider) GetType() string {
	return p.Config.Type()
}

func (p *GoogleProvider) oauth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
	}
}

func (p *GoogleProvider) AuthCodeURL(state string, redirectURL string) string {
	var opts []oauth2.AuthCodeOption // TODO https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
	return p.oauth2Config(redirectURL).AuthCodeURL(state, opts...)
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	return p.oauth2Config(redirectURL).Exchange(ctx, code)
}

func (p *GoogleProvider) GetMe(ctx context.Context, token *oauth2.Token) (*Me, error) {
	var opts []option.ClientOption
	opts = append(opts,
		option.WithScopes(p.Config.Scopes...),
		option.WithTokenSource(oauth2.StaticTokenSource(token)),
	)
	s, err := googleoauth2.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	me, err := s.Userinfo.V2.Me.Get().Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := mapstructureDecodeJson(me, &raw); err != nil {
		return nil, err
	}
	return &Me{
		Email:       me.Email,
		DisplayName: me.Name,
		Raw:         raw,
	}, nil
}

// https://developers.google.com/identity/protocols/oauth2
type GoogleProviderConfig struct {
	ClientID     string   `json:"clientId,omitempty" yaml:"clientId" vavalidate:"required"`
	ClientSecret string   `json:"clientSecret,omitempty" yaml:"clientSecret" validate:"required"`
	Scopes       []string `json:"scopes,omitempty" yaml:"scopes"`
}

func (c *GoogleProviderConfig) FillDefaults() error {
	c.Scopes = append(c.Scopes, googleoauth2.UserinfoEmailScope, googleoauth2.OpenIDScope, googleoauth2.UserinfoProfileScope)
	return nil
}

func (c *GoogleProviderConfig) Type() string {
	return "google"
}
