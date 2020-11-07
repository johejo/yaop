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

func (p *GoogleProvider) AuthCodeURL(state string, redirectURL string) string {
	config := &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
	}
	var opts []oauth2.AuthCodeOption // TODO https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
	return config.AuthCodeURL(state, opts...)
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
	}
	return config.Exchange(ctx, code)
}

func (p *GoogleProvider) GetEmailAddress(ctx context.Context, token *oauth2.Token) (string, error) {
	svc, err := googleoauth2.NewService(ctx, option.WithTokenSource(oauth2.StaticTokenSource(token)))
	if err != nil {
		return "", err
	}
	tokenInfo, err := svc.Tokeninfo().Do()
	if err != nil {
		return "", err
	}
	return tokenInfo.Email, nil
}

// https://developers.google.com/identity/protocols/oauth2
type GoogleProviderConfig struct {
	ClientID     string   `json:"clientId,omitempty" yaml:"clientId" vavalidate:"required"`
	ClientSecret string   `json:"clientSecret,omitempty" yaml:"clientSecret" validate:"required"`
	Scopes       []string `json:"scopes,omitempty" yaml:"scopes"`
}

func (c *GoogleProviderConfig) FillDefaults() error {
	c.Scopes = append(c.Scopes, googleoauth2.UserinfoEmailScope)
	return nil
}

func (c *GoogleProviderConfig) Type() string {
	return "google"
}
