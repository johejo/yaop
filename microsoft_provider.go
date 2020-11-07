package yaop

import (
	"context"

	"github.com/imdario/mergo"
	msgraph "github.com/yaegashi/msgraph.go/v1.0"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var (
	_ Provider             = (*MicrosoftProvider)(nil)
	_ ProviderConfigDetail = (*MicrosoftProviderConfig)(nil)
)

type MicrosoftProvider struct {
	Name   string                   `json:"name,omitempty"`
	Config *MicrosoftProviderConfig `json:"config,omitempty"`
}

func (p *MicrosoftProvider) GetName() string {
	return p.Name
}

func (p *MicrosoftProvider) GetType() string {
	return p.Config.Type()
}

func (p *MicrosoftProvider) oauth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     microsoft.AzureADEndpoint(p.Config.Tenant),
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
	}
}

func (p *MicrosoftProvider) AuthCodeURL(state string, redirectURL string) string {
	config := p.oauth2Config(redirectURL)
	var opts []oauth2.AuthCodeOption // TODO https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-oauth2-auth-code-flow
	return config.AuthCodeURL(state, opts...)
}

func (p *MicrosoftProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	return p.oauth2Config(redirectURL).Exchange(ctx, code)
}

func (p *MicrosoftProvider) GetMe(ctx context.Context, token *oauth2.Token) (*Me, error) {
	client := msgraph.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)))
	me, err := client.Me().Request().Get(ctx)
	if err != nil {
		return nil, err
	}

	var email, displayName string

	if me.UserPrincipalName != nil {
		email = *me.UserPrincipalName
	} else if me.Mail != nil {
		email = *me.Mail
	}
	if me.DisplayName != nil {
		displayName = *me.DisplayName
	}

	var raw map[string]interface{}
	if err := mapstructureDecodeJson(me, &raw); err != nil {
		return nil, err
	}

	return &Me{
		Email:       email,
		DisplayName: displayName,
		Raw:         raw,
	}, nil
}

type MicrosoftProviderConfig struct {
	ClientID     string   `json:"clientId,omitempty" yaml:"clientId" validate:"required"`
	ClientSecret string   `json:"clientSecret,omitempty" yaml:"clientSecret" validate:"required"`
	Scopes       []string `json:"scopes,omitempty" yaml:"scopes"`

	Tenant string `json:"tenant,omitempty" yaml:"tenant"`
}

func (c *MicrosoftProviderConfig) Type() string {
	return "microsoft"
}

func (c *MicrosoftProviderConfig) FillDefaults() error {
	defaults := &MicrosoftProviderConfig{
		Tenant: "common",
	}
	if err := mergo.Merge(c, defaults); err != nil {
		return err
	}
	c.Scopes = append(c.Scopes, "email", "profile", "openid")
	return nil
}
