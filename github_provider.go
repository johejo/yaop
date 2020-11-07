package yaop

import (
	"context"

	gogithub "github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var _ Provider = (*GitHubProvider)(nil)

type GitHubProvider struct {
	Name   string                `json:"name,omitempty"`
	Config *GitHubProviderConfig `json:"config,omitempty"`
}

func (p *GitHubProvider) GetName() string {
	return p.Name
}

func (p *GitHubProvider) AuthCodeURL(state string, redirectURL string) string {
	config := &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
	}
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
	config := &oauth2.Config{
		ClientID:     p.Config.ClientID,
		ClientSecret: p.Config.ClientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       p.Config.Scopes,
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
