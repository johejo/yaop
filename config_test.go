package yaop

import "testing"

func TestConfig(t *testing.T) {
	var c Config
	if err := c.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	c.Cookie.Key = "aaa"
	c.Providers = []ProviderConfig{
		{
			Name: "github",
			Type: "github",
			Config: &GitHubProviderConfig{
				ClientID:     "xxx",
				ClientSecret: "yyy",
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
