package yaop

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeProvider(t *testing.T) {
	pj := &providerJSON{
		Type: "github",
		Provider: &GitHubProvider{
			Name: "my-github",
			Config: &GitHubProviderConfig{
				ClientID:     "clientId",
				ClientSecret: "clientSecret",
			},
		},
	}
	p, err := DecodeProvider(pj)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, p.GetName(), "my-github")
}
