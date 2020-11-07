package yaop

import (
	"context"
	"errors"
	"strings"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

type Provider interface {
	GetName() string
	GetType() string
	AuthCodeURL(state string, redirectURL string) string
	Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error)
	GetMe(ctx context.Context, token *oauth2.Token) (*Me, error)
}

type providerJSON struct {
	Type     string      `json:"type,omitempty"`
	Provider interface{} `json:"provider,omitempty"`
}

func decodeProvider(pj *providerJSON, dst interface{}) error {
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: dst, TagName: "json"})
	if err != nil {
		return err
	}
	if err := d.Decode(pj.Provider); err != nil {
		return err
	}
	return nil
}

func DecodeProvider(pj *providerJSON) (Provider, error) {
	switch strings.ToLower(pj.Type) {
	case "github":
		var p GitHubProvider
		if err := decodeProvider(pj, &p); err != nil {
			return nil, err
		}
		return &p, nil
	default:
		return nil, errors.New("invalid provider")
	}
}
