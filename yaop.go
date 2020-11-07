package yaop

import (
	"context"
	"errors"
	"strings"
)

func NewServerWithConfig(ctx context.Context, config *Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := config.FillDefaults(); err != nil {
		return nil, err
	}
	var ps ProviderStorage
	switch config.ProviderStorage.Type {
	case "inmemory":
		ps = new(InMemoryProviderStorage)
	default:
		return nil, errors.New("invalid provider storage type")
	}

	var ss SessionStorage
	switch config.SessionStorage.Type {
	case "cookie":
		cs, err := NewCookieStorage([]byte(config.Cookie.Key))
		if err != nil {
			return nil, err
		}
		ss = cs
	default:
		return nil, errors.New("invalid session storage type")
	}

	providers := make([]Provider, 0, len(config.Providers))
	for _, p := range config.Providers {
		var provider Provider
		switch strings.ToLower(p.Type) {
		case "github":
			var gpc GitHubProviderConfig
			if err := DynamicConfigAs(p.Config, &gpc); err != nil {
				return nil, err
			}
			if err := gpc.FillDefaults(); err != nil {
				return nil, err
			}
			provider = &GitHubProvider{
				Name:   p.Name,
				Config: &gpc,
			}
		case "google":
			var gpc GoogleProviderConfig
			if err := DynamicConfigAs(p.Config, &gpc); err != nil {
				return nil, err
			}
			if err := gpc.FillDefaults(); err != nil {
				return nil, err
			}
			provider = &GoogleProvider{
				Name:   p.Name,
				Config: &gpc,
			}
		case "microsoft":
			var mpc MicrosoftProviderConfig
			if err := DynamicConfigAs(p.Config, &mpc); err != nil {
				return nil, err
			}
			if err := mpc.FillDefaults(); err != nil {
				return nil, err
			}
			provider = &MicrosoftProvider{
				Name:   p.Name,
				Config: &mpc,
			}
		default:
			return nil, errors.New("invalid provider")
		}
		providers = append(providers, provider)
	}

	for _, p := range providers {
		if err := ps.Store(ctx, p.GetName(), p); err != nil {
			return nil, err
		}
	}

	var opts []ServerOption
	if config.Upstream.URL != "" {
		opts = append(opts, WithUpstream(config.Upstream))
	}
	return NewServer(ctx, config.Server, config.Cookie, ps, ss, opts...)
}
