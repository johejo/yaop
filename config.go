package yaop

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/imdario/mergo"
	"gopkg.in/yaml.v3"
)

type fillDefaults interface {
	FillDefaults() error
}

var (
	validate = validator.New()

	_ fillDefaults = (*Config)(nil)
	_ fillDefaults = (*ProviderConfig)(nil)
	_ fillDefaults = (*ProviderStorageConfig)(nil)
	_ fillDefaults = (*CookieConfig)(nil)
	_ fillDefaults = (*SessionStorageConfig)(nil)
	_ fillDefaults = (*ServerConfig)(nil)
	_ fillDefaults = (*UpstreamConfig)(nil)
)

type Config struct {
	Providers       []ProviderConfig      `yaml:"providers" validate:"required"`
	ProviderStorage ProviderStorageConfig `yaml:"providerStorage" validate:"required"`
	Cookie          CookieConfig          `yaml:"cookie" validate:"required"`
	SessionStorage  SessionStorageConfig  `yaml:"sessionStorage" validate:"required"`
	Server          ServerConfig          `yaml:"server" validate:"required"`
	Upstream        UpstreamConfig        `yaml:"upstream"`
}

func (c *Config) Validate() error {
	return validate.Struct(c)
}

func (c *Config) FillDefaults() error {
	for _, p := range c.Providers {
		if err := p.FillDefaults(); err != nil {
			return err
		}
	}
	if err := c.ProviderStorage.FillDefaults(); err != nil {
		return err
	}
	if err := c.Cookie.FillDefaults(); err != nil {
		return err
	}
	if err := c.SessionStorage.FillDefaults(); err != nil {
		return err
	}
	if err := c.Server.FillDefaults(); err != nil {
		return err
	}
	if err := c.Upstream.FillDefaults(); err != nil {
		return err
	}
	return nil
}

type UpstreamConfig struct {
	URL               string `yaml:"url" validate:"omitempty,url"`
	PropergateSession struct {
		Enable    bool   `yaml:"enable"`
		HeaderKey string `yaml:"headerKey"`
	} `yaml:"propergateSession"`
}

func (c *UpstreamConfig) FillDefaults() error {
	defaults := &UpstreamConfig{
		URL: "",
	}
	defaults.PropergateSession.Enable = false
	defaults.PropergateSession.HeaderKey = "X-Yaop-Session"
	return mergo.Merge(c, defaults)
}

type ProviderConfig struct {
	Name   string        `yaml:"name" validate:"required"`
	Type   string        `yaml:"type" validate:"required,oneof=github google microsoft"` // TODO support other providers
	Config DynamicConfig `yaml:"config" validate:"required"`
}

func (c *ProviderConfig) FillDefaults() error {
	return nil
}

type DynamicConfig interface{}

func DynamicConfigAs(c DynamicConfig, pc ProviderConfigDetail) error {
	return mapstructureDecodeJson(c, pc)
}

type ProviderStorageConfig struct {
	Type string `yaml:"type" validate:"omitempty,oneof=inmemory"` // TODO support redis
}

func (c *ProviderStorageConfig) FillDefaults() error {
	defaults := &ProviderStorageConfig{
		Type: "inmemory",
	}
	return mergo.Merge(c, defaults)
}

type SessionStorageConfig struct {
	Type string `yaml:"type" validate:"required,oneof=cookie"` // TODO support redis
}

func (c *SessionStorageConfig) FillDefaults() error {
	defaults := &SessionStorageConfig{
		Type: "cookie",
	}
	return mergo.Merge(c, defaults)
}

type ServerConfig struct {
	Prefix    string `yaml:"prefix" validate:"startswith=/"`
	Port      int    `yaml:"port"`
	FirstPage string `yaml:"firstPage" validate:"startswith=/"`

	AllowedDomains []string `yaml:"allowedDomains" validate:"dive,fqdn,omitempty"`
}

func (c *ServerConfig) FillDefaults() error {
	defaults := &ServerConfig{
		Prefix:    "/oauth2",
		Port:      8080,
		FirstPage: "/",
	}
	return mergo.Merge(c, defaults)
}

type CookieConfig struct {
	Key        string        `yaml:"key" validate:"required"`
	Name       string        `yaml:"name"`
	CsrfSuffix string        `yaml:"csrfSuffix"`
	ExpiresIn  time.Duration `yaml:"expiresIn"`
	SameSite   samesite      `yaml:"samesite"`
	HttpOnly   bool          `yaml:"httponly"`
	Secure     bool          `yaml:"secure"`
}

func (c *CookieConfig) CsrfCookieName() string {
	return c.Name + c.CsrfSuffix
}

func (c *CookieConfig) FillDefaults() error {
	defaults := &CookieConfig{
		Name:       "_yaop_session",
		CsrfSuffix: "_csrf",
		ExpiresIn:  24 * time.Hour,
		SameSite:   samesite(http.SameSiteLaxMode),
		HttpOnly:   true,
		Secure:     true,
	}
	return mergo.Merge(c, defaults)
}

type samesite http.SameSite

var _ yaml.Unmarshaler = (*samesite)(nil)

func (s *samesite) UnmarshalYAML(value *yaml.Node) error {
	switch strings.ToLower(value.Value) {
	case "lax":
		*s = samesite(http.SameSiteLaxMode)
	case "none":
		*s = samesite(http.SameSiteNoneMode)
	default:
		return errors.New("invalid samesite")
	}
	return nil
}

type ProviderConfigDetail interface {
	Type() string
	fillDefaults
}
