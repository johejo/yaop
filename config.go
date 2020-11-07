package yaop

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Providers       []*ProviderConfig      `yaml:"providers"`
	ProviderStorage *ProviderStorageConfig `yaml:"providerStorage"`
	Cookie          *CookieConfig          `yaml:"cookie"`
	SessionStorage  *SessionStorageConfig  `yaml:"sessionStorage"`
	Server          *ServerConfig          `yaml:"server"`
	Upstream        *UpstreamConfig        `yaml:"upstream"`
}

type UpstreamConfig struct {
	URL               string `yaml:"url"`
	PropergateSession struct {
		Enable    bool   `yaml:"enable"`
		HeaderKey string `yaml:"headerKey"`
	} `yaml:"propergateSession"`
}

type ProviderConfig struct {
	Name   string        `yaml:"name"`
	Type   string        `yaml:"type"`
	Config DynamicConfig `yaml:"config"`
}

type DynamicConfig map[string]interface{}

func (c DynamicConfig) As(pc interface{}) error {
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  pc,
		TagName: "json",
	})
	if err != nil {
		return err
	}
	if err := d.Decode(c); err != nil {
		return err
	}
	return nil
}

type ProviderStorageConfig struct {
	Type string `yaml:"type"`
}

type SessionStorageConfig struct {
	Type string `yaml:"type"`
}

type ServerConfig struct {
	Prefix    string `yaml:"prefix"`
	Port      int    `yaml:"port"`
	FirstPage string `yaml:"firstPage"`

	AllowedDomains []string `yaml:"allowedDomains"`
}

func (c *CookieConfig) CsrfCookieName() string {
	return c.Name + c.CsrfSuffix
}

type CookieConfig struct {
	Key        string        `yaml:"key"`
	Name       string        `yaml:"name"`
	CsrfSuffix string        `yaml:"csrfSuffix"`
	ExpiresIn  time.Duration `yaml:"expiresIn"`
	SameSite   samesite      `yaml:"samesite"`
	HttpOnly   bool          `yaml:"httponly"`
	Secure     bool          `yaml:"secure"`
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
