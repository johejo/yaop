package yaop

import "github.com/mitchellh/mapstructure"

type Config struct {
	Providers []*ProviderConfig `yaml:"providers"`
}

type ProviderConfig struct {
	Name   string        `yaml:"name"`
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
