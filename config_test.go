package yaop_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/johejo/yaop"
)

func TestConfig(t *testing.T) {
	path := "./testdata/yaop-config-0.yaml"
	b, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pc yaop.Config
	if err := yaml.Unmarshal(b, &pc); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "github-0", pc.Providers[0].Name)
	var gpc yaop.GitHubProviderConfig
	if err := pc.Providers[0].Config.As(&gpc); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "xxx", gpc.ClientID)
}
