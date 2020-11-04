package yaop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

type testProvider struct {
	Name string
}

var _ Provider = (*testProvider)(nil)

func (p *testProvider) GetName() string {
	return p.Name
}

func (p *testProvider) AuthCodeURL(state string, redirectURL string) string {
	return ""
}

func (p *testProvider) Exchange(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error) {
	return nil, nil
}

func (p *testProvider) GetEmailAddress(ctx context.Context, token *oauth2.Token) (string, error) {
	return "", nil
}

func TestInMemoryProviderStorage(t *testing.T) {
	ctx := context.Background()

	s := new(InMemoryProviderStorage)
	p0 := &testProvider{Name: "p0"}
	p1 := &testProvider{Name: "p1"}
	const (
		p0Name = "test-provider-0"
		p1Name = "test-provider-1"
	)

	if err := s.Store(ctx, p0Name, p0); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, p0Name)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, p0, got)

	if err := s.Store(ctx, p1Name, p1); err != nil {
		t.Fatal(err)
	}

	ps, err := s.LoadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, map[string]Provider{p0Name: p0, p1Name: p1}, ps)

	if err := s.Delete(ctx, p0Name); err != nil {
		t.Fatal(err)
	}

	ps, err = s.LoadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, map[string]Provider{p1Name: p1}, ps)

	_, err = s.Load(ctx, p0Name)
	assert.Equal(t, ErrProviderNotFound, err)
}
