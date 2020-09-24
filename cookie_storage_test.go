package yaop

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
)

func TestCookieStorage(t *testing.T) {
	s, err := NewCookieStorage([]byte("1234123412341234"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sess := &Session{ID: "id", Email: "example@email.com", Token: &oauth2.Token{
		AccessToken:  "my-access-token",
		TokenType:    "",
		RefreshToken: "",
		Expiry:       time.Time{},
	}}
	v, err := s.Store(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Load(ctx, v)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, sess, got)
}
