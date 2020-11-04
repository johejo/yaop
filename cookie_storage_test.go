package yaop_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/johejo/yaop"
)

func TestCookieStorage(t *testing.T) {
	s, err := yaop.NewCookieStorage([]byte("1234123412341234"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sess := &yaop.Session{ID: "id", Email: "example@email.com", Token: &oauth2.Token{
		AccessToken:  "my-access-token",
		TokenType:    "",
		RefreshToken: "",
		Expiry:       time.Date(2020, 1, 2, 3, 4, 5, 6, loadLocalLocation(t)),
	}}
	v, err := s.Store(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(len(v))

	got, err := s.Load(ctx, v)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, sess, got)
}
