package yaop

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/google/uuid"
)

type Session struct {
	ID    string        `json:"id" msgpack:"id"`
	Email string        `json:"email" msgpack:"email"`
	Token *oauth2.Token `json:"token" msgpack:"token"`
}

func newSession(email string) *Session {
	return &Session{ID: uuid.New().String(), Email: email}
}

type SessionStorage interface {
	Load(ctx context.Context, cookieValue string) (*Session, error)
	Store(ctx context.Context, sess *Session) (cookieValue string, err error)
}
