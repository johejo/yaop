package yaop

import (
	"context"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type Session struct {
	ID    string        `json:"id" msgpack:"id"`
	Email string        `json:"email" msgpack:"email"`
	Token *oauth2.Token `json:"token" msgpack:"token"`
}

func newSession(email string, token *oauth2.Token) *Session {
	return &Session{ID: uuid.New().String(), Email: email, Token: token}
}

type SessionStorage interface {
	Load(ctx context.Context, cookieValue string) (*Session, error)
	Store(ctx context.Context, sess *Session) (cookieValue string, err error)
}
