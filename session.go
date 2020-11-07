package yaop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type Session struct {
	ID          string        `json:"id" msgpack:"id"`
	ProvideName string        `json:"provideName" msgpack:"providerName"`
	Email       string        `json:"email" msgpack:"email"`
	Token       *oauth2.Token `json:"token" msgpack:"token"`
}

func newSession(email, providerName string, token *oauth2.Token) *Session {
	return &Session{ID: uuid.New().String(), Email: email, Token: token}
}

type SessionStorage interface {
	Load(ctx context.Context, cookieValue string) (*Session, error)
	Store(ctx context.Context, sess *Session) (cookieValue string, err error)
}

type ctxKey int

const (
	_ ctxKey = iota
	ctxSessionKey
)

func ContextWithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, ctxSessionKey, sess)
}

func SessionFromContext(ctx context.Context) (*Session, error) {
	v := ctx.Value(ctxSessionKey)
	sess, ok := v.(*Session)
	if !ok {
		return nil, errors.New("no session")
	}
	return sess, nil
}

func encodeSessionToString(sess *Session) (string, error) {
	buf := new(strings.Builder)
	if err := json.NewEncoder(buf).Encode(sess); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func decodeSessionFromString(s string) (*Session, error) {
	var sess Session
	if err := json.NewDecoder(strings.NewReader(s)).Decode(&sess); err != nil {
		return nil, err
	}
	return &sess, nil
}
