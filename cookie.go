package yaop

import (
	"encoding/base64"

	"github.com/vmihailenco/msgpack/v5"
)

type csrfCookieValue struct {
	EncodedState string `msgpack:"encodedState"`
}

func newCsrfCookieValue(state string) *csrfCookieValue {
	return &csrfCookieValue{EncodedState: state}
}

func decodeCsrfCookieValue(raw string) (*csrfCookieValue, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var v csrfCookieValue
	if err := msgpack.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (v *csrfCookieValue) EncodeToString() (string, error) {
	b, err := msgpack.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

type state struct {
	CsrfToken string `msgpack:"csrfToken"`
	Next      string `msgpack:"next"`
	Provider  string `msgpack:"provider"`
}

func newState(next string) *state {
	return &state{CsrfToken: genSecret(), Next: next}
}

func (s *state) EncodeToString() (string, error) {
	b, err := msgpack.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func decodeState(raw string) (*state, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var st state
	if err := msgpack.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
