package yaop

import (
	"context"
	"encoding/base64"

	"github.com/klauspost/compress/zstd"
	"github.com/vmihailenco/msgpack/v5"
)

type CookieStorage struct {
	enc    *zstd.Encoder
	dec    *zstd.Decoder
	cipher Cipher
}

func NewCookieStorage(key []byte) (*CookieStorage, error) {
	e, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	d, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	c, err := NewGCMCipher(key)
	if err != nil {
		return nil, err
	}
	return &CookieStorage{cipher: c, enc: e, dec: d}, nil
}

var _ SessionStorage = (*CookieStorage)(nil)

func (s *CookieStorage) Load(ctx context.Context, cookieValue string) (*Session, error) {
	b, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, err
	}

	decrypted, err := s.cipher.Decrypt(b)
	if err != nil {
		return nil, err
	}

	decoded, err := s.dec.DecodeAll(decrypted, nil)
	if err != nil {
		return nil, err
	}

	var sess Session
	if err := msgpack.Unmarshal(decoded, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *CookieStorage) Store(ctx context.Context, sess *Session) (cookieValue string, err error) {
	b, err := msgpack.Marshal(sess)
	if err != nil {
		return "", err
	}
	encoded := s.enc.EncodeAll(b, nil)

	encrypted, err := s.cipher.Encrypt(encoded)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}
