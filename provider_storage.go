package yaop

import (
	"context"
	"errors"
)

type ProviderStorage interface {
	Load(ctx context.Context, name string) (Provider, error)
	Store(ctx context.Context, name string, provider Provider) error
	Delete(ctx context.Context, name string) error
	LoadAll(ctx context.Context) ([]Provider, error)
}

var (
	ErrProviderNotFound = errors.New("specified provider not found")
)
