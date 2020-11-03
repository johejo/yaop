package yaop

import (
	"context"
)

type ProviderStorage interface {
	Load(ctx context.Context, name string) (Provider, error)
	Store(ctx context.Context, name string, provider Provider) error
	Delete(ctx context.Context, name string) error
	LoadAll(ctx context.Context) (map[string]Provider, error)
}
