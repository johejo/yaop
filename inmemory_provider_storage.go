package yaop

import (
	"context"
	"errors"
	"sync"
)

var _ ProviderStorage = (*InMemoryProviderStorage)(nil)

type InMemoryProviderStorage struct {
	store sync.Map
}

func (ps *InMemoryProviderStorage) Load(ctx context.Context, name string) (Provider, error) {
	_p, ok := ps.store.Load(name)
	if !ok {
		return nil, ErrProviderNotFound
	}
	p, ok := _p.(Provider)
	if !ok {
		return nil, errors.New("invalid provider")
	}
	return p, nil
}

func (ps *InMemoryProviderStorage) Store(ctx context.Context, name string, provider Provider) error {
	ps.store.Store(name, provider)
	return nil
}

func (ps *InMemoryProviderStorage) Delete(ctx context.Context, name string) error {
	ps.store.Delete(name)
	return nil
}

func (ps *InMemoryProviderStorage) LoadAll(ctx context.Context) (map[string]Provider, error) {
	result := make(map[string]Provider)
	ps.store.Range(func(key, value interface{}) bool {
		p, ok := value.(Provider)
		if !ok {
			return false
		}
		_key, ok := key.(string)
		if !ok {
			return false
		}
		result[_key] = p
		return true
	})
	return result, nil
}
