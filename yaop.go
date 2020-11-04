package yaop

import (
	"context"
	"log"
	"net/http"
)

func run() error {
	ctx := context.Background()
	config := &ServerConfig{
		Cookie: &CookieConfig{},
	}
	cs, err := NewCookieStorage([]byte("1234123412341234"))
	if err != nil {
		return err
	}
	ps := new(InMemoryProviderStorage)
	if err := ps.Store(ctx, "github", nil); err != nil {
		return err
	}
	s, err := NewServer(ctx, config, ps, cs)
	if err != nil {
		return err
	}
	return http.ListenAndServe(":8080", s)
}

func Run() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
