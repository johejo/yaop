package yaop

import (
	"context"
	"log"
	"net/http"
)

func run() error {
	ctx := context.Background()
	s, err := NewServer(ctx, nil, nil, nil) // TODO
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
