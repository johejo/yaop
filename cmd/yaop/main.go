package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/johejo/yaop"
)

var (
	rootOpts struct {
		configFile string
	}
)

func init() {
	flag.StringVar(&rootOpts.configFile, "config", "./yaop.yaml", "yaop config file")
}

func main() {
	flag.Parse()
	ctx := context.Background()
	log.SetFlags(log.Lmicroseconds | log.LstdFlags | log.Lshortfile)
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {

	b, err := ioutil.ReadFile(rootOpts.configFile)
	if err != nil {
		return err
	}
	var config yaop.Config
	if err := yaml.Unmarshal(b, &config); err != nil {
		return err
	}

	s, err := yaop.NewServerWithConfig(ctx, &config)
	if err != nil {
		return err
	}

	// background upstream server for debug
	mux := http.NewServeMux()
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		session := r.Header.Get(config.Upstream.PropergateSession.HeaderKey)
		w.Write([]byte(fmt.Sprintf("protected, session=%s", session)))
	})
	go func() {
		http.ListenAndServe(":8888", mux)
	}()

	return s.Run(ctx)
}
