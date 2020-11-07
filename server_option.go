package yaop

import (
	"html/template"
	"net/http"
)

type ServerOption func(config *serverOptionalConfig)

type serverOptionalConfig struct {
	protected  http.Handler
	upstream   UpstreamConfig
	signInTmpl *template.Template
	httpClient *http.Client
}

func WithProtectedHandler(h http.Handler) ServerOption {
	return func(cfg *serverOptionalConfig) {
		cfg.protected = h
	}
}

func WithUpstream(upstreamConfig UpstreamConfig) ServerOption {
	return func(cfg *serverOptionalConfig) {
		cfg.upstream = upstreamConfig
	}
}

func WithSignInTmpl(tmpl *template.Template) ServerOption {
	return func(cfg *serverOptionalConfig) {
		cfg.signInTmpl = tmpl
	}
}

func WithHTTPClient(httpClient *http.Client) ServerOption {
	return func(cfg *serverOptionalConfig) {
		cfg.httpClient = httpClient
	}
}
