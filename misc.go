package yaop

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/sethvargo/go-password/password"
)

var nowFunc func() time.Time = nil

func timeNow() time.Time {
	if nowFunc == nil {
		return time.Now()
	}
	return nowFunc()
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func genSecret() string {
	return password.MustGenerate(32, 8, 0, false, false)
}

func respondJSON(w http.ResponseWriter, v interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("[ERROR] failed to marshal json: %v", err)
		http.Error(w, "failed to marshal json", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// Copied from net/http/httputil reverseproxy.go

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

func mapstructureDecodeJson(src, dst interface{}) error {
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  dst,
		TagName: "json",
	})
	if err != nil {
		return err
	}
	return d.Decode(src)
}
