package yaop

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/sethvargo/go-password/password"
)

type yaopError struct {
	httpStatus int
	msg        string
	err        error
}

var _ error = (*yaopError)(nil)

func (e *yaopError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("msg=%s, err=%v", e.msg, e.err.Error())
	}
	return fmt.Sprintf("msg=%s", e.msg)
}

func (e *yaopError) Unrap() error {
	if e.err != nil {
		return e.err
	}
	return nil
}

func wrapErr(httpStatus int, msg string, err error) error {
	return &yaopError{httpStatus: httpStatus, msg: msg, err: err}
}

func newErr(httpStatus int, msg string) error {
	return &yaopError{httpStatus: httpStatus, msg: msg}
}

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
