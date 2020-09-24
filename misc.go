package yaop

import (
	"fmt"
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
