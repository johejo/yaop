package yaop_test

import (
	"testing"
	"time"
	_ "time/tzdata"
)

func loadLocalLocation(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Local")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}
