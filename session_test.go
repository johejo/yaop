package yaop

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_encodeSessionToString(t *testing.T) {
	sess := &Session{
		ID:          "id",
		ProvideName: "github",
		Email:       "test@test.com",
		Token:       nil,
	}
	s, err := encodeSessionToString(sess)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(s)
	got, err := decodeSessionFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, sess, got)
}
