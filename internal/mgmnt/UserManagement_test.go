package mgmnt

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestGenPass(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("abcdefg"), 14)
	if err != nil {
		t.Fail()
	}
	t.Log(string(hash))
}
