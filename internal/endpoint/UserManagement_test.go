package endpoint

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestArrayJsonParsing(t *testing.T) {
	jsonStr := `["abc","cde","fgh"]`
	target := make([]string, 0)
	err := json.Unmarshal([]byte(jsonStr), &target)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
	if target[0] != "abc" {
		t.Fail()
	}
	if target[2] != "fgh" {
		t.Fail()
	}
}

func TestGenPass(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("abcdefg"), 14)
	if err != nil {
		t.Fail()
	}
	t.Log(string(hash))
}
