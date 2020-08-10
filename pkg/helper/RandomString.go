package helper

import (
	"bytes"
	"math/rand"
	"time"
)

const (
	upper  = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
	lower  = `abcdefghijklmnopqrstuvwxyz`
	number = `123456789`
)

// MakeRandomString produces a string contains random character with defined specification.
func MakeRandomString(length int, upperAlphas, lowerAlphas, numbers, space bool) string {
	if length == 0 {
		return ""
	}
	poolBuff := bytes.Buffer{}
	if upperAlphas {
		poolBuff.WriteString(upper)
	}
	if lowerAlphas {
		poolBuff.WriteString(lower)
	}
	if numbers {
		poolBuff.WriteString(number)
	}
	if space {
		poolBuff.WriteString(" ")
	}
	bpool := poolBuff.Bytes()
	buff := bytes.Buffer{}
	rand.Seed(time.Now().UnixNano())
	for buff.Len() < length {
		buff.WriteByte(bpool[rand.Intn(len(bpool))])
	}
	return string(buff.Bytes())
}
