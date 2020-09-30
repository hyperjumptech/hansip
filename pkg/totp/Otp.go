package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/skip2/go-qrcode"
	"strconv"
	"time"
)

var (
	// ErrInvalidOTP is an error to be returned if the supplied OTP code is not valid.
	ErrInvalidOTP = fmt.Errorf("invalid otp code format")
	// Window OTP validity stepping window. Set this between 2 to 6. Above that is not secure
	Window = 3
)

// Authenticate will validate the supplied OTP toward user's secrets.
func Authenticate(secret Secret, suppliedOTP string, inUTC bool) (bool, error) {
	if len(suppliedOTP) == 6 && suppliedOTP[0] >= '0' && suppliedOTP[0] <= '9' {
		code, err := strconv.Atoi(suppliedOTP)
		if err != nil {
			return false, ErrInvalidOTP
		}
		var t0 int
		if inUTC {
			t0 = int(time.Now().UTC().Unix() / 30)
		} else {
			t0 = int(time.Now().Unix() / 30)
		}

		minT := t0 - (Window / 2)
		maxT := t0 + (Window / 2)
		for t := minT; t <= maxT; t++ {
			if getCurrentCode(secret, int64(t)) == code {
				return true, nil
			}
		}
		return false, nil
	}
	return false, ErrInvalidOTP
}

func getCurrentCode(secret Secret, value int64) int {
	hash := hmac.New(sha1.New, secret)
	err := binary.Write(hash, binary.BigEndian, value)
	if err != nil {
		return -1
	}
	h := hash.Sum(nil)
	offset := h[19] & 0x0f
	truncated := binary.BigEndian.Uint32(h[offset : offset+4])

	truncated &= 0x7fffffff
	code := truncated % 1000000

	return int(code)
}

// MakeTotpQrImage will produce a PNG image bytes to be scanned by OTP apps.
func MakeTotpQrImage(secret Secret, issuer, user string) ([]byte, error) {
	url := secret.ProvisionURL(issuer, user)
	return qrcode.Encode(url, qrcode.Medium, 256)
}
