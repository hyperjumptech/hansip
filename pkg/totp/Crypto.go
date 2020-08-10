package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/skip2/go-qrcode"
	"math"
	"math/big"
	"time"
)

// MakeRandomTotpKey create a 32 digit BASE32 digits for TOTP key
func MakeRandomTotpKey() string {
	return helper.MakeRandomString(32, true, false, true, false)
}

// MakeTotpQrImage create a QR image for TOTP key.
func MakeTotpQrImage(key, label string) ([]byte, error) {
	url := fmt.Sprintf("otpauth://totp/%s?secret=%s", label, key)
	return qrcode.Encode(url, qrcode.Medium, 256)
}

func hmacShaGen(keyBytes, text []byte) []byte {
	h := hmac.New(sha1.New, keyBytes)
	h.Write(text)
	return h.Sum(nil)
}

func hexStr2Bytes(hex string) ([]byte, error) {
	// Adding one byte to get the right conversion
	// Values starting with "0" can be converted
	//byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

	bInt := new(big.Int)
	bInt.SetString("10"+hex, 16)
	b := bInt.Bytes()

	// Copy all the REAL bytes, not the "first"
	ret := make([]byte, len(b)-1)
	for idx := range ret {
		ret[idx] = b[idx+1]
	}
	return ret, nil
}

// GenerateTotpWithDrift (Time-based OTP) generates OTP code according to RFC 6238 - https://tools.ietf.org/html/rfc6238
// With time drifting sample.
func GenerateTotpWithDrift(key string, time time.Time, driftSecond int64, digit int) (string, error) {
	unix := time.UTC().Unix()
	T := unix / driftSecond
	THex := fmt.Sprintf("%X", T)
	return GenerateTotp(key, THex, digit)
}

// GenerateTotp (Time-based OTP) generates OTP code according to RFC 6238 - https://tools.ietf.org/html/rfc6238
// key is a HEX shared key.
// time is a HEX value that reflect time. could be unix time stamp - in seconds.
// digit is number of otp digit to return. advised to be 6 digit.
func GenerateTotp(key, time string, digit int) (string, error) {
	codeDigits := int(math.Pow10(digit))

	timeMessage := time

	// Using the counter
	// First 8 bytes are for the movingFactor
	// Compliant with base RFC 4226 (HOTP)
	for len(timeMessage) < 16 {
		timeMessage = "0" + timeMessage
	}

	// Get the HEX in a Byte[]
	msg, err := hexStr2Bytes(timeMessage)
	if err != nil {
		return "", err
	}
	k, err := hexStr2Bytes(key)
	if err != nil {
		return "", err
	}

	hash := hmacShaGen(k, msg)

	// put selected bytes into result int
	offset := int(hash[len(hash)-1] & 0xf)

	binary :=
		((int(hash[offset]) & 0x7f) << 24) |
			((int(hash[offset+1]) & 0xff) << 16) |
			((int(hash[offset+2]) & 0xff) << 8) |
			(int(hash[offset+3]) & 0xff)

	otp := binary % codeDigits
	sotp := fmt.Sprintf("%d", otp)
	for len(sotp) < digit {
		sotp = "0" + sotp
	}
	return sotp, nil
}
