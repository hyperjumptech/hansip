package totp

import (
	"encoding/base32"
	"fmt"
	"math/rand"
	"net/url"
	"time"
)

// Secret is a secret data that represent user's secret.
type Secret []byte

// SecretFromBase32 will create a secret data from its base32 format.
func SecretFromBase32(base32string string) Secret {
	dec, err := base32.StdEncoding.DecodeString(base32string)
	if err != nil {
		return Secret{1}
	}
	return dec
}

// MakeSecret will create a random 10 bytes (80 bits) secret.
func MakeSecret() Secret {
	rand.Seed(time.Now().Unix())
	secret := make(Secret, 10)
	for i := 0; i < 10; i++ {
		secret[i] = byte(rand.Intn(255))
	}
	return secret
}

// Base32 will create the Base32 string representation of this secret (eg. for storing into db)
func (s Secret) Base32() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s)
}

// IsValid validate this key. if its 10 bytes than its valid.
func (s Secret) IsValid() bool {
	return len(s) == 10
}

// ProvisionURL will create provisioning URL to be generated into QR or Bar Codes.
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (s Secret) ProvisionURL(issuer, user string) string {
	query := make(url.Values)
	query.Add("secret", s.Base32())
	query.Add("issuer", issuer)
	query.Add("algorithm", "SHA1")
	query.Add("digits", "6")
	query.Add("period", "30")
	return fmt.Sprintf("otpauth://totp/%s:%s?%s", issuer, user, query.Encode())
}
