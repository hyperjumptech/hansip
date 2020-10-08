package passphrase

import (
	"regexp"
	"strings"
)

// Validate parses your passphrase and validates for minimum characters and words
func Validate(passphrase string, minchars, minwords, mincharsinword int) bool {
	if len(passphrase) < minchars {
		return false
	}
	regx := regexp.MustCompile(`[ \t\n]+`)
	reps := regx.ReplaceAllString(passphrase, " ")
	words := strings.Split(reps, " ")
	if len(words) < minwords {
		return false
	}
	for _, w := range words {
		if len(w) < mincharsinword {
			return false
		}
	}
	return true
}
