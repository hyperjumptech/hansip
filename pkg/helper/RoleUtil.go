package helper

import (
	"regexp"
	"strings"
)

// IsRoleValid Validates if the required roles matches the supplied roles
func IsRoleValid(requires, supplied []string) bool {
	if len(requires) == 0 {
		return true
	}
	valid := false
	for _, require := range requires {
		requireValid := false
		for _, supply := range supplied {
			if matchesTwoRole(require, supply) {
				valid = true
				requireValid = true
			}
		}
		if !requireValid {
			return false
		}
	}
	return valid
}

// matchesTwoRole will compare if role b will fulfil role b
func matchesTwoRole(a, b string) bool {
	aw := strings.Contains(a, "*")
	bw := strings.Contains(b, "*")
	if aw && bw {
		return false
	}
	if !aw && !bw {
		return a == b
	}
	if aw {
		rx, err := regexp.Compile(strings.ReplaceAll(a, "*", `[a-zA-Z0-9_\-\.]+`))
		if err != nil {
			return false
		}
		return rx.Match([]byte(b))
	}
	if bw {
		rx, err := regexp.Compile(strings.ReplaceAll(b, "*", `[a-zA-Z0-9_\-\.]+`))
		if err != nil {
			return false
		}
		return rx.Match([]byte(a))
	}
	return false
}
