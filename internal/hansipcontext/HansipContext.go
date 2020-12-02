package hansipcontext

import (
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"strings"
)

// AuthenticationContext is a context value to be add into request context.
type AuthenticationContext struct {
	Token     string
	Subject   string
	Audience  []string
	TokenType string
}

// IsAdminOfDomain validate if the user have an admin account of a domain
func (c *AuthenticationContext) IsAdminOfDomain(domain string) bool {
	lookFor := fmt.Sprintf("%s@%s", config.Get("hansip.admin"), domain)
	hansipRole := fmt.Sprintf("%s@%s", config.Get("hansip.admin"), config.Get("hansip.domain"))
	for _, aud := range c.Audience {
		if aud == lookFor || aud == hansipRole {
			return true
		}
	}
	return false
}

// IsAdminOfDomain validate if the user have an admin account of a domain
func (c *AuthenticationContext) IsAnAdmin() bool {
	lookFor := fmt.Sprintf("%s@", config.Get("hansip.admin"))
	for _, aud := range c.Audience {
		if strings.HasPrefix(aud, lookFor) {
			return true
		}
	}
	return false
}
