package hansipcontext

import (
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
)

// AuthenticationContext is a context value to be add into request context.
type AuthenticationContext struct {
	Token     string
	Subject   string
	Audience  []string
	TokenType string
}

// HasIsAdminOfDomain validate if the user have an admin account of a domain
func (c *AuthenticationContext) HasIsAdminOfDomain(domain string) bool {
	lookFor := fmt.Sprintf("%s@%s", config.Get("hansip.admin"), domain)
	for _, aud := range c.Audience {
		if aud == lookFor {
			return true
		}
	}
	return false
}
