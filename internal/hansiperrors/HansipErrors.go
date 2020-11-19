package hansiperrors

import (
	"fmt"
	"strings"
)

type ErrPathNotAllowed struct {
	Given    string
	Required string
}

func (e *ErrPathNotAllowed) Error() string {
	return fmt.Sprintf("path permission error. path %s not allowed for %s", e.Given, e.Required)
}

type ErrMethodNotAllowed struct {
}

func (e *ErrMethodNotAllowed) Error() string {
	return "method is not allowed error"
}

type ErrAudienceNotAllowed struct {
	Audiences []string
}

func (e *ErrAudienceNotAllowed) Error() string {
	return fmt.Sprintf("audiences are not allowed error. %s", strings.Join(e.Audiences, ", "))
}

type ErrMissingAuthorizationHeader struct {
}

func (e *ErrMissingAuthorizationHeader) Error() string {
	return "no Authorization header error"
}

type ErrInvalidAuthorizationMethod struct {
}

func (e *ErrInvalidAuthorizationMethod) Error() string {
	return "authorization error. Authorization header contains non bearer method"
}

type ErrTokenInvalid struct {
	Wrapped error
}

func (e *ErrTokenInvalid) Error() string {
	return fmt.Sprintf("token validation error. Got %s", e.Wrapped.Error())
}

func (e *ErrTokenInvalid) Unwrap() error {
	return e.Wrapped
}

type ErrInvalidIssuer struct {
	InvalidIssuer string
}

func (e *ErrInvalidIssuer) Error() string {
	return fmt.Sprintf("invalid issuer \"%s\" error", e.InvalidIssuer)
}
