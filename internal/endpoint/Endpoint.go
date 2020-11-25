package endpoint

import (
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/hansiperrors"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	OptionMethod = 0b00000001
	HeadMethod   = 0b00000010
	GetMethod    = 0b00000100
	PostMethod   = 0b00001000
	PutMethod    = 0b00010000
	PatchMethod  = 0b00100000
	DeleteMethod = 0b01000000
)

var (
	search = regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)
)

type Endpoint struct {
	PathPattern        string
	AllowedMethodFlag  uint8
	IsPublic           bool
	WhiteListAudiences []string
	HandleFunction     func(http.ResponseWriter, *http.Request)
}

func GetMethodFlag(method string) uint8 {
	switch strings.ToUpper(method) {
	case "OPTIONS":
		return OptionMethod
	case "HEAD":
		return HeadMethod
	case "GET":
		return GetMethod
	case "POST":
		return PostMethod
	case "PUT":
		return PutMethod
	case "PATCH":
		return PatchMethod
	case "DELETE":
		return DeleteMethod
	}
	return 0
}

func (e *Endpoint) getPathGob() string {
	return search.ReplaceAllString(e.PathPattern, "*")
}

func (e *Endpoint) isPathCanAccess(path string) bool {
	match, err := helper.Match(e.getPathGob(), path)
	if err != nil {
		return false
	}
	return match
}

func getHToken(r *http.Request) (*helper.HansipToken, error) {
	// If it need validation, Check the Authorization header
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) == 0 {
		return nil, &hansiperrors.ErrMissingAuthorizationHeader{}
	}
	meth := strings.ToLower(strings.TrimSpace(authHeader[:6]))
	if meth != "bearer" {
		return nil, &hansiperrors.ErrInvalidAuthorizationMethod{}
	}
	// Get the token, validate and parse it.
	tok := strings.TrimSpace(authHeader[7:])
	hToken, err := TokenFactory.ReadToken(tok)
	if err != nil {
		return nil, &hansiperrors.ErrTokenInvalid{Wrapped: err}
	}
	// Makesure the issuer is the same
	if hToken.Issuer != config.Get("token.issuer") {
		return nil, &hansiperrors.ErrInvalidIssuer{InvalidIssuer: hToken.Issuer}
	}
	return hToken, err
}

func (e *Endpoint) AccessValid(r *http.Request, TokenFactory helper.TokenFactory) (*helper.HansipToken, error) {
	path := r.URL.Path
	method := GetMethodFlag(r.Method)
	hTok, hTokErr := getHToken(r)
	if e.IsPublic {
		if hTokErr != nil {
			return &helper.HansipToken{
				Issuer:    config.Get("token.issuer"),
				Subject:   "anonymous",
				Audiences: []string{"anonymous@*"},
				Expire:    time.Now().Add(24 * 360 * time.Hour),
				NotBefore: time.Time{},
				IssuedAt:  time.Time{},
				Additional: map[string]interface{}{
					"type": "access",
				},
			}, e.canAccess(path, method, nil)
		}
		return hTok, e.canAccess(path, method, nil)
	}
	if hTokErr != nil {
		return nil, hTokErr
	}
	err := e.canAccess(path, method, hTok.Audiences)
	if err != nil {
		return nil, &hansiperrors.ErrTokenInvalid{Wrapped: err}
	}
	return hTok, nil

}

func (e *Endpoint) canAccess(path string, method uint8, audience []string) error {
	if !e.isPathCanAccess(path) {
		return &hansiperrors.ErrPathNotAllowed{
			Given:    path,
			Required: e.PathPattern,
		}
	}
	if method&e.AllowedMethodFlag != method {
		return &hansiperrors.ErrMethodNotAllowed{}
	}
	if e.IsPublic {
		return nil
	}
	if isRoleMatch(e.WhiteListAudiences, audience) {
		return nil
	}
	return &hansiperrors.ErrAudienceNotAllowed{Audiences: audience}
}

func FlagToListMethod(flags uint8) []string {
	methods := make([]string, 0)
	if flags&OptionMethod == OptionMethod {
		methods = append(methods, "OPTIONS")
	}
	if flags&HeadMethod == HeadMethod {
		methods = append(methods, "HEAD")
	}
	if flags&GetMethod == GetMethod {
		methods = append(methods, "GET")
	}
	if flags&PostMethod == PostMethod {
		methods = append(methods, "POST")
	}
	if flags&PutMethod == PutMethod {
		methods = append(methods, "PUT")
	}
	if flags&PatchMethod == PatchMethod {
		methods = append(methods, "PATCH")
	}
	if flags&DeleteMethod == DeleteMethod {
		methods = append(methods, "DELETE")
	}
	return methods
}

func isRoleMatch(needs, supplies []string) bool {
	for _, need := range needs {
		if need == "*@*" {
			return true
		}
		for _, supply := range supplies {
			if supply == "*@*" {
				return true
			}
			if strings.Contains(need, "*") && strings.Contains(supply, "*") {
				continue
			} else if strings.Contains(need, "*") {
				needPattern := fmt.Sprintf("^%s$", strings.ReplaceAll(need, "*", `.*`))
				match, err := regexp.MatchString(needPattern, supply)
				if err == nil && match {
					return true
				}
			} else if strings.Contains(supply, "*") {
				supplyPattern := fmt.Sprintf("^%s$", strings.ReplaceAll(supply, "*", `.*`))
				match, err := regexp.MatchString(supplyPattern, need)
				if err == nil && match {
					return true
				}
			} else if need == supply {
				return true
			}
		}
	}
	return false
}
