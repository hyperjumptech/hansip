package endpoint

import (
	"context"
	"fmt"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/internal/hansipcontext"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"net/http"
)

// JwtMiddleware handle authorization check for accessed endpoint by inspecting the Authorization header and look for JWT token.
func JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, ep := range Endpoints {
			tok, err := ep.AccessValid(r, TokenFactory)
			if err != nil {
				hansipContext := &hansipcontext.AuthenticationContext{
					Token:     tok.Token,
					Subject:   tok.Subject,
					Audience:  tok.Audiences,
					TokenType: tok.Additional["type"].(string),
				}
				tokenCtx := context.WithValue(r.Context(), constants.HansipAuthentication, hansipContext)
				next.ServeHTTP(w, r.WithContext(tokenCtx))
				return
			}
		}
		helper.WriteHTTPResponse(r.Context(), w, http.StatusUnauthorized, fmt.Sprintf("You are not authorized to access this end point %s", r.URL.Path), nil, nil)
		return
	})
}
