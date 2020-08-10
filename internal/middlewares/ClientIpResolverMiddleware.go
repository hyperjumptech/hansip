package middlewares

import (
	"net/http"
	"strings"
)

var (
	// ForwardedForHeader header key for X-Forwarded-For
	ForwardedForHeader = http.CanonicalHeaderKey("X-Forwarded-For")

	// RealIpHeader header key for X-Real-IP
	RealIpHeader = http.CanonicalHeaderKey("X-Real-IP")
)

// ClientIPResolverMiddleware will try to resolve caller's real IP address by looking for gateway injected header such as X-Forwarded-For and X-Real-IP
func ClientIPResolverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ForwardedHeader := r.Header.Get(ForwardedForHeader)
		if len(ForwardedForHeader) > 0 {
			r.RemoteAddr = ForwardedHeader
		} else {
			RealHeader := r.Header.Get(RealIpHeader)
			if len(RealHeader) > 0 {
				i := strings.Index(RealHeader, ", ")
				if i == -1 {
					i = len(RealHeader)
				}
				r.RemoteAddr = RealHeader[:i]
			}
		}
		next.ServeHTTP(w, r)
	})
}
