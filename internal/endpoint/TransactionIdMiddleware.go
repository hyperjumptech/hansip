package endpoint

import (
	"context"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

var (
	trxMiddlewareLog = log.WithField("go", "TrackingMiddleware")
)

// TransactionIDMiddleware handles X-Request-Id handler, if no X-Request-Id found, it will create one.
func TransactionIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(constants.RequestIDHeader)
		if len(requestID) == 0 {
			requestID = helper.MakeRandomString(20, true, true, true, false)
		}
		log := trxMiddlewareLog.WithField("path", r.URL.Path).WithField("RequestID", requestID).WithField("func", "TransactionIDMiddleware").WithField("method", r.Method)
		log.Tracef("request start")
		start := time.Now()
		ctx := context.WithValue(r.Context(), constants.RequestID, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
		dur := time.Now().Sub(start)
		log.WithField("ms", dur.Milliseconds()).Tracef("request end")
	})
}
