package endpoint

import (
	"github.com/hyperjumptech/hansip/pkg/helper"
	"net/http"
)

// health serve health check request
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("cache-control", "no-cache")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	hc := &helper.HealthCheck{}
	_, _ = w.Write([]byte(hc.String()))
}
