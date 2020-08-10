package helper

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// StatusPass if the health check is ok
	StatusPass = "pass"
	// StatusFail if the health check is failing
	StatusFail = "fail"
	// StatusWarn if the health check has some component warning
	StatusWarn = "warn"
)

// HealthDetail structure shows health check in the component level
type HealthDetail struct {
	DetailKey     string    `json:"-"`
	ComponentID   string    `json:"componentId"`
	ComponentType string    `json:"componentType"`
	MetricValue   int       `json:"metricValue"`
	MetricUnit    string    `json:"metricUnit"`
	Time          time.Time `json:"time"`
	Status        string    `json:"status"`
}

// HealthCheck structure to return when health check is called
type HealthCheck struct {
	fmt.Stringer
	Status  string                   `json:"status"`
	Time    time.Time                `json:"time"`
	Version string                   `json:"version"`
	Details map[string]*HealthDetail `json:"details"`
}

// AddDetail add health check details
func (hc *HealthCheck) AddDetail(detail *HealthDetail) {
	if hc.Details == nil {
		hc.Details = make(map[string]*HealthDetail)
	}
	hc.Details[detail.DetailKey] = detail
}

// String returns Health check json
func (hc *HealthCheck) String() string {
	hc.Time = time.Now()
	hc.Version = "1"
	hc.Status = StatusPass
	if hc.Details == nil || len(hc.Details) == 0 {
		hc.Status = StatusPass
	} else {
		for _, v := range hc.Details {
			if v.Status != StatusPass {
				hc.Status = StatusWarn
			}
		}
	}
	bytes, _ := json.Marshal(hc)
	return string(bytes)
}
