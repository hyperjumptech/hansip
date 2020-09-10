package constants

type ContextKey int

const (
	RequestID            ContextKey = 1
	HansipAuthentication ContextKey = 2

	RequestIDHeader = "X-Request-ID"
)
