package constants

// ContextKey a context key to be used with context.Context
type ContextKey int

const (
	// RequestID is context key for RequestID tracking
	RequestID ContextKey = 1

	// HansipAuthentication is context key for hansip authentication information
	HansipAuthentication ContextKey = 2

	// RequestIDHeader is context key for tracking request
	RequestIDHeader = "X-Request-ID"
)
