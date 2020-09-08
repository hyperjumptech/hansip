package constants

// ContextKey is key definition
type ContextKey int

const (
	// RequestID context key constant
	RequestID ContextKey = 1
	// HansipAuthentication contenxt key constant
	HansipAuthentication ContextKey = 2

	// RequestIDHeader header constant
	RequestIDHeader = "X-Request-ID"
)
