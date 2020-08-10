package constants

type ContextKey int

const (
	RequestId            ContextKey = 1
	HansipAuthentication ContextKey = 2

	RequestIdHeader = "X-Request-ID"
)
