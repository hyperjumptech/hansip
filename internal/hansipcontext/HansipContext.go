package hansipcontext

// AuthenticationContext is a context value to be add into request context.
type AuthenticationContext struct {
	Token     string
	Subject   string
	Audience  []string
	TokenType string
}
