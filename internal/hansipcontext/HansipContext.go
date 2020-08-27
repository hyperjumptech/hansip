package hansipcontext

// AuthenticationContext is custom authentication context
type AuthenticationContext struct {
	Token     string
	Subject   string
	Audience  []string
	TokenType string
}
