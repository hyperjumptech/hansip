package hansipcontext

type AuthenticationContext struct {
	Token     string
	Subject   string
	Audience  []string
	TokenType string
}
