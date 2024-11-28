package paseto

type SignOptions struct {
	Assertion string
	Audience  string
	ExpiresIn string
	Footer    string
	Issuer    string
	Jti       string
	Kid       string
	NotBefore string
	Subject   string
}
