package paseto

type PasetoSignOptions struct {
	Assertion []byte
	Audience  string
	ExpiresIn string
	Footer    []byte
	Issuer    string
	Jti       string
	KeyId     string
	NotBefore string
	Subject   string
}

type PasetoV4 interface {
	Sign(payload string, privateKey string, options PasetoSignOptions) (string, error)
	Verify(token string, publicKey string) (PasetoCompleteResult, error)
}
