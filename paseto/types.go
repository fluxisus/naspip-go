package paseto

type PasetoSignOptions struct {
	Footer    []byte
	Assertion []byte
	Audience  string
	IssuedAt  string
	ExpiresIn string
	Issuer    string
	Jti       string
	KeyId     string
	NotBefore string
	Subject   string
}

type PasetoVerifyOptions struct {
	Footer      []byte
	Assertion   []byte
	IgnoreExp   bool
	IgnoreIat   bool
	IgnoreNbf   bool
	MaxTokenAge string
	Issuer      string
	Subject     string
	Audience    string
}

type PasetoV4 interface {
	Sign(payload string, privateKey string, options PasetoSignOptions) (string, error)
	Verify(token string, publicKey string, options PasetoVerifyOptions) (PasetoCompleteResult, error)
}
