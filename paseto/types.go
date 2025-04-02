// Package paseto provides PASETO (Platform-Agnostic Security Tokens) v4 functionality
// for the NASPIP protocol. It handles the creation, signing, and verification of tokens
// using Ed25519 asymmetric keys.
package paseto

// PasetoSignOptions contains the options for signing a PASETO token.
// These options control various token claims and metadata.
type PasetoSignOptions struct {
	Footer    []byte // Additional authenticated data stored in the token's footer
	Assertion []byte // Additional authenticated data used as an anti-replay measure
	Audience  string // Intended audience of the token
	IssuedAt  string // Time when the token was issued (RFC3339Mili format)
	ExpiresIn string // Duration string for token expiration (e.g., "1h", "2d")
	Issuer    string // Entity that issued the token
	Jti       string // Unique identifier for the token
	KeyId     string // Identifier for the key used to sign the token
	NotBefore string // Duration string before which the token is not valid
	Subject   string // Subject of the token
}

// PasetoVerifyOptions contains the options for verifying a PASETO token.
// These options control validation rules and expected claims.
type PasetoVerifyOptions struct {
	Footer      []byte // Additional authenticated data stored in the token's footer
	Assertion   []byte // Additional authenticated data used as an anti-replay measure
	IgnoreExp   bool   // Whether to ignore expiration time validation
	IgnoreIat   bool   // Whether to ignore issued-at time validation
	IgnoreNbf   bool   // Whether to ignore not-before time validation
	MaxTokenAge string // Maximum allowed age of token (duration string)
	Issuer      string // Expected issuer of the token
	Subject     string // Expected subject of the token
	Audience    string // Expected audience of the token
}

// PasetoV4 defines the interface for PASETO v4 token operations.
// Implementations of this interface provide methods for signing and verifying tokens.
type PasetoV4 interface {
	// Sign creates a signed PASETO token with the provided payload and options.
	Sign(payload []byte, privateKey string, options PasetoSignOptions) (string, error)

	// Verify validates a PASETO token against the provided public key and options,
	// returning the parsed token content if valid.
	Verify(token string, publicKey string, options PasetoVerifyOptions) (*PasetoCompleteResult, error)
}
