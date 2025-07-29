package paseto

import (
	"errors"
	"time"

	"github.com/fluxisus/naspip-go/v3/encoding/protobuf"
	"github.com/fluxisus/naspip-go/v3/utils"

	str2duration "github.com/xhit/go-str2duration/v2"

	pasetoV4 "zntr.io/paseto/v4"
)

// PasetoTokenData represents the payload structure of a PASETO token.
// It contains standard PASETO claims as well as custom data for NASPIP.
type PasetoTokenData struct {
	Iss  string                 `json:"iss"`  // Issuer of the token
	Sub  string                 `json:"sub"`  // Subject of the token
	Aud  string                 `json:"aud"`  // Audience of the token
	Exp  string                 `json:"exp"`  // Expiration time (RFC3339Mili format)
	Nbf  string                 `json:"nbf"`  // Not before time (RFC3339Mili format)
	Iat  string                 `json:"iat"`  // Issued at time (RFC3339Mili format)
	Jti  string                 `json:"jti"`  // JWT ID (unique identifier)
	Kid  string                 `json:"kid"`  // Key ID
	Kep  string                 `json:"kep"`  // Key expiration time (RFC3339 format)
	Kis  string                 `json:"kis"`  // Key issuer
	Data map[string]interface{} `json:"data"` // Custom payload data
}

// PasetoCompleteResult represents a fully parsed PASETO token.
// It includes version information, purpose, footer, and the payload data.
type PasetoCompleteResult struct {
	Version string          `json:"version"` // PASETO version (v4)
	Purpose string          `json:"purpose"` // PASETO purpose (public)
	Footer  []byte          `json:"footer"`  // Token footer
	Payload PasetoTokenData `json:"payload"` // Parsed token payload
}

// PasetoV4Handler implements the PasetoV4 interface for handling PASETO v4 tokens.
// It provides methods for signing and verifying tokens using Ed25519 keys.
type PasetoV4Handler struct{}

// Sign creates a new PASETO v4 token with the provided payload and signing options.
//
// Parameters:
//   - payload: Protocol buffer encoded data to include in the token
//   - privateKey: Ed25519 private key in raw or PASERK format
//   - options: Configuration options for the token
//
// Returns:
//   - A PASETO v4 token string or an error if token creation fails
func (p PasetoV4Handler) Sign(payload []byte, privateKey string, options PasetoSignOptions) (string, error) {
	var data protobuf.PasetoTokenData

	if err := protobuf.DecodeProto(payload, &data); err != nil {
		return "", err
	}

	var issuedAt = time.Now().UTC()

	data.Iss = options.Issuer
	data.Aud = options.Audience
	data.Sub = options.Subject
	data.Jti = options.Jti
	data.Kid = options.KeyId
	data.Iat = issuedAt.Format(utils.RFC3339Mili)

	if options.IssuedAt != "" {
		var err error
		issuedAt, err = time.Parse(utils.RFC3339Mili, options.IssuedAt)

		if err != nil {
			return "", errors.New("invalid issuedAt format")
		}
		data.Iat = issuedAt.Format(utils.RFC3339Mili)
	}

	if options.ExpiresIn != "" {
		dur, err := str2duration.ParseDuration(options.ExpiresIn)

		if err != nil {
			return "", errors.New("invalid expiresIn format")
		}

		data.Exp = issuedAt.Add(dur).Format(utils.RFC3339Mili)
	}

	if options.NotBefore != "" {
		dur, err := str2duration.ParseDuration(options.NotBefore)

		if err != nil {
			return "", errors.New("invalid notBefore format")
		}

		data.Nbf = issuedAt.Add(dur).Format(utils.RFC3339Mili)
	}

	var key = GetPrivateKey(privateKey)

	dataBytes, err := protobuf.EncodeProto(&data)

	if err != nil {
		return "", err
	}

	return pasetoV4.Sign(dataBytes, key, options.Footer, options.Assertion)
}

// Verify validates a PASETO v4 token using the provided public key and options.
//
// Parameters:
//   - token: PASETO v4 token to verify
//   - publicKey: Ed25519 public key in raw or PASERK format
//   - options: Verification options and expected claims
//
// Returns:
//   - A parsed PasetoCompleteResult containing the token data if verification succeeds
//   - An error if verification fails for any reason
func (p PasetoV4Handler) Verify(token string, publicKey string, options PasetoVerifyOptions) (*PasetoCompleteResult, error) {

	var key = GetPublicKey(publicKey)

	tokenBytes, err := pasetoV4.Verify(token, key, options.Footer, options.Assertion)

	if err != nil {
		return nil, err
	}

	var tokenData protobuf.PasetoTokenData

	err = protobuf.DecodeProto(tokenBytes, &tokenData)

	if err != nil {
		return nil, err
	}

	var payload PasetoTokenData

	err = protobuf.ConvertProtoToGo(&tokenData, &payload)

	if err != nil {
		return nil, err
	}

	// For InstructionPayload, convert payment.expires_at to int64
	if paymentData, ok := payload.Data["payment"]; ok {
		if paymentMap, ok := paymentData.(map[string]interface{}); ok {
			if expiresAtStr, ok := paymentMap["expires_at"].(string); ok {
				paymentMap["expires_at"] = utils.FormatStringTimestampToUnixMilli(expiresAtStr)
			}
		}
	}

	verifyErr := assertPayload(payload, options)

	if verifyErr != nil {
		return nil, verifyErr
	}

	var data = PasetoCompleteResult{Version: "v4", Purpose: "public", Footer: []byte{}, Payload: payload}

	return &data, nil
}

// assertPayload validates the claims within a PASETO token payload according to the verification options.
// It checks issuer, subject, audience, issued-at time, not-before time, expiration, and token age.
//
// Returns an error if any validation fails according to the provided options.
func assertPayload(payload PasetoTokenData, options PasetoVerifyOptions) error {

	var now = time.Now().UTC()

	// Check iss
	if options.Issuer != "" && payload.Iss != options.Issuer {
		return errors.New("issuer mismatch")
	}

	// Check sub
	if options.Subject != "" && payload.Sub != options.Subject {
		return errors.New("subject mismatch")
	}

	// Check aud
	if options.Audience != "" && payload.Aud != options.Audience {
		return errors.New("audience mismatch")
	}

	// Check iat
	if !options.IgnoreIat {
		if payload.Iat == "" {
			return errors.New("payload.iat is required")
		}

		iat, err := time.Parse(utils.RFC3339Mili, payload.Iat)

		if err != nil {
			return errors.New("payload.iat must be a valid RFC3339 string")
		}

		if now.Before(iat) {
			return errors.New("token issued in the future")
		}
	}

	// Check nbf
	if !options.IgnoreNbf && payload.Nbf != "" {
		nbf, err := time.Parse(utils.RFC3339Mili, payload.Nbf)

		if err != nil {
			return errors.New("payload.nbf must be a valid RFC3339 string")
		}

		if now.Before(nbf) {
			return errors.New("token is not active yet")
		}
	}

	// Check exp
	if !options.IgnoreExp {
		if payload.Exp == "" {
			return errors.New("payload.exp is required")
		}

		exp, err := time.Parse(utils.RFC3339Mili, payload.Exp)

		if err != nil {
			return errors.New("payload.exp must be a valid RFC3339 string")
		}

		if now.After(exp) {
			return errors.New("token is expired")
		}
	}

	// Check maxTokenAge
	if !options.IgnoreIat && options.MaxTokenAge != "" {

		maxDuration, err := str2duration.ParseDuration(options.MaxTokenAge)

		if err != nil {
			return errors.New("invalid MaxTokenAge format")
		}

		iat, _ := time.Parse(utils.RFC3339Mili, payload.Iat)

		if now.After(iat.Add(maxDuration)) {
			return errors.New("maxTokenAge exceeded")
		}
	}

	// Check if this is a payment instruction or URL payload
	if _, exists := payload.Data["payment"]; exists {
		// This is a payment instruction payload - validation passed
		return nil
	} else if _, exists := payload.Data["url_payload"]; exists {
		// This is a URL payload - no expires_at field needed
		return nil
	} else if _, exists := payload.Data["data"]; exists {
		// Check if data contains url_payload or payment
		if dataMap, ok := payload.Data["data"].(map[string]interface{}); ok {
			if _, hasUrl := dataMap["url"]; hasUrl {
				// This is a URL payload
				return nil
			} else if _, hasPayment := dataMap["payment"]; hasPayment {
				// This is a payment instruction
				return nil
			}
		}
		// Unknown payload type
		return errors.New("unknown payload type")
	} else if _, exists := payload.Data["url"]; exists {
		// This is a URL payload (flattened structure)
		return nil
	} else {
		// Unknown payload type
		return errors.New("unknown payload type")
	}
}
