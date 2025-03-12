package paseto

import (
	"errors"
	"time"

	"github.com/fluxisus/payments-standard-protocol-go/v2/encoding/protobuf"
	"github.com/fluxisus/payments-standard-protocol-go/v2/utils"

	str2duration "github.com/xhit/go-str2duration/v2"

	pasetoV4 "zntr.io/paseto/v4"
)

type PasetoTokenData struct {
	Iss  string                 `json:"iss"`
	Sub  string                 `json:"sub"`
	Aud  string                 `json:"aud"`
	Exp  string                 `json:"exp"`
	Nbf  string                 `json:"nbf"`
	Iat  string                 `json:"iat"`
	Jti  string                 `json:"jti"`
	Kid  string                 `json:"kid"`
	Kep  string                 `json:"kep"`
	Kis  string                 `json:"kis"`
	Data map[string]interface{} `json:"data"`
}

type PasetoCompleteResult struct {
	Version string          `json:"version"`
	Purpose string          `json:"purpose"`
	Footer  []byte          `json:"footer"`
	Payload PasetoTokenData `json:"payload"`
}

type PasetoV4Handler struct{}

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

	verifyErr := assertPayload(payload, options)

	if verifyErr != nil {
		return nil, verifyErr
	}

	var data = PasetoCompleteResult{Version: "v4", Purpose: "public", Footer: []byte{}, Payload: payload}

	return &data, nil
}

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

	return nil
}
