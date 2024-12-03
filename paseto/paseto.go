package paseto

import (
	"encoding/json"
	"errors"
	"time"

	str2duration "github.com/xhit/go-str2duration/v2"

	pasetoV4 "zntr.io/paseto/v4"
)

type PasetoTokenData struct {
	Iss     string         `json:"iss"`
	Sub     string         `json:"sub"`
	Aud     string         `json:"aud"`
	Exp     string         `json:"exp"`
	Nbf     string         `json:"nbf"`
	Iat     string         `json:"iat"`
	Jti     string         `json:"jti"`
	Kid     string         `json:"kid"`
	Kep     string         `json:"kep"`
	Kis     string         `json:"kis"`
	Payload map[string]any `json:"payload"`
}

type PasetoCompleteResult struct {
	Version string          `json:"version"`
	Purpose string          `json:"purpose"`
	Footer  []byte          `json:"footer"`
	Payload PasetoTokenData `json:"payload"`
}

type PasetoV4Handler struct{}

func (p PasetoV4Handler) Sign(payload string, privateKey string, options PasetoSignOptions) (string, error) {
	var data PasetoTokenData

	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return "", err
	}

	var now = time.Now().UTC()

	data.Iss = options.Issuer
	data.Aud = options.Audience
	data.Sub = options.Subject
	data.Jti = options.Jti
	data.Kid = options.KeyId
	data.Iat = now.Format(time.RFC3339)

	if options.ExpiresIn != "" {
		dur, err := str2duration.ParseDuration(options.ExpiresIn)

		if err != nil {
			return "", errors.New("invalid expiresIn format")
		}

		data.Exp = now.Add(dur).Format(time.RFC3339)
	}

	if options.NotBefore != "" {
		dur, err := str2duration.ParseDuration(options.NotBefore)

		if err != nil {
			return "", errors.New("invalid notBefore format")
		}

		data.Nbf = now.Add(dur).Format(time.RFC3339)
	}

	var key = GetPrivateKey(privateKey)

	dataJson, _ := json.Marshal(data)

	return pasetoV4.Sign(dataJson, key, options.Footer, options.Assertion)
}

func (p PasetoV4Handler) Verify(token string, publicKey string) (PasetoCompleteResult, error) {

	var key = GetPublicKey(publicKey)

	tokenData, err := pasetoV4.Verify(token, key, nil, nil)

	if err != nil {
		return PasetoCompleteResult{}, err
	}

	var payload PasetoTokenData

	json.Unmarshal(tokenData, &payload)

	var data = PasetoCompleteResult{Version: "v4", Purpose: "public", Footer: []byte{}, Payload: payload}

	return data, err
}
