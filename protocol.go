package main

import (
	"crypto-payments-standard-protocol/paseto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type TokenPublicKeyOptions struct {
	KeyId         string
	KeyExpiration string
	KeyIssuer     string
}

type UrlPayload struct {
	Url      string `json:"url"`
	IsStatic bool   `json:"is_static"`
}

type InstructionPayload struct {
	Payment struct {
		Id         string `json:"id"`
		Address    string `json:"address"`
		AddressTag string `json:"address_tag"`
		Network    string `json:"network"`
		Coin       string `json:"coin"`
		IsOpen     bool   `json:"is_open"`
		Amount     string `json:"amount"`
		MinAmount  string `json:"min_amount"`
		MaxAmount  string `json:"max_amount"`
	} `json:"payment"`
	Order struct {
		TotalAmount string              `json:"total_amount"`
		CoinCode    string              `json:"coin_code"`
		Description string              `json:"description"`
		Items       []InstructionItem   `json:"items"`
		Merchant    InstructionMerchant `json:"merchant"`
	} `json:"order"`
}

type InstructionMerchant struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	TaxId       string `json:"tax_id"`
	ImageUrl    string `json:"image_url"`
}

type InstructionItem struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Amount      string `json:"amount"`
	UnitPrice   string `json:"unit_price"`
	Quantity    int    `json:"quantity"`
	CoinCode    string `json:"coin_code"`
	ImageUrl    string `json:"image_url"`
}

type QrCriptoReadOptions struct {
	paseto.PasetoSignOptions
	KeyIssuer    string
	IgnoreKeyExp bool
}

type QrCriptoCreateOptions struct {
	paseto.PasetoSignOptions
	KeyIssuer     string
	KeyExpiration string
}

type PaymentInstructionsBuilder struct {
	PasetoHandler paseto.PasetoV4
}

func (p PaymentInstructionsBuilder) Read(qrCrypto string, publicKey string, options QrCriptoReadOptions) (any, error) {
	var isValid = strings.HasPrefix(qrCrypto, "qr-crypto.")

	if !isValid {
		return nil, errors.New("invalid 'qr-crypto' token prefix")
	}

	token := strings.Replace(qrCrypto, "qr-crypto.", "", 1)

	var data, err = p.PasetoHandler.Verify(
		token,
		publicKey,
	)

	if err != nil {
		return nil, err
	}

	if options.KeyId != "" && data.Payload.Kid != options.KeyId {
		return nil, errors.New("invalid Key ID")
	}

	if options.KeyIssuer != "" && options.KeyIssuer != data.Payload.Kis {
		return nil, errors.New("invalid Key Issuer")
	}

	if !options.IgnoreKeyExp {
		keyExpiredAt, err := time.Parse(time.RFC3339, data.Payload.Kep)

		if err != nil {
			return nil, errors.New("invalid key expiration")
		}

		if time.Now().After(keyExpiredAt) {
			return nil, errors.New("expired Key")
		}
	}

	return data, nil
}

func (p PaymentInstructionsBuilder) Create(data any, secretKey string, options QrCriptoCreateOptions) (string, error) {

	keyOptions := TokenPublicKeyOptions{KeyId: options.KeyId, KeyIssuer: options.KeyIssuer, KeyExpiration: options.KeyExpiration}

	isValid, err := validateParameters(secretKey, keyOptions)

	if !isValid {
		return "", err
	}

	if options.ExpiresIn == "" {
		fmt.Println(
			`\x1b[33m[WARNING]\x1b[0m: Field 'expiresIn' not provided in QR-Crypto token creation.
		   It is recommended to set an expiration time.
		   Use default of 10 minutes.`,
		)
		options.ExpiresIn = "10m"
	}

	var payload = map[string]any{"payload": data, "kid": keyOptions.KeyId, "kis": keyOptions.KeyIssuer, "kep": keyOptions.KeyExpiration}

	paylosString, errJson := json.Marshal(payload)

	if errJson != nil {
		return "", errors.New("invalid Payload Json")
	}

	pasetoToken, errPaseto := p.PasetoHandler.Sign(string(paylosString), secretKey, options.PasetoSignOptions)

	if errPaseto != nil {
		return "", errPaseto
	}

	qrCrypto := "qr-crypto." + pasetoToken
	return qrCrypto, nil
}

func validateParameters(secretKey string, optionsKey TokenPublicKeyOptions) (bool, error) {

	if secretKey == "" {
		return false, errors.New("secretKey is required for token creation")
	}

	if optionsKey.KeyId == "" {
		return false, errors.New("kid is required for token creation")
	}

	if optionsKey.KeyIssuer == "" {
		return false, errors.New("kis is required for token creation")
	}

	keyExpiredAt, err := time.Parse(time.RFC3339, optionsKey.KeyExpiration)

	if err != nil {
		return false, errors.New("invalid key expiration")
	}

	if time.Now().After(keyExpiredAt) {
		return false, errors.New("expired Key")
	}

	return true, nil
}
