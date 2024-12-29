package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"payments-standard-protocol/paseto"
	"payments-standard-protocol/utils"
	"strings"
	"time"

	validator "github.com/tiendc/go-validator"
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
	Payment PaymentInstruction `json:"payment"`
	Order   OrderInstruction   `json:"order"`
}

type PaymentInstruction struct {
	Id         string `json:"id"`
	Address    string `json:"address"`
	AddressTag string `json:"address_tag"`
	Network    string `json:"network"`
	Coin       string `json:"coin"`
	IsOpen     bool   `json:"is_open"`
	Amount     string `json:"amount"`
	MinAmount  string `json:"min_amount"`
	MaxAmount  string `json:"max_amount"`
}

type OrderInstruction struct {
	TotalAmount string              `json:"total_amount"`
	CoinCode    string              `json:"coin_code"`
	Description string              `json:"description"`
	Items       []InstructionItem   `json:"items"`
	Merchant    InstructionMerchant `json:"merchant"`
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
	VerifyOptions paseto.PasetoVerifyOptions
	KeyId         string
	KeyIssuer     string
	IgnoreKeyExp  bool
}

type QrCriptoCreateOptions struct {
	SignOptions   paseto.PasetoSignOptions
	KeyIssuer     string
	KeyExpiration string
}

type PaymentInstructionsBuilder struct {
	PasetoHandler paseto.PasetoV4
}

func (p PaymentInstructionsBuilder) Read(qrCrypto string, publicKey string, options QrCriptoReadOptions) (paseto.PasetoCompleteResult, error) {
	var isValid = strings.HasPrefix(qrCrypto, "qr-crypto.")

	if !isValid {
		return paseto.PasetoCompleteResult{}, errors.New("invalid 'qr-crypto' token prefix")
	}

	token := strings.Replace(qrCrypto, "qr-crypto.", "", 1)

	options.VerifyOptions.IgnoreExp = false
	options.VerifyOptions.IgnoreIat = false
	options.VerifyOptions.Assertion = []byte(publicKey)

	var data, err = p.PasetoHandler.Verify(
		token,
		publicKey,
		options.VerifyOptions,
	)

	if err != nil {
		return paseto.PasetoCompleteResult{}, err
	}

	if options.KeyId != "" && data.Payload.Kid != options.KeyId {
		return paseto.PasetoCompleteResult{}, errors.New("invalid Key ID")
	}

	if options.KeyIssuer != "" && options.KeyIssuer != data.Payload.Kis {
		return paseto.PasetoCompleteResult{}, errors.New("invalid Key Issuer")
	}

	if !options.IgnoreKeyExp {
		keyExpiredAt, err := time.Parse(time.RFC3339, data.Payload.Kep)

		if err != nil {
			return paseto.PasetoCompleteResult{}, errors.New("invalid key expiration")
		}

		if time.Now().After(keyExpiredAt) {
			return paseto.PasetoCompleteResult{}, errors.New("expired Key")
		}
	}

	return data, nil
}

func (p PaymentInstructionsBuilder) CreateUrlPayload(data UrlPayload, secretKey string, options QrCriptoCreateOptions) (string, error) {

	isValid, err := validateUrlPayload(data)

	if !isValid {
		return "", err
	}

	return p.create(data, secretKey, options)
}

func (p PaymentInstructionsBuilder) CreatePaymentInstruction(data InstructionPayload, secretKey string, options QrCriptoCreateOptions) (string, error) {

	isValid, err := validatePaymentInstructionPayload(data)

	if !isValid {
		return "", err
	}

	return p.create(data, secretKey, options)
}

func (p PaymentInstructionsBuilder) create(data any, secretKey string, options QrCriptoCreateOptions) (string, error) {

	keyOptions := TokenPublicKeyOptions{KeyId: options.SignOptions.KeyId, KeyIssuer: options.KeyIssuer, KeyExpiration: options.KeyExpiration}

	isValid, err := validateParameters(secretKey, keyOptions)

	if !isValid {
		return "", err
	}

	if options.SignOptions.ExpiresIn == "" {
		fmt.Println(
			`\x1b[33m[WARNING]\x1b[0m: Field 'expiresIn' not provided in QR-Crypto token creation.
		   It is recommended to set an expiration time.
		   Use default of 10 minutes.`,
		)
		options.SignOptions.ExpiresIn = "10m"
	}

	var payload = map[string]any{"payload": data, "kid": keyOptions.KeyId, "kis": keyOptions.KeyIssuer, "kep": keyOptions.KeyExpiration}

	payloadString, errJson := json.Marshal(payload)

	if errJson != nil {
		return "", errors.New("invalid Payload Json")
	}

	pasetoToken, errPaseto := p.PasetoHandler.Sign(string(payloadString), secretKey, options.SignOptions)

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

	keyExpiredAt, err := time.Parse(utils.RFC3339Mili, optionsKey.KeyExpiration)

	if err != nil {
		return false, errors.New("invalid key expiration")
	}

	if time.Now().After(keyExpiredAt) {
		return false, errors.New("expired Key")
	}

	return true, nil
}

func validateUrlPayload(payload UrlPayload) (bool, error) {
	errs := validator.Validate(
		validator.StrIsRequestURL(&payload.Url).OnError(
			validator.SetField("url", nil),
			validator.SetCustomKey("invalid url"),
		),
	)

	if len(errs) > 0 {
		return false, errs[0]
	}

	return true, nil
}

func validatePaymentInstructionPayload(payload InstructionPayload) (bool, error) {
	errs := validator.Validate(
		validator.StrLen(&payload.Payment.Id, 1, 1000).OnError(
			validator.SetField("payment_id", nil),
		),
		validator.StrLen(&payload.Payment.Address, 1, 1000).OnError(
			validator.SetField("payment_address", nil),
		),
		validator.StrLen(&payload.Payment.AddressTag, 0, 100).OnError(
			validator.SetField("payment_address_tag", nil),
		),
		validator.StrLen(&payload.Payment.Network, 1, 100).OnError(
			validator.SetField("payment_network", nil),
		),
		validator.StrLen(&payload.Payment.Coin, 2, 100).OnError(
			validator.SetField("payment_coin", nil),
		),

		validator.When(payload.Payment.IsOpen).Then(
			validator.Must(payload.Payment.MinAmount != "" && utils.BiggerThanOrEqualZero(payload.Payment.MinAmount)).OnError(
				validator.SetField("payment_min_amount", nil),
				validator.SetCustomKey("PAYMENT_MIN_AMOUNT_INVALID"),
			),

			validator.Must(payload.Payment.MaxAmount != "" && utils.BiggerThanZero(payload.Payment.MaxAmount)).OnError(
				validator.SetField("payment_min_amount", nil),
				validator.SetCustomKey("PAYMENT_MAX_AMOUNT_INVALID"),
			),
		).Else(
			validator.Must(utils.BiggerThanZero(payload.Payment.Amount)).OnError(
				validator.SetField("payment_amount", nil),
				validator.SetCustomKey("PAYMENT_AMOUNT_INVALID"),
			),
		),

		validator.When(payload.Order.CoinCode != "").Then(validator.StrLen(&payload.Order.CoinCode, 2, 50).OnError(
			validator.SetField("order_coin_code", nil),
		)),
		validator.When(payload.Order.Description != "").Then(validator.StrLen(&payload.Order.Description, 1, 200).OnError(
			validator.SetField("order_description", nil),
		)),
		validator.When(payload.Order.TotalAmount != "").Then(
			validator.Must(utils.BiggerThanOrEqualZero(payload.Order.TotalAmount)).OnError(
				validator.SetField("order_total_amount", nil),
				validator.SetCustomKey("ORDER_TOTAL_AMOUNT_INVALID"),
			)),
		validator.When(payload.Order.Merchant.Name != "").Then(validator.StrLen(&payload.Order.Merchant.Name, 3, 100).OnError(
			validator.SetField("order_merchant_name", nil),
		)),
		validator.When(payload.Order.Merchant.Description != "").Then(validator.StrLen(&payload.Order.Merchant.Description, 3, 200).OnError(
			validator.SetField("order_merchant_description", nil),
		)),
		validator.When(payload.Order.Merchant.TaxId != "").Then(validator.StrLen(&payload.Order.Merchant.TaxId, 6, 50).OnError(
			validator.SetField("order_merchant_tax_id", nil),
		)),
		validator.When(payload.Order.Merchant.ImageUrl != "").Then(validator.StrIsRequestURI(&payload.Order.Merchant.ImageUrl).OnError(
			validator.SetField("order_merchant_image_url", nil),
		)),
		validator.Slice(payload.Order.Items).ForEach(func(elem InstructionItem, index int, vld validator.ItemValidator) {
			vld.Validate(
				validator.When(elem.Title != "").Then(
					validator.StrLen(&elem.Title, 3, 100).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_title", index), nil),
					),
					validator.NumGT(&elem.Quantity, 0).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_quantity", index), nil),
					),
					validator.Must(utils.BiggerThanOrEqualZero(elem.Amount)).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_amount", index), nil),
						validator.SetCustomKey(fmt.Sprintf("ORDER_ITEM_[%d]_TOTAL_AMOUNT_INVALID", index)),
					),
				),
				validator.When(elem.Description != "").Then(
					validator.StrLen(&elem.Description, 3, 100).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_description", index), nil),
					)),
				validator.When(elem.UnitPrice != "").Then(
					validator.StrLen(&elem.UnitPrice, 1, 20).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_unit_price", index), nil),
					)),
				validator.When(elem.CoinCode != "").Then(
					validator.StrLen(&elem.CoinCode, 2, 50).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_coin_code", index), nil),
					)),
				validator.When(elem.ImageUrl != "").Then(validator.StrIsRequestURI(&elem.ImageUrl).OnError(
					validator.SetField(fmt.Sprintf("order_item_[%d]_image_url", index), nil),
				)),
			)
		}),
	)

	if len(errs) > 0 {
		return false, errs[0]
	}

	return true, nil
}
