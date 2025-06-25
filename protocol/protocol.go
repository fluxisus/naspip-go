// Package protocol implements the Network-Agnostic Secure Payment Instructions Protocol (NASPIP).
// It provides functionality for creating, validating, and processing payment instructions
// using PASETO tokens with asymmetric cryptography for security.
package protocol

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fluxisus/naspip-go/v3/encoding/protobuf"
	"github.com/fluxisus/naspip-go/v3/paseto"
	"github.com/fluxisus/naspip-go/v3/utils"
	validator "github.com/tiendc/go-validator"
)

// QrPaymentTokenData represents the structure of a decoded NASPIP token.
// This is the result of splitting a NASPIP token string into its components.
type QrPaymentTokenData struct {
	Prefix    string `json:"prefix"` // Protocol prefix ("naspip")
	KeyIssuer string `json:"kis"`    // Entity that issued the key
	KeyId     string `json:"kid"`    // Unique identifier for the key
	Token     string `json:"token"`  // PASETO token containing encrypted data
}

// TokenPublicKeyOptions contains options related to the key used to sign NASPIP tokens.
type TokenPublicKeyOptions struct {
	KeyId         string // Unique identifier for the key
	KeyExpiration string // When the key expires (RFC3339 format)
	KeyIssuer     string // Entity that issued the key
}

// UrlPayload represents a payment URL instruction payload.
// This is used for directing users to a payment service endpoint.
type UrlPayload struct {
	Url            string           `json:"url"`                       // Payment service URL
	PaymentOptions []string         `json:"payment_options,omitempty"` // Available payment asset IDs
	Order          InstructionOrder `json:"order,omitempty"`           // Optional order information
}

// InstructionPayload represents a complete payment instruction.
// This contains both the payment details and optional order information.
type InstructionPayload struct {
	Payment PaymentInstruction `json:"payment"`         // Payment details
	Order   InstructionOrder   `json:"order,omitempty"` // Optional order information
}

// PaymentInstruction contains the essential details needed to make a payment.
// This includes recipient address, amount, expiration, and other payment parameters.
type PaymentInstruction struct {
	Id            string `json:"id"`                    // Unique payment identifier
	Address       string `json:"address"`               // Recipient's address
	AddressTag    string `json:"address_tag,omitempty"` // Optional tag/memo (for blockchains that require it)
	UniqueAssetId string `json:"unique_asset_id"`       // Asset identifier (cryptocurrency/token)
	IsOpen        bool   `json:"is_open"`               // Whether the amount is open (variable)
	Amount        string `json:"amount,omitempty"`      // Fixed amount (when IsOpen is false)
	MinAmount     string `json:"min_amount,omitempty"`  // Minimum amount (when IsOpen is true)
	MaxAmount     string `json:"max_amount,omitempty"`  // Maximum amount (when IsOpen is true)
	ExpiresAt     int64  `json:"expires_at"`            // Unix timestamp when payment expires
}

// InstructionOrder contains additional information about the order.
// This provides context for the payment such as merchant details and items purchased.
type InstructionOrder struct {
	Total       string              `json:"total"`                 // Total order amount
	CoinCode    string              `json:"coin_code"`             // Currency code (e.g., USD, EUR)
	Description string              `json:"description,omitempty"` // Order description
	Merchant    InstructionMerchant `json:"merchant,omitempty"`    // Merchant information
	Items       []InstructionItem   `json:"items,omitempty"`       // Individual items in the order
}

// InstructionMerchant contains information about the merchant.
// This helps identify the recipient of the payment.
type InstructionMerchant struct {
	Name        string `json:"name"`                  // Merchant name
	Description string `json:"description,omitempty"` // Merchant description
	TaxId       string `json:"tax_id,omitempty"`      // Tax identification number
	Image       string `json:"image,omitempty"`       // Merchant logo/image URL or data URI
	Mcc         string `json:"mcc,omitempty"`         // Merchant category code (ISO 18245)
}

// InstructionItem represents an individual item in an order.
// This provides details about a specific product or service being purchased.
type InstructionItem struct {
	Description string `json:"description"`          // Item description
	Amount      string `json:"amount"`               // Total amount for this item
	CoinCode    string `json:"coin_code"`            // Currency code for this item
	UnitPrice   string `json:"unit_price,omitempty"` // Price per unit
	Quantity    int    `json:"quantity,omitempty"`   // Number of units
}

// QrCriptoReadOptions contains options for reading and verifying NASPIP tokens.
type QrCriptoReadOptions struct {
	VerifyOptions paseto.PasetoVerifyOptions // PASETO verification options
	KeyId         string                     // Expected key ID
	KeyIssuer     string                     // Expected key issuer
	IgnoreKeyExp  bool                       // Whether to ignore key expiration
}

// QrCriptoCreateOptions contains options for creating NASPIP tokens.
type QrCriptoCreateOptions struct {
	SignOptions   paseto.PasetoSignOptions // PASETO signing options
	KeyIssuer     string                   // Key issuer identifier
	KeyExpiration string                   // Key expiration date (RFC3339 format)
}

// PaymentInstructionsBuilder creates and validates NASPIP payment instructions.
// It serves as the main entry point for interacting with the NASPIP protocol.
type PaymentInstructionsBuilder struct {
	PasetoHandler paseto.PasetoV4 // Handler for PASETO operations
}

// Decode splits a NASPIP token string into its components.
// It validates that the token has the correct format and prefix.
//
// Parameters:
//   - qrPayment: A NASPIP token string in the format "naspip;[key-issuer];[key-id];[paseto-token]"
//
// Returns:
//   - A QrPaymentTokenData struct containing the split components
//   - An error if the token format is invalid
func (p PaymentInstructionsBuilder) Decode(qrPayment string) (QrPaymentTokenData, error) {
	values := strings.Split(qrPayment, ";")

	var isValid = len(values) == 4 && values[0] == "naspip"

	if !isValid {
		return QrPaymentTokenData{}, errors.New("invalid naspip token prefix")
	}

	var data = QrPaymentTokenData{Prefix: values[0], KeyIssuer: values[1], KeyId: values[2], Token: values[3]}

	return data, nil
}

// Read decodes and verifies a NASPIP token.
// It validates the token signature and checks expiration dates and key information.
//
// Parameters:
//   - qrPayment: A NASPIP token string to verify
//   - publicKey: The public key (in raw or PASERK format) to verify the token signature
//   - options: Options controlling verification behavior
//
// Returns:
//   - The parsed token content if verification succeeds
//   - An error if decoding or verification fails
func (p PaymentInstructionsBuilder) Read(qrPayment string, publicKey string, options QrCriptoReadOptions) (*paseto.PasetoCompleteResult, error) {
	decodedQr, errQr := p.Decode(qrPayment)

	if errQr != nil {
		return nil, errQr
	}

	options.VerifyOptions.IgnoreExp = false
	options.VerifyOptions.IgnoreIat = false
	options.VerifyOptions.Assertion = []byte(publicKey)

	var data, err = p.PasetoHandler.Verify(
		decodedQr.Token,
		publicKey,
		options.VerifyOptions,
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

// CreateUrlPayload creates a NASPIP token containing a URL payload.
// This is used when redirecting to a payment service that will generate the actual payment instructions.
//
// Parameters:
//   - data: The URL payload to encode in the token
//   - secretKey: The private key (in raw or PASERK format) to sign the token
//   - options: Options for token creation
//
// Returns:
//   - A NASPIP token string if creation succeeds
//   - An error if validation or creation fails
func (p PaymentInstructionsBuilder) CreateUrlPayload(data UrlPayload, secretKey string, options QrCriptoCreateOptions) (string, error) {

	isValid, err := validateUrlPayload(data)

	if !isValid {
		return "", err
	}

	protoPayload := &protobuf.UrlPayload{}
	if err := protobuf.ConvertGoToProto(data, protoPayload); err != nil {
		return "", err
	}

	var payload = &protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_UrlPayload{
			UrlPayload: protoPayload,
		},
	}

	return p.create(payload, secretKey, options)
}

// CreatePaymentInstruction creates a NASPIP token containing complete payment instructions.
// This provides all the information needed to make a payment directly.
//
// Parameters:
//   - data: The payment instruction payload to encode in the token
//   - secretKey: The private key (in raw or PASERK format) to sign the token
//   - options: Options for token creation
//
// Returns:
//   - A NASPIP token string if creation succeeds
//   - An error if validation or creation fails
func (p PaymentInstructionsBuilder) CreatePaymentInstruction(data InstructionPayload, secretKey string, options QrCriptoCreateOptions) (string, error) {

	isValid, err := validatePaymentInstructionPayload(data)

	if !isValid {
		return "", err
	}
	protoPayload := &protobuf.InstructionPayload{}
	if err := protobuf.ConvertGoToProto(data, protoPayload); err != nil {
		return "", err
	}

	var payload = &protobuf.PasetoTokenData{
		Data: &protobuf.PasetoTokenData_InstructionPayload{
			InstructionPayload: protoPayload,
		},
	}

	return p.create(payload, secretKey, options)
}

// create is an internal method that handles the common logic for creating NASPIP tokens.
// It validates parameters, sets defaults, and performs the actual token signing.
//
// Parameters:
//   - data: Protocol buffer encoded payload data
//   - secretKey: Private key for signing
//   - options: Token creation options
//
// Returns:
//   - A NASPIP token string if successful
//   - An error if validation or signing fails
func (p PaymentInstructionsBuilder) create(data *protobuf.PasetoTokenData, secretKey string, options QrCriptoCreateOptions) (string, error) {

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

	data.Kid = keyOptions.KeyId
	data.Kis = keyOptions.KeyIssuer
	data.Kep = keyOptions.KeyExpiration

	payloadBytes, errJson := protobuf.EncodeProto(data)

	if errJson != nil {
		return "", errors.New("invalid Payload Json")
	}

	pasetoToken, errPaseto := p.PasetoHandler.Sign(payloadBytes, secretKey, options.SignOptions)

	if errPaseto != nil {
		return "", errPaseto
	}

	qrPayment := strings.Join([]string{"naspip", keyOptions.KeyIssuer, keyOptions.KeyId, pasetoToken}, ";")

	return qrPayment, nil
}

// validateParameters verifies that the required key parameters are present and valid.
// It checks that the secret key is provided and that the key information is complete and valid.
//
// Parameters:
//   - secretKey: The private key to validate
//   - optionsKey: Key options containing ID, issuer, and expiration
//
// Returns:
//   - true if all parameters are valid
//   - false and an error describing the problem if validation fails
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

// validateUrlPayload performs validation on a URL payload.
// It checks that the URL is valid and that all optional fields meet their requirements.
//
// Parameters:
//   - payload: The URL payload to validate
//
// Returns:
//   - true if the payload passes all validation rules
//   - false and an error describing the problem if validation fails
func validateUrlPayload(payload UrlPayload) (bool, error) {
	errs := validator.Validate(
		validator.StrIsRequestURL(&payload.Url).OnError(
			validator.SetField("url", nil),
			validator.SetCustomKey("invalid url"),
		),

		validator.Slice(payload.PaymentOptions).ForEach(func(elem string, index int, vld validator.ItemValidator) {
			validator.StrLen(&elem, 3, 50).OnError(
				validator.SetField("payment_options", nil),
				validator.SetCustomKey(fmt.Sprintf("PAYMENT_OPTIONS_INDEX_[%d]_INVALID", index)),
			)
		}),

		validator.When(payload.Order.CoinCode != "").Then(validator.StrLen(&payload.Order.CoinCode, 2, 50).OnError(
			validator.SetField("order_coin_code", nil),
		)),
		validator.When(payload.Order.Description != "").Then(validator.StrLen(&payload.Order.Description, 1, 200).OnError(
			validator.SetField("order_description", nil),
		)),
		validator.When(payload.Order.Total != "").Then(
			validator.Must(utils.BiggerThanOrEqualZero(payload.Order.Total)).OnError(
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
		validator.When(payload.Order.Merchant.Image != "").Then(validator.StrIsRequestURI(&payload.Order.Merchant.Image).OnError(
			validator.SetField("order_merchant_image_url", nil),
		)),
		validator.Slice(payload.Order.Items).ForEach(func(elem InstructionItem, index int, vld validator.ItemValidator) {
			vld.Validate(
				validator.When(elem.Description != "").Then(
					validator.StrLen(&elem.Description, 3, 100).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_description", index), nil),
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
			)
		}),
	)

	if len(errs) > 0 {
		return false, errs[0]
	}

	return true, nil
}

// validatePaymentInstructionPayload performs validation on a payment instruction payload.
// It checks that required fields are present and that all fields meet their format requirements.
//
// Parameters:
//   - payload: The payment instruction payload to validate
//
// Returns:
//   - true if the payload passes all validation rules
//   - false and an error describing the problem if validation fails
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
		validator.StrLen(&payload.Payment.UniqueAssetId, 1, 100).OnError(
			validator.SetField("payment_unique_asset_id", nil),
		),

		validator.When(payload.Payment.IsOpen).Then(
			validator.Must(payload.Payment.MinAmount == "" || utils.BiggerThanOrEqualZero(payload.Payment.MinAmount)).OnError(
				validator.SetField("payment_min_amount", nil),
				validator.SetCustomKey("PAYMENT_MIN_AMOUNT_INVALID"),
			),

			validator.Must(payload.Payment.MaxAmount == "" || utils.BiggerThanZero(payload.Payment.MaxAmount)).OnError(
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
		validator.When(payload.Order.Total != "").Then(
			validator.Must(utils.BiggerThanOrEqualZero(payload.Order.Total)).OnError(
				validator.SetField("order_total", nil),
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
		validator.When(payload.Order.Merchant.Image != "").Then(validator.StrIsRequestURI(&payload.Order.Merchant.Image).OnError(
			validator.SetField("order_merchant_image", nil),
		)),
		validator.Slice(payload.Order.Items).ForEach(func(elem InstructionItem, index int, vld validator.ItemValidator) {
			vld.Validate(
				validator.When(elem.Description != "").Then(
					validator.StrLen(&elem.Description, 3, 100).OnError(
						validator.SetField(fmt.Sprintf("order_item_[%d]_description", index), nil),
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
			)
		}),
	)

	if len(errs) > 0 {
		return false, errs[0]
	}

	return true, nil
}
