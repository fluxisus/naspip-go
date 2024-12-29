package main

import (
	"payments-standard-protocol/paseto"
	"payments-standard-protocol/utils"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var keys = map[string]string{
	"publicKey": "k4.public.sGVse4eAyt6ycfmkKl3Az7RxB34nklDPgKbNLvxVwlk",
	"secretKey": "k4.secret.y4-gze54dwfLR0eyxiJL2mRicZr6SX2-xIn6kgo999iwZWx7h4DK3rJx-aQqXcDPtHEHfieSUM-Aps0u_FXCWQ",
}

// Should create payment instruction token with valid payload: is_open: true
func TestCreateOpenPayment(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:        "payment-id",
			Network:   "TRON",
			Address:   "crypto-address",
			Coin:      "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:    true,
			MinAmount: "1",
			MaxAmount: "100",
		},
	}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreatePaymentInstruction(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestCreateOpenPayment FAIL --> %v, %v", err, qrToken)
	}

	assert.Equal(len(qrToken) > 0, true)
	assert.Equal(strings.HasPrefix(qrToken, "qr-crypto."), true)
}

// "Should create payment instruction token with valid payload: is_open: false"
func TestCreateClosePayment(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:      "payment-id",
			Network: "TRON",
			Address: "crypto-address",
			Coin:    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:  false,
			Amount:  "100",
		},
	}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreatePaymentInstruction(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestCreateClosePayment FAIL --> %v, %v", err, qrToken)
	}

	assert.Equal(len(qrToken) > 0, true)
	assert.Equal(strings.HasPrefix(qrToken, "qr-crypto."), true)
}

// Should create url payload token
func TestCreateUrlPayment(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = UrlPayload{Url: "https://www.my-ecommerce.com/checkout?id=lasdh-asdlsa-ads"}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreateUrlPayload(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestCreateClosePayment FAIL --> %v, %v", err, qrToken)
	}

	assert.Equal(len(qrToken) > 0, true)
	assert.Equal(strings.HasPrefix(qrToken, "qr-crypto."), true)
}

// Should read payment instruction token
func TestReadPaymentInstruction(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:      "payment-id",
			Network: "TRON",
			Address: "crypto-address",
			Coin:    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:  false,
			Amount:  "100",
		},
	}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
		Assertion: []byte(keys["publicKey"]),
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreatePaymentInstruction(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestReadPaymentInstruction FAIL --> %v, %v", err, qrToken)
	}

	var readOptions = QrCriptoReadOptions{KeyId: "key-id-one", KeyIssuer: "payment-processor.com",
		VerifyOptions: paseto.PasetoVerifyOptions{Issuer: "qrCrypto.com"}}

	data, errRead := builder.Read(qrToken, keys["publicKey"], readOptions)

	if errRead != nil {
		t.Errorf("TestReadPaymentInstruction FAIL --> %v", errRead)
	}

	assert.Equal("v4", data.Version)
	assert.Equal("public", data.Purpose)
	assert.Equal("qrCrypto.com", data.Payload.Iss)
}

// Should read payment instruction token with invalid issuer domain and fail
func TestReadPaymentInstructionInvalidIssuer(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:      "payment-id",
			Network: "TRON",
			Address: "crypto-address",
			Coin:    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:  false,
			Amount:  "100",
		},
	}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
		Assertion: []byte(keys["publicKey"]),
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreatePaymentInstruction(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestReadPaymentInstruction FAIL --> %v, %v", err, qrToken)
	}

	var readOptions = QrCriptoReadOptions{KeyId: "key-id-one", KeyIssuer: "payment-processor.com",
		VerifyOptions: paseto.PasetoVerifyOptions{Issuer: "invalid-issuer-domain.com"}}

	_, errRead := builder.Read(qrToken, keys["publicKey"], readOptions)

	assert.EqualError(errRead, "issuer mismatch")
}

// Should read url payload token with invalid keyIssuer and fail
func TestReadUrlPaymentInvaliKeyIssuer(t *testing.T) {
	assert := assert.New(t)

	var handler = paseto.PasetoV4Handler{}

	var builder = PaymentInstructionsBuilder{PasetoHandler: handler}

	var payload = InstructionPayload{
		Payment: PaymentInstruction{
			Id:      "payment-id",
			Network: "TRON",
			Address: "crypto-address",
			Coin:    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			IsOpen:  false,
			Amount:  "100",
		},
	}

	var options = paseto.PasetoSignOptions{
		KeyId:     "key-id-one",
		Issuer:    "qrCrypto.com",
		ExpiresIn: "5m",
		Assertion: []byte(keys["publicKey"]),
	}

	var keyExpiration = time.Now().Add(1e9).Format(utils.RFC3339Mili)

	qrToken, err := builder.CreatePaymentInstruction(payload,
		keys["secretKey"],
		QrCriptoCreateOptions{SignOptions: options, KeyIssuer: "payment-processor.com", KeyExpiration: keyExpiration},
	)

	if err != nil {
		t.Errorf("TestReadPaymentInstruction FAIL --> %v, %v", err, qrToken)
	}

	var readOptions = QrCriptoReadOptions{KeyId: "key-id-one", KeyIssuer: "other-issuer.com"}

	_, errRead := builder.Read(qrToken, keys["publicKey"], readOptions)

	assert.EqualError(errRead, "invalid Key Issuer")
}
