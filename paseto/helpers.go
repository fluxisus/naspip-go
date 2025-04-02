package paseto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/fluxisus/naspip-go/v3/encoding/protobuf"
	"github.com/fluxisus/naspip-go/v3/utils"
)

// GenerateKey creates a new Ed25519 key pair for use with PASETO v4 tokens.
//
// Parameters:
//   - purpose: The PASETO purpose ("public" is the only supported value for v4)
//   - format: The output format for the keys ("keyobject" or "paserk")
//
// Returns:
//   - A map containing "secretKey" and "publicKey" entries
//   - An error if the purpose or format is invalid
//
// The "keyobject" format returns raw base64url-encoded keys.
// The "paserk" format returns PASERK-formatted keys (k4.secret/k4.public prefixed).
func GenerateKey(purpose string, format string) (map[string]string, error) {
	if purpose != "public" {
		return nil, errors.New("unsupported v4 purpose")
	}

	if format != "keyobject" && format != "paserk" {
		return nil, errors.New("invalid format")
	}

	result := make(map[string]string)

	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	if format == "paserk" {
		result["secretKey"] = "k4.secret." + utils.EncodeRawURLBase64(privateKey)
		result["publicKey"] = "k4.public." + utils.EncodeRawURLBase64(publicKey)
		return result, nil
	}

	result["secretKey"] = utils.EncodeRawURLBase64(privateKey)
	result["publicKey"] = utils.EncodeRawURLBase64(publicKey)

	return result, nil
}

// GetPrivateKey converts a string representation of an Ed25519 private key
// to the crypto/ed25519.PrivateKey type.
//
// It supports both raw keys and PASERK-formatted keys (k4.secret.* format).
// For PASERK keys, it extracts and decodes the base64url-encoded portion.
func GetPrivateKey(key string) ed25519.PrivateKey {
	if bytes.HasPrefix([]byte(key), []byte("k4.secret.")) {
		keyString, _ := utils.DecodeRawURLBase64(key[10:])

		return ed25519.PrivateKey(keyString)
	}

	return ed25519.PrivateKey(key)
}

// GetPublicKey converts a string representation of an Ed25519 public key
// to the crypto/ed25519.PublicKey type.
//
// It supports both raw keys and PASERK-formatted keys (k4.public.* format).
// For PASERK keys, it extracts and decodes the base64url-encoded portion.
func GetPublicKey(key string) ed25519.PublicKey {
	if bytes.HasPrefix([]byte(key), []byte("k4.public.")) {
		keyString, _ := utils.DecodeRawURLBase64(key[10:])

		return ed25519.PublicKey(keyString)
	}

	return ed25519.PublicKey(key)
}

// DecodeV4 parses a PASETO v4 token string without verifying its signature.
// This is useful for extracting token information before verification.
//
// Parameters:
//   - token: A PASETO v4 token string
//
// Returns:
//   - A PasetoCompleteResult containing the parsed token parts
//   - An error if the token is not a valid PASETO v4 format
//
// Note: This function does not verify the token's signature,
// so the extracted payload should not be trusted without verification.
func DecodeV4(token string) (PasetoCompleteResult, error) {

	data := strings.Split(token, ".")

	length := len(data)
	var version, purpose, payload string = data[0], data[1], data[2]
	var encodedFooter string

	if length == 4 {
		encodedFooter = data[3]
	}

	if length != 3 && length != 4 {
		return PasetoCompleteResult{}, errors.New("token is not a PASETO formatted value")
	}

	if version != "v4" {
		return PasetoCompleteResult{}, errors.New("unsupported PASETO version")
	}

	if purpose != "local" && purpose != "public" {
		return PasetoCompleteResult{}, errors.New("unsupported PASETO purpose")
	}

	footer, errFooter := utils.DecodeRawURLBase64(encodedFooter)

	if errFooter != nil {
		return PasetoCompleteResult{}, errors.New("invalid PASETO footer")
	}

	var result = PasetoCompleteResult{Footer: footer, Version: version, Purpose: purpose}

	if purpose == "local" {
		return result, nil
	}

	raw, errRaw := utils.DecodeRawURLBase64(payload)

	if errRaw != nil {
		return PasetoCompleteResult{}, errors.New("token is not a PASETO formatted value")
	}

	var rawPayload = raw[0 : len(raw)-64]

	var parseProto protobuf.PasetoTokenData

	err := protobuf.DecodeProto(rawPayload, &parseProto)

	if err != nil {
		return PasetoCompleteResult{}, err
	}

	var parsePayload PasetoTokenData

	if err = protobuf.ConvertProtoToGo(&parseProto, &parsePayload); err != nil {
		return PasetoCompleteResult{}, err
	}

	result.Payload = parsePayload

	return result, nil
}
