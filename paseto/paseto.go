package paseto

import (
	"bytes"
	"crypto-payments-standard-protocol/utils"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	str2duration "github.com/xhit/go-str2duration/v2"

	pasetoV4 "zntr.io/paseto/v4"
)

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

func GetPrivateKey(key string) ed25519.PrivateKey {
	if bytes.HasPrefix([]byte(key), []byte("k4.secret.")) {
		keyString, _ := utils.DecodeRawURLBase64(key[10:])

		return ed25519.PrivateKey(keyString)
	}

	return ed25519.PrivateKey(key)
}

func GetPublicKey(key string) ed25519.PublicKey {
	if bytes.HasPrefix([]byte(key), []byte("k4.public.")) {
		keyString, _ := utils.DecodeRawURLBase64(key[10:])

		return ed25519.PublicKey(keyString)
	}

	return ed25519.PublicKey(key)
}

func Sign(payload string, privateKey string, options SignOptions) (string, error) {
	var data map[string]interface{}

	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return "", err
	}

	var now = time.Now().UTC()

	data["iss"] = options.Issuer
	data["aud"] = options.Audience
	data["sub"] = options.Subject
	data["jti"] = options.Jti
	data["kid"] = options.Kid
	data["iat"] = now.Format(time.RFC3339)

	if options.ExpiresIn != "" {
		dur, err := str2duration.ParseDuration(options.ExpiresIn)

		if err != nil {
			return "", errors.New("invalid expiresIn format")
		}

		data["exp"] = now.Add(dur).Format(time.RFC3339)
	}

	if options.NotBefore != "" {
		dur, err := str2duration.ParseDuration(options.ExpiresIn)

		if err != nil {
			return "", errors.New("invalid notBefore format")
		}

		data["nbf"] = now.Add(dur).Format(time.RFC3339)
	}

	var key = GetPrivateKey(privateKey)

	dataJson, _ := json.Marshal(data)

	return pasetoV4.Sign(dataJson, key, []byte(options.Footer), []byte(options.Assertion))
}

func Verify(token string, publicKey string) (map[string]any, error) {

	var key = GetPublicKey(publicKey)

	tokenData, err := pasetoV4.Verify(token, key, nil, nil)

	if err != nil {
		return nil, err
	}

	var data map[string]interface{}

	json.Unmarshal(tokenData, &data)

	return data, err
}

func Decode(token string) (map[string]any, error) {

	data := strings.SplitAfter(token, ".")

	length := len(data)
	var version, purpose, payload string = strings.TrimSuffix(data[0], "."), strings.TrimSuffix(data[1], "."), strings.TrimSuffix(data[2], ".")
	var encodedFooter string

	if length == 4 {
		encodedFooter = data[3]
	}

	if length != 3 && length != 4 {
		return nil, errors.New("token is not a PASETO formatted value")
	}

	if version != "v4" {
		return nil, errors.New("unsupported PASETO version")
	}

	if purpose != "local" && purpose != "public" {
		return nil, errors.New("unsupported PASETO purpose")
	}

	footer, errFooter := utils.DecodeRawURLBase64(encodedFooter)

	if errFooter != nil {
		return nil, errors.New("invalid PASETO footer")
	}

	var result = map[string]any{"footer": footer, "version": version, "purpose": purpose}

	if purpose == "local" {
		return result, nil
	}

	raw, errRaw := utils.DecodeRawURLBase64(payload)

	if errRaw != nil {
		return nil, errors.New("token is not a PASETO formatted value")
	}

	var rawPayload = raw[0 : len(raw)-64]

	var parsePayload map[string]interface{}

	if err := json.Unmarshal(rawPayload, &parsePayload); err != nil {
		return nil, err
	}

	result["payload"] = parsePayload

	return result, nil
}
