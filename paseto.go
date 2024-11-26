package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

func GenerateKey(purpose string, format string) (map[string]any, error) {
	if purpose != "public" {
		return nil, errors.New("unsupported v4 purpose")
	}

	if format != "keyobject" && format != "paserk" {
		return nil, errors.New("invalid format")
	}

	result := make(map[string]any)

	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	fmt.Println(publicKey)

	if format == "paserk" {
		result["secretKey"] = "k4.secret." + base64.URLEncoding.EncodeToString(privateKey)
		result["publicKey"] = "k4.public." + base64.URLEncoding.EncodeToString(publicKey)
		return result, nil

	}

	result["secretKey"] = privateKey
	result["publicKey"] = publicKey

	return result, nil
}
