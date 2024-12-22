package utils

import "encoding/base64"

const RFC3339Mili = "2006-01-02T15:04:05.999Z07:00"

func EncodeRawURLBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func DecodeRawURLBase64(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func EncodeURLBase64(value []byte) string {
	return base64.URLEncoding.EncodeToString(value)
}

func DecodeURLBase64(value string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(value)
}
