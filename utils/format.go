// Package utils provides utility functions for the NASPIP protocol implementation,
// including encoding/decoding utilities and value validation helpers.
package utils

import (
	"encoding/base64"
	"strconv"
)

// RFC3339Mili is a time format constant that extends RFC3339 with millisecond precision.
// It can be used with time.Format and time.Parse functions for consistent time representation.
const RFC3339Mili = "2006-01-02T15:04:05.999Z07:00"

// EncodeRawURLBase64 encodes a byte slice using base64 URL encoding without padding.
// This is useful for generating URL-safe tokens and identifiers.
func EncodeRawURLBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// DecodeRawURLBase64 decodes a string using base64 URL encoding without padding.
// It returns the decoded bytes or an error if the input is not valid base64.
func DecodeRawURLBase64(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

// EncodeURLBase64 encodes a byte slice using standard base64 URL encoding with padding.
// This provides a URL-safe representation of binary data.
func EncodeURLBase64(value []byte) string {
	return base64.URLEncoding.EncodeToString(value)
}

// DecodeURLBase64 decodes a string using standard base64 URL encoding with padding.
// It returns the decoded bytes or an error if the input is not valid base64.
func DecodeURLBase64(value string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(value)
}

// FormatStringTimestampToUnixMilli formats a time string to a Unix timestamp in milliseconds.
// It parses the time string using RFC3339Mili format and returns the Unix timestamp in milliseconds.
func FormatStringTimestampToUnixMilli(expiresAt string) int64 {
	convertedValue, err := strconv.ParseInt(expiresAt, 10, 64)
	if err != nil {
		return -1
	}
	return convertedValue
}
