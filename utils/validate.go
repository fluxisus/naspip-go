package utils

import (
	"github.com/shopspring/decimal"
)

// BiggerThanZero checks if a string representation of a decimal number is greater than zero.
// It returns true if the value can be parsed as a decimal and is greater than zero,
// otherwise returns false (including for parsing errors).
// This function is useful for validating positive numeric values in payment instructions.
func BiggerThanZero(value string) bool {
	val, err := decimal.NewFromString(value)

	if err != nil {
		return false
	}

	return val.GreaterThan(decimal.NewFromInt(0))
}

// BiggerThanOrEqualZero checks if a string representation of a decimal number is greater than
// or equal to zero. It returns true if the value can be parsed as a decimal and is zero or positive,
// otherwise returns false (including for parsing errors).
// This function is useful for validating non-negative values in payment instructions.
func BiggerThanOrEqualZero(value string) bool {
	val, err := decimal.NewFromString(value)

	if err != nil {
		return false
	}

	return val.GreaterThanOrEqual(decimal.NewFromInt(0))
}
