package utils

import (
	"github.com/shopspring/decimal"
)

func BiggerThanZero(value string) bool {
	val, err := decimal.NewFromString(value)

	if err != nil {
		return false
	}

	return val.GreaterThan(decimal.NewFromInt(0))
}

func BiggerThanOrEqualZero(value string) bool {
	val, err := decimal.NewFromString(value)

	if err != nil {
		return false
	}

	return val.GreaterThanOrEqual(decimal.NewFromInt(0))
}
