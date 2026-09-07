package envschema

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

func validateExactPolicy(rule Rule, name string, values []string) (bool, error) {
	if name == "decimalPrecision" || name == "decimalScale" {
		if rule.Kind != KindDecimal || len(values) != 1 {
			return true, fmt.Errorf("%s requires one integer on a decimal rule", name)
		}
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 0 || name == "decimalPrecision" && n == 0 {
			return true, fmt.Errorf("invalid %s", name)
		}

		return true, nil
	}

	if name != "exactMin" && name != "exactMax" && name != "exactMultiple" {
		return false, nil
	}

	if rule.Kind != KindInt && rule.Kind != KindUInt && rule.Kind != KindBigInt && rule.Kind != KindDecimal && rule.Kind != KindBytes && rule.Kind != KindPort {
		return true, fmt.Errorf("%s requires an exact numeric rule", name)
	}

	if len(values) != 1 {
		return true, fmt.Errorf("%s requires one numeric value", name)
	}
	value, ok := new(big.Rat).SetString(values[0])
	if !ok || name == "exactMultiple" && value.Sign() <= 0 {
		return true, fmt.Errorf("invalid %s", name)
	}
	minimum, minOK := policy(rule, "exactMin")
	maximum, maxOK := policy(rule, "exactMax")
	if minOK && maxOK && len(minimum) == 1 && len(maximum) == 1 {
		min, a := new(big.Rat).SetString(minimum[0])
		max, b := new(big.Rat).SetString(maximum[0])
		if a && b && min.Cmp(max) > 0 {
			return true, fmt.Errorf("exact minimum exceeds maximum")
		}
	}

	return true, nil
}

func checkExactPolicies(rule Rule, value any, path string) error {
	for _, name := range []string{"exactMin", "exactMax", "exactMultiple"} {
		values, configured := policy(rule, name)
		if !configured {
			continue
		}

		if _, err := validateExactPolicy(rule, name, values); err != nil {
			return fmt.Errorf("[%s] %w", path, err)
		}
		bound, _ := new(big.Rat).SetString(values[0])
		number, ok := constraintRat(value)
		if !ok {
			return fmt.Errorf("[%s] expected exact numeric value", path)
		}

		if name == "exactMin" && number.Cmp(bound) < 0 || name == "exactMax" && number.Cmp(bound) > 0 || name == "exactMultiple" && !new(big.Rat).Quo(number, bound).IsInt() {
			return fmt.Errorf("[%s] %s constraint failed", path, name)
		}
	}

	return nil
}

func checkDecimalShape(rule Rule, value any, path string) error {
	precision, hasPrecision := policyInt(rule, "decimalPrecision")
	scale, hasScale := policyInt(rule, "decimalScale")
	if !hasPrecision && !hasScale {
		return nil
	}
	number, ok := value.(big.Rat)
	if !ok {
		return fmt.Errorf("[%s] expected decimal", path)
	}
	denominator := new(big.Int).Set(number.Denom())
	counts := [2]int{}
	for i, factor := range []int64{2, 5} {
		divisor := big.NewInt(factor)
		for new(big.Int).Mod(denominator, divisor).Sign() == 0 {
			denominator.Quo(denominator, divisor)
			counts[i]++
		}
	}
	if denominator.Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("[%s] expected terminating decimal", path)
	}
	fractional := max(counts[0], counts[1])
	if hasScale && fractional > scale {
		return fmt.Errorf("[%s] decimal scale exceeds %d", path, scale)
	}
	text := number.FloatString(fractional)
	digits := strings.TrimLeft(strings.ReplaceAll(strings.TrimPrefix(text, "-"), ".", ""), "0")
	if digits == "" {
		digits = "0"
	}

	if hasPrecision && len(digits) > precision {
		return fmt.Errorf("[%s] decimal precision exceeds %d", path, precision)
	}

	return nil
}

// AtLeastInt64 sets an exact inclusive minimum.
func (rule Rule) AtLeastInt64(value int64) Rule {
	return rule.WithPolicy("exactMin", strconv.FormatInt(value, 10))
}

// AtMostInt64 sets an exact inclusive maximum.
func (rule Rule) AtMostInt64(value int64) Rule {
	return rule.WithPolicy("exactMax", strconv.FormatInt(value, 10))
}

// AtLeastUint64 sets an exact inclusive minimum.
func (rule Rule) AtLeastUint64(value uint64) Rule {
	return rule.WithPolicy("exactMin", strconv.FormatUint(value, 10))
}

// AtMostUint64 sets an exact inclusive maximum.
func (rule Rule) AtMostUint64(value uint64) Rule {
	return rule.WithPolicy("exactMax", strconv.FormatUint(value, 10))
}

// AtLeastDecimal sets an exact inclusive minimum from decimal or rational text.
func (rule Rule) AtLeastDecimal(value string) Rule {
	return rule.WithPolicy("exactMin", value)
}

// AtMostDecimal sets an exact inclusive maximum from decimal or rational text.
func (rule Rule) AtMostDecimal(value string) Rule {
	return rule.WithPolicy("exactMax", value)
}

// MultipleOfDecimal sets an exact positive multiple from decimal or rational text.
func (rule Rule) MultipleOfDecimal(value string) Rule {
	return rule.WithPolicy("exactMultiple", value)
}

// WithPrecision limits the digits in a decimal's shortest exact fixed-point representation.
// Leading and fractional trailing zeros do not count; zero has precision one.
func (rule Rule) WithPrecision(digits int) Rule {
	return rule.WithPolicy("decimalPrecision", strconv.Itoa(digits))
}

// WithScale limits fractional digits after removing trailing zeros.
// Non-terminating rational values fail a precision or scale constraint.
func (rule Rule) WithScale(digits int) Rule {
	return rule.WithPolicy("decimalScale", strconv.Itoa(digits))
}
