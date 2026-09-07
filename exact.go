package envschema

import (
	"fmt"
	"math/big"
	"strconv"
)

func validateExactPolicy(rule Rule, name string, values []string) (bool, error) {
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
