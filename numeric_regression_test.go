package envschema

import (
	"encoding/json"
	"math"
	"testing"
)

func TestIntegerPrecisionAndRange(t *testing.T) {
	tests := []struct {
		rule Rule
		raw  any
		want int64
	}{
		{
			rule: Int(),
			raw:  "9007199254740993",
			want: 9007199254740993,
		},
		{
			rule: Int(),
			raw:  "9223372036854775807",
			want: math.MaxInt64,
		},
		{
			rule: Int(),
			raw:  int64(math.MinInt64),
			want: math.MinInt64,
		},
		{
			rule: Int().Base(16),
			raw:  "7fffffffffffffff",
			want: math.MaxInt64,
		},
		{
			rule: Int(),
			raw:  json.Number("9007199254740993.0"),
			want: 9007199254740993,
		},
		{
			rule: Int(),
			raw:  "9.007199254740993e15",
			want: 9007199254740993,
		},
		{
			rule: Bytes(),
			raw:  "9223372036854775807B",
			want: math.MaxInt64,
		},
		{
			rule: Bytes(),
			raw:  "1.1KB",
			want: 1100,
		},
	}
	for _, test := range tests {
		value, err := parseRule(test.rule, test.raw, "VALUE")
		if err != nil || value != test.want {
			t.Errorf("%s(%v) = %v, %v; want %d", test.rule.Kind, test.raw, value, err, test.want)
		}
	}
	for _, input := range []any{"9223372036854775808", "-9223372036854775809", "9007199254740993.1", float64(0x1p63), math.NaN()} {
		if value, err := parseRule(Int(), input, "VALUE"); err == nil {
			t.Errorf("Int(%v) accepted as %v", input, value)
		}
	}
	for _, input := range []any{"9223372036854775808B", "9223372036854775.808KB", "0.1B", float64(0x1p63)} {
		if value, err := parseRule(Bytes(), input, "VALUE"); err == nil {
			t.Errorf("Bytes(%v) accepted as %v", input, value)
		}
	}
	if _, err := parseRule(Uint(), float64(0x1p64), "VALUE"); err == nil {
		t.Error("Uint accepted 2^64")
	}
}

func TestLargeIntegerConstraintsRemainExact(t *testing.T) {
	for _, rule := range []Rule{Int().MultipleOf(2), Uint().MultipleOf(2), Int().AtMost(9007199254740992), Uint().AtMost(9007199254740992)} {
		if _, err := parseRule(rule, "9007199254740993", "VALUE"); err == nil {
			t.Errorf("%s accepted an integer violating its bound or multiple", rule.Kind)
		}
	}
}

func TestDecimalConstraintsUseDecimalBounds(t *testing.T) {
	for _, rule := range []Rule{Decimal().MultipleOf(0.1), Decimal().Between(0.3, 0.3), Decimal().GreaterThan(0.2).LessThan(0.4)} {
		if _, err := parseRule(rule, "0.3", "VALUE"); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range []Rule{Decimal().MultipleOf(0.1), Decimal().AtMost(0.3), Decimal().AtLeast(0.32)} {
		if _, err := parseRule(rule, "0.31", "VALUE"); err == nil {
			t.Error("decimal constraint accepted 0.31")
		}
	}
	if _, err := parseRule(Decimal().MultipleOf(1e-10), "0.0000000003", "VALUE"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectNonFiniteBounds(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		for _, rule := range []Rule{Decimal().AtLeast(value), Decimal().AtMost(value), Decimal().GreaterThan(value), Decimal().LessThan(value), Decimal().MultipleOf(value)} {
			if _, err := New(Var("VALUE", rule)); err == nil {
				t.Errorf("schema accepted non-finite bound %v", value)
			}
			if _, err := parseRule(rule, "1", "VALUE"); err == nil {
				t.Errorf("parser accepted non-finite bound %v", value)
			}
		}
		for _, rule := range []Rule{Int().AtMost(value), Uint().AtLeast(value), Float().MultipleOf(value), BigInt().LessThan(value)} {
			if _, err := New(Var("VALUE", rule)); err == nil {
				t.Errorf("%s schema accepted non-finite bound", rule.Kind)
			}
		}
	}
}
