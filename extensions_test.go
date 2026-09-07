package envschema_test

import (
	"encoding/json"
	"github.com/depthbomb/envschema"
	"testing"
)

func checkRule(t *testing.T, rule envschema.Rule, valid, invalid []string) {
	t.Helper()
	schema, err := envschema.New(envschema.Var("VALUE", rule))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []envschema.Schema{schema, envschema.MustSchemaJSON(string(encoded))} {
		for _, raw := range valid {
			if _, err := envschema.LoadFrom(candidate, func(string) (string, bool) { return raw, true }); err != nil {
				t.Errorf("%q: %v", raw, err)
			}
		}
		for _, raw := range invalid {
			if _, err := envschema.LoadFrom(candidate, func(string) (string, bool) { return raw, true }); err == nil {
				t.Errorf("accepted %q", raw)
			}
		}
	}
}

func TestExactBounds(t *testing.T) {
	checkRule(t, envschema.Uint().AtMostUint64(18446744073709551614), []string{"18446744073709551614"}, []string{"18446744073709551615"})
	checkRule(t, envschema.Decimal().MultipleOfDecimal("0.0000000000000000003"), []string{"0.0000000000000000009"}, []string{"0.000000000000000001"})
	checkRule(t, envschema.BigInt().AtLeastDecimal("999999999999999999999"), []string{"1000000000000000000000"}, []string{"999999999999999999998"})
	if _, err := envschema.New(envschema.Var("X", envschema.Int().AtLeastDecimal("2").AtMostDecimal("1"))); err == nil {
		t.Fatal("accepted inverted bounds")
	}
}
