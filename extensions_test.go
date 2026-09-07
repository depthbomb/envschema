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

func TestDecimalShape(t *testing.T) {
	checkRule(t, envschema.Decimal().WithPrecision(4).WithScale(2), []string{"12.34", "12.3400", "0", "1e-2"}, []string{"123.45", "0.001", "1/3"})
}

func TestMapKeyContracts(t *testing.T) {
	checkRule(t, envschema.Map(envschema.String().Trimmed(), envschema.Int()).RequiredKeys("a").AllowedKeys("a", "b").UniqueKeys(), []string{"a=1,b=2"}, []string{"b=2", "a=1,c=2", "a=1,a=2"})
}

func TestCIDRCollections(t *testing.T) {
	checkRule(t, envschema.List(envschema.CIDR()).NonOverlapping().SubnetsOf("10.0.0.0/8"), []string{"10.0.0.0/24,10.1.0.0/24"}, []string{"10.0.0.0/16,10.0.1.0/24", "192.168.0.0/24", "::/0", "10.0.0.0/24,10.0.0.0/24"})
}

func TestExplicitInput(t *testing.T) {
	schema := envschema.Must(envschema.Var("A", envschema.Int().DefaultTo(1).ExplicitInput()).FallbackTo("OLD"))
	if _, err := envschema.LoadFrom(schema, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("default satisfied explicit input")
	}
	values, err := envschema.LoadFrom(schema, func(name string) (string, bool) { return "2", name == "OLD" })
	if err != nil || values["A"] != int64(2) {
		t.Fatalf("%v %v", values, err)
	}
}
