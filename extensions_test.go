package envschema_test

import (
	"encoding/json"
	"errors"
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

func TestSensitiveRules(t *testing.T) {
	checkRule(t, envschema.URL().WithSchemes("postgres").Sensitive(), []string{"postgres://user:password@host/db"}, []string{"https://host"})
	schema := envschema.Must(envschema.Var("TOKEN", envschema.Base64().ExactlyDecodedBytes(3).Sensitive()))
	values, err := envschema.LoadFrom(schema, func(string) (string, bool) { return "YWJj", true })
	if err != nil {
		t.Fatal(err)
	}
	value, err := envschema.ValueAs[envschema.Protected[string]](values, "TOKEN")
	if err != nil || value.Release() != "YWJj" {
		t.Fatalf("%v %v", value, err)
	}
	encoded, _ := json.Marshal(value)
	if string(encoded) != "\"[redacted]\"" {
		t.Fatalf("%s", encoded)
	}
}

func TestSensitiveCollectionUniqueness(t *testing.T) {
	checkRule(t, envschema.List(envschema.String().Sensitive()).UniqueItems(), []string{"a,b"}, []string{"a,a"})
}

func TestObjects(t *testing.T) {
	checkRule(t, envschema.Object(envschema.Field("port", envschema.Port()), envschema.Field("timeout", envschema.Duration().DefaultTo("2s")), envschema.Field("token", envschema.String().Sensitive().Optional())), []string{`{"port":8080}`}, []string{`{"port":70000}`, `{"port":8080,"extra":1}`, `{"port":1,"port":2}`, "null"})
}

func TestQueryRules(t *testing.T) {
	checkRule(t, envschema.URL().QueryParameter("timeout", envschema.Int().Between(1, 10)).QueryParameter("mode", envschema.OneOf("fast", "safe").Optional()), []string{"https://host?timeout=2&mode=safe"}, []string{"https://host", "https://host?timeout=11", "https://host?timeout=2&timeout=3", "https://host?timeout=2&mode=no"})
	checkRule(t, envschema.URI().AllowRelativeReference().QueryParameter("port", envschema.Array(envschema.Port())), []string{"/?port=80&port=443"}, []string{"/?port=99999"})
}

func TestConditionalValidation(t *testing.T) {
	schema := envschema.Must(envschema.Var("MODE", envschema.OneOf("local", "production").CaseInsensitive()), envschema.Var("URL", envschema.URL())).ValidateWhen("MODE", "production", "URL", envschema.URL().HTTPSOnly())
	encoded, _ := json.Marshal(schema)
	for _, candidate := range []envschema.Schema{schema, envschema.MustSchemaJSON(string(encoded))} {
		for _, mode := range []string{"local", "PRODUCTION"} {
			_, err := envschema.LoadFrom(candidate, func(name string) (string, bool) {
				if name == "MODE" {
					return mode, true
				}
				return "http://host", true
			})
			if (err != nil) != (mode == "PRODUCTION") {
				t.Fatalf("%s: %v", mode, err)
			}
		}
	}
}

func TestCollectionRelationships(t *testing.T) {
	schema := envschema.Must(envschema.Var("DEFAULT", envschema.String()), envschema.Var("ENABLED", envschema.List(envschema.String())), envschema.Var("BLOCKED", envschema.Map(envschema.String(), envschema.Int()))).MemberOf("DEFAULT", "ENABLED").DisjointWith("ENABLED", "BLOCKED")
	for _, enabled := range []string{"a,b", "b,c", "a,c"} {
		values := map[string]string{"DEFAULT": "a", "ENABLED": enabled, "BLOCKED": "c=1"}
		_, err := envschema.LoadFrom(schema, func(name string) (string, bool) { value, ok := values[name]; return value, ok })
		if (err == nil) != (enabled == "a,b") {
			t.Fatalf("%s: %v", enabled, err)
		}
	}
}

func TestGroups(t *testing.T) {
	fragment := envschema.Must(envschema.Var("MIN", envschema.Int()), envschema.Var("MAX", envschema.Int())).LessThanVariable("MIN", "MAX")
	schema := envschema.Must().WithGroup("Primary", "PRIMARY_", fragment).WithGroup("Replica", "REPLICA_", fragment)
	data, _ := json.Marshal(schema)
	schema = envschema.MustSchemaJSON(string(data))
	if len(fragment.Variables) != 2 || fragment.Variables[0].Name != "MIN" {
		t.Fatal("fragment mutated")
	}
	_, err := envschema.LoadFrom(schema, func(name string) (string, bool) {
		if name == "PRIMARY_MAX" || name == "REPLICA_MAX" {
			return "2", true
		}
		return "1", true
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregatedErrors(t *testing.T) {
	schema := envschema.Must(envschema.Var("PORT", envschema.Port()), envschema.Var("BACKENDS", envschema.Array(envschema.Object(envschema.Field("timeout", envschema.Duration())))))
	_, err := envschema.LoadFrom(schema, func(name string) (string, bool) {
		if name == "PORT" {
			return "bad", true
		}
		return `[{"timeout":"bad"},{"timeout":"also bad"}]`, true
	})
	var failures *envschema.ValidationErrors
	if !errors.As(err, &failures) || len(failures.Issues) != 3 || failures.Issues[2].Path != "BACKENDS[1].timeout" {
		t.Fatalf("%#v %v", failures, err)
	}
}

func TestSensitiveComposition(t *testing.T) {
	checkRule(t, envschema.List(envschema.String().Sensitive()).CaseInsensitiveUniqueItems().RejectEmptyItems().Sorted(), []string{"a,b"}, []string{"a,A", "b,a", "a,"})
	checkRule(t, envschema.Array(envschema.Object(envschema.Field("token", envschema.String().Sensitive()))).UniqueItems(), []string{`[{"token":"a"},{"token":"b"}]`}, []string{`[{"token":"a"},{"token":"a"}]`})
}
