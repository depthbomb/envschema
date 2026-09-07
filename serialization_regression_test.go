package envschema

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func TestWhitespacePoliciesSurviveSchemaJSON(t *testing.T) {
	for _, rule := range []Rule{List(String()).PreserveWhitespace(), Map(String(), String()).PreserveWhitespace(), List(List(String()).SeparatedBy(";").PreserveWhitespace()).PreserveWhitespace()} {
		schema := Must(Var("VALUE", rule))
		encoded, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		decoded := MustSchemaJSON(string(encoded))
		if !reflect.DeepEqual(schema.Variables, decoded.Variables) {
			t.Fatalf("rule changed after round trip: %s", encoded)
		}
	}
	schema := MustSchemaJSON(`{"variables":[{"name":"VALUE","rule":{"kind":"list","item":{"kind":"string"}}}]}`)
	if !schema.Variables[0].Rule.ListTrim {
		t.Error("omitted listTrim should retain the default true value")
	}
}

func TestNumericDefaultsSurviveSchemaJSON(t *testing.T) {
	for _, rule := range []Rule{
		Uint().DefaultTo(uint64(math.MaxUint64)),
		Int().DefaultTo(int64(math.MaxInt64)),
		Float().DefaultTo(1.5),
		Bytes().DefaultTo(int64(math.MaxInt64)),
		Duration().DefaultTo(int64(1000)),
		BigInt().DefaultTo(int64(math.MaxInt64)),
		Int().Base(16).DefaultTo(int64(255)),
		Uint().Base(16).DefaultTo(uint64(255)),
		BigInt().Base(16).DefaultTo(int64(255)),
		Array(Uint()).DefaultTo([]uint64{9007199254740993, math.MaxUint64}),
		Map(String(), Uint()).DefaultTo(map[string]uint64{
			"limit": math.MaxUint64,
		}),
	} {
		schema := Must(Var("VALUE", rule))
		encoded, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		decoded := MustSchemaJSON(string(encoded))
		lookup := func(string) (string, bool) {
			return "", false
		}
		before, beforeErr := LoadFrom(schema, lookup)
		after, afterErr := LoadFrom(decoded, lookup)
		if beforeErr != nil || afterErr != nil || !reflect.DeepEqual(before, after) {
			t.Errorf("%s round trip: %v (%v) -> %v (%v)", rule.Kind, before, beforeErr, after, afterErr)
		}
	}
}
