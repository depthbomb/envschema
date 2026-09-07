package envschema

import (
	"encoding/json"
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
