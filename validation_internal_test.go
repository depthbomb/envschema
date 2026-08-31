package envschema

import (
	"encoding/json"
	"testing"
)

func testPointer[T any](value T) *T {
	return &value
}

func TestValidateRuleErrorMatrix(t *testing.T) {
	t.Parallel()

	invalid := []Rule{
		{Kind: "unknown"},
		{Kind: KindInt, Min: testPointer(2.0), Max: testPointer(1.0)},
		{Kind: KindInt, ExclusiveMin: testPointer(2.0), ExclusiveMax: testPointer(2.0)},
		{Kind: KindInt, Multiple: testPointer(0.0)},
		{Kind: KindList, Item: testPointer(String()), Separator: ",", ListTrim: true, MinItems: testPointer(-1)},
		{Kind: KindList, Item: testPointer(String()), Separator: ",", ListTrim: true, MinItems: testPointer(2), MaxItems: testPointer(1)},
		{Kind: KindDuration, MinDuration: "invalid"},
		{Kind: KindDuration, MaxDuration: "invalid"},
		{Kind: KindDuration, MinDuration: "2s", MaxDuration: "1s"},
		{Kind: KindString, Required: true, ListTrim: true, MinLength: testPointer(2), MaxLength: testPointer(1)},
		{Kind: KindString, Required: true, ListTrim: true, MinLength: testPointer(-1)},
		{Kind: KindDate, MinDate: "invalid"},
		{Kind: KindDate, MaxDate: "invalid"},
		{Kind: KindDate, MinDate: "2026-02-01", MaxDate: "2026-01-01"},
		{Kind: KindString, Pattern: "["},
		{Kind: KindEnum},
		{Kind: KindEnum, Choices: []string{"A", "a"}, EnumCaseInsensitive: true},
		{Kind: KindEnum, Choices: []string{"a"}, Aliases: map[string]string{"x": "missing"}},
		{Kind: KindList},
		{Kind: KindList, Item: testPointer(CustomNamed("example.com/custom", "Value")), Separator: ",", ListTrim: true},
		{Kind: KindMap},
		{Kind: KindMap, Key: testPointer(Int()), Item: testPointer(Int()), Separator: ",", KeyValueSeparator: "="},
		{Kind: KindMap, Key: testPointer(String()), Item: testPointer(Int()), Separator: ",", KeyValueSeparator: ","},
		{Kind: KindMap, Key: testPointer(String()), Item: testPointer(CustomNamed("example.com/custom", "Value")), Separator: ",", KeyValueSeparator: "="},
		{Kind: KindString, Lowercase: true, Uppercase: true},
		{Kind: KindURL, Schemes: []string{"HTTPS"}},
		{Kind: KindHash, Hash: "unknown"},
		{Kind: KindPath, PathKind: "unknown"},
		{Kind: KindBase64, Padding: "unknown"},
		{Kind: KindIP, IPVersion: "unknown"},
		{Kind: KindUUID, UUID: "9"},
		{Kind: KindString, MinItems: testPointer(1)},
		{Kind: KindString, Multiple: testPointer(1.0)},
		{Kind: KindString, MinDuration: "1s"},
		{Kind: KindString, Schemes: []string{"https"}},
		{Kind: KindInt, Prefix: "x"},
		{Kind: KindInt, Lowercase: true},
		{Kind: KindString, EnumCaseInsensitive: true},
		{Kind: KindString, Absolute: testPointer(true)},
		{Kind: KindString, UTC: true},
		{Kind: KindString, StrictBoolean: true},
		{Kind: KindInt, RuneLength: true},
		{Kind: KindInt, Trim: true},
		{Kind: KindString, Min: testPointer(1.0)},
		{Kind: KindString, MinDate: "2026-01-01"},
		{Kind: KindString, Separator: ","},
		{Kind: KindString, PathKind: PathFile},
		{Kind: KindString, URLSafe: true},
		{Kind: KindString, IPVersion: IPv4},
		{Kind: KindString, UUID: UUIDv4},
		{Kind: KindCustom},
		String().WithPolicy("unknown"),
		List(Int()).CaseInsensitiveUniqueItems(),
		List(JSON()).Sorted(),
		String().Containing(),
		String().Containing(""),
		Int().Base(1),
		Endpoint().PortBetween(10, 1),
		Endpoint().PortBetween(1, 70000),
		IPAddress().WithPolicy(policyIPClass, "unknown"),
		Endpoint().WithPolicy(policyEndpointHostType, "unknown"),
		JSON().WithPolicy(policyJSONKind, "unknown"),
		Path().WithPolicy(policySymlink, "unknown"),
		PEM().WithPolicy(policyPEMHeaders, "required"),
		Certificate().WithPolicy(policyCertificateUsage, "unknown"),
		PrivateKey().WithPolicy(policyPrivateKeyAlgorithms, "unknown"),
		UUID().Versions(UUIDVersion("9")),
		Timestamp().Precision(0),
		Certificate().WithPolicy(policyValidAt, "invalid"),
		SemVer().AtLeastVersion("invalid"),
		CIDR().ContainingAddresses("invalid"),
		CIDR().ContainedBy("invalid"),
		Boolean().TrueValues("yes").FalseValues("YES"),
		Host().AtLeastLabels(3).AtMostLabels(2),
		Base64().AtLeastDecodedBytes(3).AtMostDecodedBytes(2),
		SemVer().AtLeastVersion("2.0.0").LessThanVersion("1.0.0"),
		Path().MatchingGlob("["),
	}

	for index, rule := range invalid {
		if err := validateRule(rule, "VALUE"); err == nil {
			t.Fatalf("invalid rule %d (%s) was accepted: %#v", index, rule.Kind, rule)
		}
	}
}

func TestSchemaAndJSONValidationErrors(t *testing.T) {
	t.Parallel()

	schemas := []Schema{
		{Variables: []Variable{{Name: "bad-name", Rule: String()}}},
		{Variables: []Variable{Var("A", String()), Var("A", String())}},
		{Variables: []Variable{Var("A", String()).FallbackTo("bad-name")}},
		{Variables: []Variable{Var("A", String()).FallbackTo("A")}},
		{Variables: []Variable{Var("A", String())}, Constraints: []Constraint{{Kind: "unknown", Names: []string{"A", "B"}}}},
		{Variables: []Variable{Var("A", String())}, Constraints: []Constraint{{Kind: ConstraintEqualValues, Names: []string{"A"}}}},
		{Variables: []Variable{Var("A", String()), Var("B", String()), Var("C", String())}, Constraints: []Constraint{{Kind: ConstraintEqualValues, Names: []string{"A", "B", "C"}}}},
		{Variables: []Variable{Var("A", String()), Var("B", String())}, Constraints: []Constraint{{Kind: ConstraintEqualValues, Names: []string{"A", "missing"}}}},
		{Variables: []Variable{Var("A", String()), Var("B", String())}, Constraints: []Constraint{{Kind: ConstraintEqualValues, Names: []string{"A", "A"}}}},
		{Variables: []Variable{Var("A", String()), Var("B", String())}, Constraints: []Constraint{{Kind: ConstraintTLSKeyPair, Names: []string{"A", "B"}}}},
	}
	for index, schema := range schemas {
		if err := schema.Validate(); err == nil {
			t.Fatalf("invalid schema %d was accepted", index)
		}
	}

	inputs := []string{
		`{`,
		`{"kind":"string","unknown":true}`,
		`{"type":1}`,
	}
	for _, input := range inputs {
		var rule Rule
		if err := json.Unmarshal([]byte(input), &rule); err == nil {
			t.Fatalf("json.Unmarshal(%q) error = nil", input)
		}
	}

	var legacy Rule
	if err := json.Unmarshal([]byte(`{"type":"string","default":"x"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Kind != KindString || !legacy.HasDefault {
		t.Fatalf("legacy rule = %#v", legacy)
	}
}
