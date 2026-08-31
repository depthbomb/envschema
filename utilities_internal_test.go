package envschema

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPublicRuntimeWrappers(t *testing.T) {
	t.Setenv("ENVSCHEMA_TEST_LOOKUP", "value")

	if value, exists := LookupEnv("ENVSCHEMA_TEST_LOOKUP"); !exists || value != "value" {
		t.Fatalf("LookupEnv() = %q, %v", value, exists)
	}
	if value, exists := lookupOS("ENVSCHEMA_TEST_LOOKUP"); !exists || value != "value" {
		t.Fatalf("lookupOS() = %q, %v", value, exists)
	}
	if _, err := LookupEnvFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := parseEnvFile([]byte("invalid")); err == nil {
		t.Fatal("parseEnvFile() accepted malformed input")
	}

	value, present, err := Read[int64](Int(), "VALUE", func(string) (string, bool) { return "4", true })
	if err != nil || !present || value != 4 {
		t.Fatalf("Read() = %v, %v, %v", value, present, err)
	}
	value, present, err = ReadWithFallbacks[int64](Int(), "VALUE", []string{"OLD"}, func(name string) (string, bool) {
		return "5", name == "OLD"
	})
	if err != nil || !present || value != 5 {
		t.Fatalf("ReadWithFallbacks() = %v, %v, %v", value, present, err)
	}
	if _, _, err := Read[string](Int(), "VALUE", func(string) (string, bool) { return "4", true }); err == nil {
		t.Fatal("Read[string](Int()) error = nil")
	}

	decoded, err := DecodeJSON[map[string]int](json.RawMessage(`{"a":1}`))
	if err != nil || decoded["a"] != 1 {
		t.Fatalf("DecodeJSON() = %v, %v", decoded, err)
	}
	if _, err := DecodeJSON[any](json.RawMessage(`{`)); err == nil {
		t.Fatal("DecodeJSON(invalid) error = nil")
	}

	secret := SecretValue{value: "hidden"}
	if secret.GoString() != redactedSecret {
		t.Fatal("GoString() did not redact")
	}
	if text, err := secret.MarshalText(); err != nil || string(text) != redactedSecret {
		t.Fatalf("MarshalText() = %q, %v", text, err)
	}

	schema := Must(Var("OPTIONAL", String().Optional()))
	if err := ValidateConstraints(schema, func(string) (string, bool) { return "", false }); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(schema); err != nil {
		t.Fatal(err)
	}
}

func TestParsingAndComparisonUtilities(t *testing.T) {
	t.Parallel()

	uintInputs := []any{uint64(1), uint(1), int(1), int64(1), float64(1), json.Number("1"), "1"}
	for _, input := range uintInputs {
		if _, err := parseUint(Uint(), input, "VALUE"); err != nil {
			t.Fatalf("parseUint(%T) error = %v", input, err)
		}
	}
	for _, input := range []any{int(-1), int64(-1), float64(-1), json.Number("x"), struct{}{}} {
		if _, err := parseUint(Uint(), input, "VALUE"); err == nil {
			t.Fatalf("parseUint(%T) error = nil", input)
		}
	}

	itemRules := []struct {
		rule Rule
		raw  any
	}{
		{String(), "x"}, {Number(), "1"}, {Int(), "1"}, {Uint(), "1"}, {Boolean(), "true"},
		{Duration(), "1s"}, {Date(), "2026-08-31"}, {CIDR(), "10.0.0.0/8"},
		{Regexp(), "x"}, {PEM(), "-----BEGIN X-----\neA==\n-----END X-----"},
		{JSON(), `{"a":1}`}, {Secret(), "x"}, {MACAddress(), "02:00:5e:10:00:00"},
		{BigInt(), "1"}, {Decimal(), "1.5"}, {FileMode(), "0755"},
		{CustomNamed("example.com/custom", "Value"), "x"},
	}
	for _, test := range itemRules {
		if _, err := parseItems(test.rule, []any{test.raw}, "VALUE", false); err != nil {
			t.Fatalf("parseItems(%s) error = %v", test.rule.Kind, err)
		}
	}
	if _, err := parseItems(String(), []any{"x", "x"}, "VALUE", true); err == nil {
		t.Fatal("parseItems() accepted duplicate comparable values")
	}
	if _, err := parseItems(PEM(), []any{"-----BEGIN X-----\neA==\n-----END X-----", "-----BEGIN X-----\neA==\n-----END X-----"}, "VALUE", true); err == nil {
		t.Fatal("parseItems() accepted duplicate non-comparable values")
	}
	custom := CustomNamed("example.com/custom", "Value")
	if _, err := parseUntypedItems(custom, []any{"a", "b"}, "VALUE", true); err != nil {
		t.Fatal(err)
	}
	if _, err := parseUntypedItems(custom, []any{"a", "a"}, "VALUE", true); err == nil {
		t.Fatal("parseUntypedItems() accepted duplicate values")
	}
	if _, err := parseUntypedItems(custom, []any{1}, "VALUE", false); err == nil {
		t.Fatal("parseUntypedItems() accepted a non-string custom value")
	}

	comparisons := [][2]any{
		{"a", "b"}, {int(1), int(2)}, {int8(1), int8(2)}, {uint(1), uint(2)}, {uint8(1), uint8(2)},
		{int64(1), int64(2)}, {uint64(1), uint64(2)}, {time.Second, 2 * time.Second},
		{*big.NewInt(1), *big.NewInt(2)}, {*big.NewRat(1, 2), *big.NewRat(2, 3)},
		{time.Unix(1, 0), time.Unix(2, 0)},
	}
	for _, values := range comparisons {
		if comparison, comparable := compareOrderedValues(values[0], values[1]); !comparable || comparison >= 0 {
			t.Fatalf("compareOrderedValues(%T) = %d, %v", values[0], comparison, comparable)
		}
	}
	if _, comparable := compareOrderedValues(struct{}{}, struct{}{}); comparable {
		t.Fatal("compareOrderedValues() considered structs ordered")
	}

	for _, value := range []any{int64(1), uint64(1), float64(1), time.Second, *big.NewInt(1), *big.NewRat(1, 2)} {
		if _, ok := constraintRat(value); !ok {
			t.Fatalf("constraintRat(%T) failed", value)
		}
	}
	if _, ok := constraintRat("1"); ok {
		t.Fatal("constraintRat(string) succeeded")
	}
	for _, version := range []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0+build"} {
		parsed, valid := parseSemanticVersion(version)
		if !valid {
			t.Fatalf("invalid semantic-version fixture %q", version)
		}
		_ = compareSemanticVersions(parsed, semanticVersionBound("2.0.0"))
	}
	versionPairs := [][2]string{
		{"1.0.0-alpha", "1.0.0-alpha.1"},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-beta.2", "1.0.0-beta.11"},
		{"1.0.0-beta", "1.0.0"},
		{"1.0.0+one", "1.0.0+two"},
	}
	for _, pair := range versionPairs {
		left, _ := parseSemanticVersion(pair[0])
		right, _ := parseSemanticVersion(pair[1])
		_ = compareSemanticVersions(left, right)
	}
	_ = semanticVersionBound("1.2.3")
	_ = semanticVersionBound("1.2.3")

	_ = netip.MustParsePrefix("10.0.0.0/8")
	_ = fs.FileMode(0o755)
}

func TestAssignmentUtilities(t *testing.T) {
	t.Parallel()

	var stringsValue []string
	if err := assignValue(reflect.ValueOf(&stringsValue).Elem(), reflect.ValueOf([]any{"a", "b"})); err != nil {
		t.Fatal(err)
	}
	var mapValue map[string]int64
	if err := assignValue(reflect.ValueOf(&mapValue).Elem(), reflect.ValueOf(map[string]any{"a": int64(1)})); err != nil {
		t.Fatal(err)
	}
	var anyValue any
	if err := assignValue(reflect.ValueOf(&anyValue).Elem(), reflect.ValueOf("x")); err != nil {
		t.Fatal(err)
	}
	var integer int
	for _, source := range []reflect.Value{reflect.Value{}, reflect.ValueOf((*any)(nil)).Elem(), reflect.ValueOf("x")} {
		if err := assignValue(reflect.ValueOf(&integer).Elem(), source); err == nil {
			t.Fatalf("assignValue(%v) error = nil", source)
		}
	}

	values := Values{"VALUE": "text"}
	if _, err := ValueAs[int](values, "VALUE"); err == nil {
		t.Fatal("ValueAs[int]() error = nil")
	}
	if _, err := ValueAs[string](values, "MISSING"); err == nil {
		t.Fatal("ValueAs(missing) error = nil")
	}

	_ = fmt.Sprint(stringsValue, mapValue, anyValue)
	_ = os.PathSeparator
}

func TestPathURLJSONAndKeyBranches(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	file := filepath.Join(directory, "config.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		rule Rule
		raw  any
	}{
		{Path().LocalOnly(), filepath.Join("..", "outside")},
		{Path().CleanOnly(), "a" + string(filepath.Separator) + ".." + string(filepath.Separator) + "b"},
		{Path().WithExtensions(".json"), file},
		{Path().MatchingGlob("*.json"), file},
		{Path().Within(directory), filepath.Join(directory, "..", "outside")},
		{Path().RelativeOnly(), file},
		{UnixSocket().Existing(), file},
		{JSON().ArrayOnly(), `{"a":1}`},
		{JSON().WithoutNull(), `null`},
		{JSON().RequiredKeys("missing"), `{"a":1}`},
		{JSON().AllowedKeys("a"), `{"b":1}`},
		{JSON().AtMostDepth(1), `{"a":{"b":1}}`},
		{CIDR().ContainingAddresses("11.0.0.1"), "10.0.0.0/8"},
		{CIDR().ContainedBy("10.0.0.0/16"), "10.0.0.0/8"},
		{Endpoint().ValidateHostname(), "bad_host:80"},
		{Host().RequireTrailingDot(), "example.com"},
		{Host().AtMostLabels(1), "example.com"},
	}
	for _, test := range tests {
		if _, err := parseRule(test.rule, test.raw, "VALUE"); err == nil {
			t.Fatalf("parseRule(%s, %v) error = nil", test.rule.Kind, test.raw)
		}
	}
	if _, err := parseURL("https://example.com", "VALUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseUnixSocket(UnixSocket(), "socket.sock", "VALUE"); err != nil {
		t.Fatal(err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{ecdsaKey, ed25519Key} {
		if keyAlgorithm(key) == "" {
			t.Fatalf("keyAlgorithm(%T) is empty", key)
		}
	}
	if keyAlgorithm(struct{}{}) != "struct {}" {
		t.Fatal("keyAlgorithm(struct) did not identify the concrete type")
	}
}

func TestConstraintBranches(t *testing.T) {
	t.Parallel()

	base := Must(Var("A", Int().Optional()), Var("B", Int().Optional()), Var("C", Int().Optional()))
	tests := []struct {
		schema Schema
		values map[string]string
	}{
		{base.AtLeastOneOf("A", "B"), nil},
		{base.MutuallyExclusive("A", "B"), map[string]string{"A": "1", "B": "2"}},
		{base.DifferentValues("A", "B"), map[string]string{"A": "1", "B": "1"}},
		{base.EqualValues("A", "B"), map[string]string{"A": "1", "B": "2"}},
		{base.RequiredIfPresent("A", "B"), map[string]string{"A": "1"}},
		{base.RequiredUnless("A", "1", "B"), map[string]string{"A": "2"}},
		{base.ForbiddenWhen("A", "1", "B"), map[string]string{"A": "1", "B": "2"}},
	}
	for _, test := range tests {
		if err := ValidateConstraints(test.schema, func(name string) (string, bool) {
			value, exists := test.values[name]

			return value, exists
		}); err == nil {
			t.Fatalf("ValidateConstraints(%v) error = nil", test.values)
		}
	}
}

func TestPrimitiveParserBranches(t *testing.T) {
	t.Parallel()
	if value, err := parseBoolean(Boolean(), true, "VALUE"); err != nil || value != true {
		t.Fatalf("parseBoolean(bool) = %v, %v", value, err)
	}
	if _, err := parseArray(Array(Int()), []any{"1", "2"}, "VALUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseArray(Array(Int()), map[string]any{}, "VALUE"); err == nil {
		t.Fatal("parseArray() accepted an object")
	}
	if _, err := parseDate(Date(), time.Now(), "VALUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseDate(Date(), 1, "VALUE"); err == nil {
		t.Fatal("parseDate() accepted a numeric input")
	}

	for _, input := range []any{time.Second, float64(1000), int64(1000), "1000", "1 second"} {
		if _, err := parseDuration(Duration(), input, "VALUE"); err != nil {
			t.Fatalf("parseDuration(%T) error = %v", input, err)
		}
	}
	for _, input := range []any{struct{}{}, "1e999", "invalid duration"} {
		if _, err := parseDuration(Duration(), input, "VALUE"); err == nil {
			t.Fatalf("parseDuration(%T) error = nil", input)
		}
	}
	for _, input := range []any{int64(1), int(1), float64(1), "1KB"} {
		if _, err := parseBytes(Bytes(), input, "VALUE"); err != nil {
			t.Fatalf("parseBytes(%T) error = %v", input, err)
		}
	}
	for _, input := range []any{struct{}{}, float64(1.5), float64(-1)} {
		if _, err := parseBytes(Bytes(), input, "VALUE"); err == nil {
			t.Fatalf("parseBytes(%T) error = nil", input)
		}
	}

	jsonCases := []struct {
		rule Rule
		raw  any
		err  bool
	}{
		{JSON(), json.RawMessage(`{"a":1}`), false},
		{JSON(), json.RawMessage(`{`), true},
		{JSON().ObjectOnly(), map[string]any{"a": 1}, false},
		{JSON(), make(chan int), true},
		{JSON().UniqueObjectKeys(), `[{"a":1},{"b":2}]`, false},
		{JSON().RequiredKeys("a"), `[]`, true},
	}
	for _, test := range jsonCases {
		_, err := parseJSON(test.rule, test.raw, "VALUE")
		if (err != nil) != test.err {
			t.Fatalf("parseJSON(%T) error = %v, want error %v", test.raw, err, test.err)
		}
	}

	for _, test := range []struct {
		rule Rule
		raw  string
	}{
		{Int().AtLeast(2), "1"}, {Int().AtMost(0), "1"}, {Int().GreaterThan(1), "1"},
		{Int().LessThan(1), "1"}, {Int().NonZero(), "0"}, {Int().MultipleOf(2), "1"},
		{Int().PositiveOnly(), "0"}, {Int().NegativeOnly(), "1"},
	} {
		if _, err := parseRule(test.rule, test.raw, "VALUE"); err == nil {
			t.Fatalf("numeric rule %#v accepted %s", test.rule, test.raw)
		}
	}

	for _, input := range []any{*big.NewInt(1), int(1), int64(1), uint64(1), "1"} {
		if _, err := parseBigInt(BigInt(), input, "VALUE"); err != nil {
			t.Fatalf("parseBigInt(%T) error = %v", input, err)
		}
	}
	for _, input := range []any{struct{}{}, "not-int"} {
		if _, err := parseBigInt(BigInt(), input, "VALUE"); err == nil {
			t.Fatalf("parseBigInt(%T) error = nil", input)
		}
	}
	if _, err := parseDecimal(Decimal(), *big.NewRat(1, 2), "VALUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseDecimal(Decimal(), "1/2", "VALUE"); err == nil {
		t.Fatal("parseDecimal() accepted a fraction")
	}
	if _, err := parseDecimal(Decimal(), 1, "VALUE"); err == nil {
		t.Fatal("parseDecimal() accepted an integer input")
	}
}

func TestNormalizationAndComparisonBranches(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	values := []any{time.Second, now, []time.Duration{time.Second}, map[string]time.Duration{"x": time.Second}, nil}
	for _, value := range values {
		_ = normalizedDefault(value)
	}

	times := [][2]any{{now, now}, {now.Add(time.Second), now}, {now, "not-time"}}
	for _, pair := range times {
		_, _ = compareConstraintValues(pair[0], pair[1])
	}
	integers := [][2]any{
		{*big.NewInt(1), *big.NewRat(3, 2)},
		{*big.NewRat(1, 2), *big.NewInt(1)},
		{*big.NewRat(1, 2), *big.NewRat(2, 3)},
		{int64(1), uint64(2)},
		{"a", "b"},
	}
	for _, pair := range integers {
		_, _ = compareConstraintValues(pair[0], pair[1])
	}

	_ = JSON().ArrayOnly()
}

func TestCryptographicValidationBranches(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})
	publicDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicDER})

	for _, material := range []string{string(pkcs1PEM), string(pkcs8PEM)} {
		if _, err := parsePrivateKeyMaterial(material); err != nil {
			t.Fatalf("parsePrivateKeyMaterial() error = %v", err)
		}
	}
	if _, err := parsePrivateKeyMaterial("not pem"); err == nil {
		t.Fatal("parsePrivateKeyMaterial() accepted invalid PEM")
	}
	for _, material := range []string{string(publicPEM), string(certificatePEM)} {
		if _, err := parsePublicKey(PublicKey(), material, "VALUE"); err != nil {
			t.Fatalf("parsePublicKey() error = %v", err)
		}
	}

	invalidRules := []Rule{
		Certificate().CAOnly(),
		Certificate().ForHostname("other.example.com"),
		Certificate().ValidAt(now.Add(2 * time.Hour)),
		Certificate().ValidForAtLeast(2 * time.Hour),
		Certificate().ServerAuth(),
		Certificate().AtLeastRSABits(2048),
	}
	for _, rule := range invalidRules {
		if _, err := parseCertificate(rule, string(certificatePEM), "VALUE"); err == nil {
			t.Fatalf("parseCertificate(%v) error = nil", rule.Policies)
		}
	}
	if _, err := parseCertificateBundle(CertificateBundle(), string(certificatePEM)+"garbage", "VALUE"); err == nil {
		t.Fatal("parseCertificateBundle() accepted trailing garbage")
	}
}

func TestAdditionalParserBranches(t *testing.T) {
	t.Parallel()

	mapRule := Map(OneOf("a", "b").CaseInsensitive(), Int()).RejectEmptyKeys().RejectEmptyValues()
	mapCases := []struct {
		raw any
		err bool
	}{
		{map[string]any{"A": "1", "b": "2"}, false},
		{map[string]any{"": "1"}, true},
		{map[string]any{"a": ""}, true},
		{map[string]any{"a": "bad"}, true},
		{[]string{"a=1"}, true},
	}
	for _, test := range mapCases {
		_, err := parseMap(mapRule, test.raw, "VALUE")
		if (err != nil) != test.err {
			t.Fatalf("parseMap(%T) error = %v, want %v", test.raw, err, test.err)
		}
	}
	if _, err := parseMap(Map(String(), Int()).CSV(), "a=1\nb=2", "VALUE"); err == nil {
		t.Fatal("parseMap(CSV) accepted multiple records")
	}
	if _, err := parseMap(Map(String(), Int()).AtLeastItems(2), "a=1", "VALUE"); err == nil {
		t.Fatal("parseMap() ignored minimum items")
	}

	cases := []struct {
		rule Rule
		raw  any
	}{
		{String().WithPrefix("x"), "value"},
		{String().WithSuffix("x"), "value"},
		{String().ASCIIOnly(), "café"},
		{String().WithoutWhitespace(), "a b"},
		{String().UppercaseOnly(), "lower"},
		{Boolean().FalseValues("nay"), "invalid"},
		{Host().LowercaseOnly(), "Example.COM"},
		{Host().UppercaseOnly(), "example.com"},
		{Host().AtLeastLabels(3), "example.com"},
		{Endpoint().NonZeroPort(), "example.com:0"},
		{Endpoint().PortBetween(100, 200), "example.com:80"},
		{Endpoint().PrivateOnly(), "8.8.8.8:53"},
		{Timestamp().WithoutFractionalSeconds(), "2026-08-31T12:00:00.1Z"},
		{Timestamp().Precision(time.Second), "2026-08-31T12:00:00.1Z"},
		{TimeOfDay().WithoutFractionalSeconds(), "12:00:00.1"},
		{BigInt().PositiveOnly(), "0"},
		{Decimal().NegativeOnly(), "1"},
	}
	for _, test := range cases {
		if _, err := parseRule(test.rule, test.raw, "VALUE"); err == nil {
			t.Fatalf("parseRule(%s, %v) error = nil", test.rule.Kind, test.raw)
		}
	}
	if value, err := parseBoolean(Boolean().FalseValues("nay"), "nay", "VALUE"); err != nil || value != false {
		t.Fatalf("parseBoolean(custom false) = %v, %v", value, err)
	}
	for _, test := range []struct {
		rule Rule
		raw  string
	}{
		{Host().AllowIPAddress(), "127.0.0.1"},
		{Host().AllowTrailingDot(), "example.com."},
		{Host().RequireTrailingDot(), "example.com."},
		{Host().UppercaseOnly(), "EXAMPLE.COM"},
	} {
		if _, err := parseHost(test.rule, test.raw, "VALUE"); err != nil {
			t.Fatalf("parseHost(%q) error = %v", test.raw, err)
		}
	}
}
