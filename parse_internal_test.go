package envschema

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRuleSuccessAndFailureMatrix(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	file := filepath.Join(directory, "config.json")
	if err := os.WriteFile(file, []byte("{}"), 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		rule    Rule
		raw     any
		wantErr bool
	}{
		{"string valid", String().Trimmed().Containing("ok").NotContaining("bad").ValidUTF8().SingleLine(), " ok ", false},
		{"string pattern", String().Matching(`^[a-z]+$`).WithExactLength(3), "A1", true},
		{"string bytes", String().WithByteLengthBetween(2, 3), "four", true},
		{"string casing", String().LowercaseOnly(), "UPPER", true},
		{"string printable", String().PrintableOnly(), "a\x00", true},
		{"number", Number().GreaterThan(1).LessThan(3).MultipleOf(.5), "2.5", false},
		{"number infinity", Number(), "Inf", true},
		{"number nonzero", Float().NonZero(), "0", true},
		{"int base", Int().Base(16), "ff", false},
		{"int malformed", Int(), "1.5", true},
		{"uint", Uint(), "-1", true},
		{"boolean custom", Boolean().TrueValues("aye").FalseValues("nay"), "aye", false},
		{"boolean invalid", Boolean().Strict(), "yes", true},
		{"enum alias", OneOf("one", "two").CaseInsensitive().Alias("first", "one"), "FIRST", false},
		{"enum invalid", OneOf("one"), "two", true},
		{"json object", JSON().ObjectOnly().RequiredKeys("a").AllowedKeys("a").AtMostDepth(2), json.RawMessage(`{"a":1}`), false},
		{"json scalar", JSON().ScalarOnly().WithoutNull(), "null", true},
		{"json bytes", JSON().AtMostBytes(2), "[1]", true},
		{"json duplicate", JSON().UniqueObjectKeys(), `{"a":1,"a":2}`, true},
		{"json invalid UTF-8 duplicate", JSON().UniqueObjectKeys(), "{\"\xff\":1,\"\xfe\":2}", true},
		{"json escaped duplicate", JSON().UniqueObjectKeys(), `{"a":1,"\u0061":2}`, true},
		{"json escaped duplicate first", JSON().UniqueObjectKeys(), `{"\u0061":1,"a":2}`, true},
		{"json escaped distinct", JSON().UniqueObjectKeys(), `{"a":1,"\u0062":2}`, false},
		{"json large duplicate", JSON().UniqueObjectKeys(), `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10,"k":11,"l":12,"m":13,"n":14,"o":15,"p":16,"q":17,"q":18}`, true},
		{"json large unique", JSON().UniqueObjectKeys(), `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10,"k":11,"l":12,"m":13,"n":14,"o":15,"p":16,"q":17}`, false},
		{"json nested duplicate", JSON().UniqueObjectKeys(), `[{"a":1,"a":2}]`, true},
		{"json whitespace", JSON().UniqueObjectKeys(), " \t{\r\n\"a\" : [ true, null, \"x\" ]\n} ", false},
		{"json unique scalar", JSON().UniqueObjectKeys(), "true", false},
		{"array", Array(Int()), `[1,"2"]`, false},
		{"array malformed", Array(Int()), `{}`, true},
		{"list csv", List(String()).CSV(), `"a,b",c`, false},
		{"list empty", List(String()).RejectEmptyItems(), "a,,b", true},
		{"list unique", List(String()).CaseInsensitiveUniqueItems(), "a,A", true},
		{"list sorted", List(Int()).Sorted(), "2,1", true},
		{"duration words", Duration().AtLeastDuration(time.Second), "2 seconds", false},
		{"duration bounds", Duration().AtMostDuration(time.Second), "2s", true},
		{"date", Date(), "2026-08-31", false},
		{"date invalid", Date(), "yesterday", true},
		{"bytes", Bytes(), "1.5KiB", false},
		{"bytes negative", Bytes(), "-1KB", true},
		{"path file", Path().File().Existing().AbsoluteOnly().WithExtensions(".json"), file, false},
		{"path executable", Path().Executable(), file, true},
		{"path directory", Path().Directory().Existing(), directory, false},
		{"path kind", Path().Directory().Existing(), file, true},
		{"path missing", Path().NotExisting(), file, true},
		{"base64", Base64().URLSafeEncoding().WithPadding(PaddingForbidden), "SGVsbG8", false},
		{"base64 invalid", Base64(), "%%%", true},
		{"email", Email(), "a@example.com", false},
		{"email invalid", Email(), "a@", true},
		{"port", Port().NonZeroPort().PortBetween(80, 443), "443", false},
		{"port invalid", Port(), "65536", true},
		{"url", URL().HTTPSOnly().RequireHost().RequirePath().RequireQueryKeys("q").WithoutUserPassword(), "https://example.com/p?q=1", false},
		{"url credentials", URL().WithoutCredentials(), "https://u:p@example.com", true},
		{"url canonical", URL().CanonicalOnly(), "HTTPS://EXAMPLE.COM", true},
		{"host", Host().AtLeastLabels(2).AtMostLabels(3).WithDomainSuffix("example.com"), "api.example.com", false},
		{"host suffix invalid", Host().WithDomainSuffix("example.com"), "127.0.0.1", true},
		{"uuid", UUID().Versions(UUIDv4).RFC9562VariantOnly().NonNil().NonMax(), "550e8400-e29b-41d4-a716-446655440000", false},
		{"uuid invalid", UUID(), "nope", true},
		{"ip private", IPAddress().PrivateOnly().WithoutLoopback(), "10.0.0.1", false},
		{"ip version", IPAddress().IPVersionIs(IPv6), "10.0.0.1", true},
		{"hash", Hash(SHA256).WithHashPrefix("sha256:"), "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"hash length", Hash(SHA1), "abcd", true},
		{"hex", Hex().UppercaseOnly(), "DEADBEEF", false},
		{"hex invalid", Hex(), "xyz", true},
		{"semver", SemVer().RequirePrerelease().RequireBuildMetadata().AtLeastVersion("1.0.0").LessThanVersion("2.0.0"), "1.2.3-beta+build", false},
		{"semver bound", SemVer().AtLeastVersion("2.0.0"), "1.0.0", true},
		{"timezone", TimeZone(), "UTC", false},
		{"timezone invalid", TimeZone(), "Mars/Olympus", true},
		{"cidr", CIDR().CanonicalOnly().ContainingAddresses("10.1.2.3").ContainedBy("10.0.0.0/8"), "10.1.0.0/16", false},
		{"cidr noncanonical", CIDR().CanonicalOnly(), "10.0.0.1/8", true},
		{"endpoint", Endpoint().HostnameOnly().ValidateHostname().NonZeroPort().PortBetween(1, 443), "example.com:443", false},
		{"endpoint invalid", Endpoint().IPOnly(), "example.com:80", true},
		{"timestamp", Timestamp().RequireOffset().RequireSeconds().WithFractionalSeconds().Precision(time.Millisecond), "2026-08-31T12:00:00.123-05:00", false},
		{"timestamp UTC", Timestamp().UTCOnly(), "2026-08-31T12:00:00-05:00", true},
		{"time", TimeOfDay().RequireSeconds().WithFractionalSeconds(), "12:00:00.1", false},
		{"time invalid", TimeOfDay(), "25:00", true},
		{"map", Map(OneOf("a", "b"), Int()).RejectEmptyKeys().RejectEmptyValues(), "a=1,b=2", false},
		{"map malformed", Map(String(), Int()), "a", true},
		{"regexp", Regexp(), "[a-z]+", false},
		{"regexp invalid", Regexp(), "[", true},
		{"pem invalid", PEM(), "not pem", true},
		{"certificate invalid", Certificate(), "not pem", true},
		{"private key invalid", PrivateKey(), "not pem", true},
		{"uri relative", URI().AllowRelativeReference().RequirePath().WithoutQuery(), "/path", false},
		{"uri host", URI().RequireHost(), "urn:value", true},
		{"mac", MACAddress(), "02:00:5e:10:00:00", false},
		{"mac invalid", MACAddress(), "not-mac", true},
		{"public key invalid", PublicKey(), "not pem", true},
		{"bundle invalid", CertificateBundle(), "not pem", true},
		{"bigint", BigInt().Base(16).PositiveOnly().MultipleOf(2), "ff", true},
		{"bigint valid", BigInt().Base(16), "ff", false},
		{"decimal", Decimal().GreaterThan(1).LessThan(2), "1.5", false},
		{"decimal invalid", Decimal(), "NaN", true},
		{"media", MediaType().RequireMediaTypeParameters(), "text/plain; charset=utf-8", false},
		{"media invalid", MediaType().WithoutMediaTypeParameters(), "text/plain; charset=utf-8", true},
		{"file mode", FileMode(), "0755", false},
		{"file mode invalid", FileMode(), "9999", true},
		{"ulid", ULID(), "01ARZ3NDEKTSV4RRFFQ69G5FAV", false},
		{"ulid invalid", ULID(), "nope", true},
		{"glob", Glob(), "config/*.json", false},
		{"glob invalid", Glob(), "[", true},
		{"nan internal", Number(), math.NaN(), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseRule(test.rule, test.raw, "VALUE")
			if test.wantErr && err == nil {
				t.Fatal("parseRule() error = nil")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("parseRule() error = %v", err)
			}
		})
	}
}
