package envschema

import (
	"encoding/json"
	"testing"
)

func FuzzParseEnvFile(f *testing.F) {
	for _, seed := range []string{"A=value\n", "export A='value'\n", "A=\"line\\nvalue\"\n", "# comment\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, contents string) {
		_, _ = parseEnvFile([]byte(contents))
	})
}

func FuzzSchemaJSON(f *testing.F) {
	for _, seed := range []string{
		`{"variables":[]}`,
		`{"variables":[{"name":"VALUE","rule":{"kind":"object","fields":[{"name":"count","rule":{"kind":"int","sensitive":true}}]}}]}`,
		`{"variables":[{"name":"VALUE","rule":{"kind":"decimal","policies":{"exactMin":["0.01"],"decimalScale":["2"]}}}]}`,
		`{"variables":[{"name":"VALUE","rule":{"kind":"string"}}]}`,
		`{}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		var schema Schema
		if json.Unmarshal([]byte(encoded), &schema) == nil {
			_ = schema.Validate()
		}
	})
}

func FuzzStructuredValues(f *testing.F) {
	for _, seed := range []string{`{"a":[1,2]}`, `[1,2]`, `null`, `{`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseJSON(JSON().AtMostDepth(16).UniqueObjectKeys(), value, "VALUE")
		_, _ = parseArray(Array(String()), value, "VALUE")
		_, _ = parseMap(Map(String(), String()), value, "VALUE")
		_, _ = parseRule(Object(Field("items", Array(Int().Sensitive())), Field("timeout", Duration().Optional())), value, "VALUE")
		_, _ = parseRule(URL().QueryParameter("timeout", Int()), value, "VALUE")
	})
}

func FuzzNetworkValues(f *testing.F) {
	for _, seed := range []string{"https://example.com/path?q=1", "urn:example:value", "127.0.0.1", "[::1]:443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseURI(URI(), value, "VALUE")
		_, _ = parseURL(value, "VALUE")
		_, _ = parseHost(Host(), value, "VALUE")
		_, _ = parseEndpoint(Endpoint(), value, "VALUE")
		_, _ = parseCIDR(CIDR(), value, "VALUE")
	})
}
