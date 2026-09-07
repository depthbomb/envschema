package envschema

import "testing"

func TestURLAlwaysValidatesCompleteInput(t *testing.T) {
	for _, rule := range []Rule{URL(), URL().HTTPSOnly(), URL().AllowRelativeReference()} {
		for _, input := range []string{"https://example.com:bad", "https://example.com/%zz", "https://[::1", "https://example.com/path\n"} {
			if _, err := parseRule(rule, input, "VALUE"); err == nil {
				t.Errorf("URL accepted %q", input)
			}
		}
	}
	for _, input := range []string{"https://example.com:443/path?q=1#part", "postgres://user:pass@localhost:5432/db", "https://[::1]/"} {
		if _, err := parseRule(URL(), input, "VALUE"); err != nil {
			t.Errorf("URL rejected %q: %v", input, err)
		}
	}
}
