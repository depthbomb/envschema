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

func TestRelativeURLPolicies(t *testing.T) {
	tests := []struct {
		rule  Rule
		input string
	}{
		{
			rule:  URL().RelativeOnly().WithoutQuery(),
			input: "/path?token=abc",
		},
		{
			rule:  URL().RelativeOnly().WithoutQuery(),
			input: "/path?",
		},
		{
			rule:  URL().RelativeOnly().WithoutFragment(),
			input: "/path#part",
		},
		{
			rule:  URL().RelativeOnly().WithPathPrefix("/api/"),
			input: "/admin/",
		},
		{
			rule:  URL().RelativeOnly().RequireQueryKeys("id"),
			input: "/api/",
		},
	}
	for _, test := range tests {
		if _, err := New(Var("VALUE", test.rule)); err != nil {
			t.Fatal(err)
		}
		if _, err := parseRule(test.rule, test.input, "VALUE"); err == nil {
			t.Errorf("relative URL policy accepted %q", test.input)
		}
	}
	if _, err := parseRule(URL().RelativeOnly().WithPathPrefix("/api/").WithoutQuery(), "/api/users", "VALUE"); err != nil {
		t.Fatal(err)
	}
}
