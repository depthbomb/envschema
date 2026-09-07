package envschema

import "testing"

func TestConstraintsUseDefaultsForEmptyValues(t *testing.T) {
	base := Must(Var("A", String().DefaultTo("default")), Var("B", String().Optional()))
	lookup := func(name string) (string, bool) {
		if name == "A" {
			return "", true
		}

		return "present", true
	}
	for _, schema := range []Schema{base.MutuallyExclusive("A", "B"), base.ExactlyOneOf("A", "B"), base.ForbiddenWhen("B", "present", "A")} {
		if _, err := LoadFrom(schema, lookup); err == nil {
			t.Error("constraint failed to count default for empty value")
		}
	}
	for _, schema := range []Schema{base.RequiredTogether("A", "B"), base.RequiredWhen("B", "present", "A")} {
		if _, err := LoadFrom(schema, lookup); err != nil {
			t.Fatal(err)
		}
	}
	fallback := Must(Var("A", String().DefaultTo("default")).FallbackTo("OLD_A"), Var("B", String().Optional())).RequiredTogether("A", "B")
	fallbackLookup := func(name string) (string, bool) {
		if name == "A" {
			return "", false
		}
		if name == "OLD_A" {
			return "", true
		}

		return "present", true
	}
	if _, err := LoadFrom(fallback, fallbackLookup); err != nil {
		t.Fatal(err)
	}
	allowed := Must(Var("A", String().AllowEmpty().DefaultTo("default")), Var("B", String().Optional())).RequiredTogether("A", "B")
	values, err := LoadFrom(allowed, lookup)
	if err != nil || values["A"] != "" {
		t.Fatalf("allowed empty value changed: %v, %v", values, err)
	}
}
