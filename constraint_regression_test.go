package envschema

import (
	"fmt"
	"testing"
)

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

func TestConstraintsOnLargeSchemas(t *testing.T) {
	variables := make([]Variable, 32)
	for index := range variables {
		variables[index] = Var(fmt.Sprintf("V%d", index), Int().DefaultTo(index))
	}
	schema := Must(variables...).LessThanVariable("V30", "V31").RequiredWhen("V31", "31", "V30")
	lookup := func(string) (string, bool) {
		return "", false
	}
	values, err := LoadFrom(schema, lookup)
	if err != nil || values["V30"] != int64(30) {
		t.Fatalf("indexed constraints failed: %v, %v", values, err)
	}
	invalid := func(name string) (string, bool) {
		return "32", name == "V30"
	}
	if _, err := LoadFrom(schema, invalid); err == nil {
		t.Fatal("indexed constraint accepted a larger left value")
	}
}
