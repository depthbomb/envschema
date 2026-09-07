package envschema

import (
	"fmt"
	"reflect"
)

func collectionRule(rule Rule) *Rule {
	if rule.Redact {
		rule.Redact = false
	}
	switch rule.Kind {
	case KindList, KindArray:
		return rule.Item
	case KindMap:
		return rule.Key
	}

	return nil
}

func validateRelationship(constraint Constraint, rules map[string]Rule) error {
	right := collectionRule(rules[constraint.Names[1]])
	if right == nil {
		return fmt.Errorf("envschema: relationship requires a collection on the right")
	}
	left := rules[constraint.Names[0]]
	if constraint.Kind != ConstraintMemberOf {
		item := collectionRule(left)
		if item == nil {
			return fmt.Errorf("envschema: relationship requires two collections")
		}
	}

	return nil
}

func relationshipItems(value any) []any {
	if protected, ok := value.(interface{ protectedValue() any }); ok {
		value = protected.protectedValue()
	}
	reflected := reflect.ValueOf(value)
	var items []any
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < reflected.Len(); i++ {
			items = append(items, reflected.Index(i).Interface())
		}
	case reflect.Map:
		for _, key := range reflected.MapKeys() {
			items = append(items, key.Interface())
		}
	}

	return items
}

func relationshipEqual(left, right any) bool {
	if value, ok := left.(interface{ protectedValue() any }); ok {
		left = value.protectedValue()
	}

	if value, ok := right.(interface{ protectedValue() any }); ok {
		right = value.protectedValue()
	}

	return reflect.DeepEqual(left, right)
}

func checkRelationship(kind ConstraintKind, left, right any) bool {
	items := relationshipItems(right)
	candidates := []any{left}
	if kind != ConstraintMemberOf {
		candidates = relationshipItems(left)
	}
	for _, candidate := range candidates {
		found := false
		for _, item := range items {
			if relationshipEqual(candidate, item) {
				found = true
				break
			}
		}
		if kind == ConstraintDisjoint && found || kind != ConstraintDisjoint && !found {
			return false
		}
	}

	return true
}

const (
	ConstraintMemberOf ConstraintKind = "memberOf"
	ConstraintSubsetOf ConstraintKind = "subsetOf"
	ConstraintDisjoint ConstraintKind = "disjoint"
)

// MemberOf requires a scalar to belong to a list, array, or map's keys.
// Like other value contracts, relationships apply when both variables are present.
func (schema Schema) MemberOf(value, collection string) Schema {
	return schema.withConstraint(ConstraintMemberOf, "", value, collection)
}

// SubsetOf requires every left item (or map key) to occur on the right.
func (schema Schema) SubsetOf(left, right string) Schema {
	return schema.withConstraint(ConstraintSubsetOf, "", left, right)
}

// DisjointWith forbids shared items or map keys.
func (schema Schema) DisjointWith(left, right string) Schema {
	return schema.withConstraint(ConstraintDisjoint, "", left, right)
}
