package envschema

import (
	"fmt"
	"reflect"
	"slices"
	"time"
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
		items = make([]any, 0, reflected.Len())
		for i := 0; i < reflected.Len(); i++ {
			items = append(items, reflected.Index(i).Interface())
		}
	case reflect.Map:
		items = make([]any, 0, reflected.Len())
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

// Primitive equality matches reflect.DeepEqual without reflection or boxing.
// Small collections use a scan to avoid paying for an index.
func comparableRelationship[T comparable](kind ConstraintKind, left any, items []T) (bool, bool) {
	if kind == ConstraintMemberOf {
		candidate, ok := left.(T)

		return ok && slices.Contains(items, candidate), true
	}
	candidates, ok := left.([]T)
	if !ok {
		return false, false
	}

	if len(candidates) == 0 {
		return true, true
	}
	var indexed map[T]struct{}
	if len(items) > 16 && len(candidates) > 1 {
		indexed = make(map[T]struct{}, len(items))
		for _, item := range items {
			indexed[item] = struct{}{}
		}
	}
	for _, candidate := range candidates {
		found := false
		if indexed != nil {
			_, found = indexed[candidate]
		} else {
			found = slices.Contains(items, candidate)
		}

		if kind == ConstraintDisjoint && found || kind != ConstraintDisjoint && !found {
			return false, true
		}
	}

	return true, true
}

func checkRelationship(kind ConstraintKind, left, right any) bool {
	if protected, ok := left.(interface{ protectedValue() any }); ok {
		left = protected.protectedValue()
	}

	if protected, ok := right.(interface{ protectedValue() any }); ok {
		right = protected.protectedValue()
	}

	if values, ok := right.(map[string]any); ok {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		right = keys
	}

	if kind != ConstraintMemberOf {
		if values, ok := left.(map[string]any); ok {
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			left = keys
		}
	}
	var result, handled bool
	switch items := right.(type) {
	case []string:
		result, handled = comparableRelationship(kind, left, items)
	case []int64:
		result, handled = comparableRelationship(kind, left, items)
	case []uint64:
		result, handled = comparableRelationship(kind, left, items)
	case []float64:
		result, handled = comparableRelationship(kind, left, items)
	case []bool:
		result, handled = comparableRelationship(kind, left, items)
	case []time.Duration:
		result, handled = comparableRelationship(kind, left, items)
	}
	if handled {
		return result
	}

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
