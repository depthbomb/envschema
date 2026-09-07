package envschema

import (
	"math"
	"reflect"
	"testing"
	"time"
)

func referenceRelationship(kind ConstraintKind, left, right any) bool {
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

func TestIndexedRelationshipSemantics(t *testing.T) {
	large := make([]string, 32)
	for i := range large {
		large[i] = string(rune('a' + i))
	}
	first, second := int64(7), int64(7)
	values := []any{
		"a", int64(1), true,
		[]string{}, []string{"a"}, []string{"a", "b", "a"}, large,
		[]int64{1, 2}, []uint64{1, 2}, []float64{0, math.Copysign(0, -1), math.NaN()}, []bool{true, false},
		[]time.Duration{time.Second, time.Minute},
		map[string]any{
			"a": 1,
			"b": 2,
		},
		[][]int{{1, 2}, {3}},
		[]any{map[string]any{
			"a": 1,
		}},
		[]*int64{&first}, []*int64{&second},
		Protected[any]{
			value: []string{"a", "b"},
		},
		Protected[any]{
			value: "a",
		},
		[]any{Protected[any]{
			value: "a",
		}, Protected[any]{
			value: "b",
		}},
	}
	for _, value := range []any{[]int64{1, 2}, []uint64{1, 2}, []float64{0, math.Copysign(0, -1), math.NaN()}, []bool{true, false}, []time.Duration{time.Second, time.Minute}} {
		original := reflect.ValueOf(value)
		expanded := reflect.MakeSlice(original.Type(), 32, 32)
		for i := range 32 {
			expanded.Index(i).Set(original.Index(i % original.Len()))
		}
		values = append(values, expanded.Interface())
	}
	for _, kind := range []ConstraintKind{ConstraintMemberOf, ConstraintSubsetOf, ConstraintDisjoint} {
		for _, left := range values {
			for _, right := range values {
				expected := referenceRelationship(kind, left, right)
				if actual := checkRelationship(kind, left, right); actual != expected {
					t.Fatalf("%s with %v and %v: got %t, want %t", kind, reflect.TypeOf(left), reflect.TypeOf(right), actual, expected)
				}
			}
		}
	}
}
