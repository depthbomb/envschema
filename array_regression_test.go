package envschema

import (
	"reflect"
	"testing"
)

func TestArrayRequiresCompleteJSONArray(t *testing.T) {
	for _, input := range []string{"[1] garbage", "[1][2]", "[1] true", "null", "{}", "1", "", "[1,]"} {
		if value, err := parseRule(Array(Int()), input, "VALUE"); err == nil {
			t.Errorf("accepted %q as %v", input, value)
		}
	}
	value, err := parseRule(Array(Int()), " \t[1, 9007199254740993]\r\n", "VALUE")
	if err != nil || !reflect.DeepEqual(value, []int64{1, 9007199254740993}) {
		t.Fatalf("valid array changed: %v, %v", value, err)
	}
	value, err = parseRule(Array(Int()), "[]", "VALUE")
	if err != nil || len(value.([]int64)) != 0 {
		t.Fatalf("empty array rejected: %v, %v", value, err)
	}
}
