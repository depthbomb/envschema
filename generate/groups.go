package generate

import (
	"fmt"
	"strings"
)

type groupField struct {
	name     string
	goType   string
	tag      string
	children []*groupField
}

func addGroupField(fields *[]*groupField, path []string, goType, tag string) error {
	for _, field := range *fields {
		if field.name != path[0] {
			continue
		}
		if len(path) == 1 || field.goType != "" {
			return fmt.Errorf("generate: group and field collision at %s", path[0])
		}

		return addGroupField(&field.children, path[1:], goType, tag)
	}
	field := &groupField{name: path[0]}
	*fields = append(*fields, field)
	if len(path) == 1 {
		field.goType = goType
		field.tag = tag
		return nil
	}

	return addGroupField(&field.children, path[1:], goType, tag)
}

func writeGroupFields(result *strings.Builder, fields []*groupField) {
	for _, field := range fields {
		result.WriteString(field.name + " ")
		if field.goType != "" {
			result.WriteString(field.goType + " " + field.tag + "\n")
			continue
		}
		result.WriteString("struct {\n")
		writeGroupFields(result, field.children)
		result.WriteString("}\n")
	}
}
