package envschema

import (
	"fmt"
	"strings"
)

// InGroup places a variable under nested generated fields.
// Environment lookup continues to use Name; this does not add a prefix.
func (variable Variable) InGroup(path ...string) Variable {
	variable.Groups = append([]string(nil), path...)

	return variable
}

// WithGroup instantiates a schema fragment with prefixed environment names.
// Fallback and companion file names and constraint references receive the prefix.
// Generated fields retain the fragment's names under the named group.
func (schema Schema) WithGroup(name, prefix string, fragment Schema) Schema {
	schema.Variables = append([]Variable(nil), schema.Variables...)
	schema.Constraints = append([]Constraint(nil), schema.Constraints...)
	for _, variable := range fragment.Variables {
		if variable.GoName == "" {
			variable.GoName = objectFieldName(Field(strings.ToLower(variable.Name), variable.Rule))
		}
		variable.Name = prefix + variable.Name
		variable.Groups = append([]string{name}, variable.Groups...)
		fallbacks := make([]string, len(variable.Fallbacks))
		for i, fallback := range variable.Fallbacks {
			fallbacks[i] = prefix + fallback
		}
		variable.Fallbacks = fallbacks
		if values, ok := policy(variable.Rule, "fileSource"); ok {
			if len(values) != 2 {
				panic(fmt.Errorf("envschema: invalid file source"))
			}
			variable.Rule = variable.Rule.WithPolicy("fileSource", prefix+values[0], values[1])
		}
		schema.Variables = append(schema.Variables, variable)
	}
	for _, constraint := range fragment.Constraints {
		names := make([]string, len(constraint.Names))
		for i, reference := range constraint.Names {
			names[i] = prefix + reference
		}
		constraint.Names = names
		schema.Constraints = append(schema.Constraints, constraint)
	}
	schema.validated = false
	if err := schema.Validate(); err != nil {
		panic(err)
	}
	schema.validated = true

	return schema
}
