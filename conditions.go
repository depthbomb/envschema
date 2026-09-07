package envschema

import "fmt"

const ConstraintValidateWhen ConstraintKind = "validateWhen"

func validateConditional(constraint Constraint, rules map[string]Rule) error {
	if constraint.Rule == nil || len(constraint.Names) != 2 {
		return fmt.Errorf("envschema: conditional validation requires a rule and two variables")
	}
	target := rules[constraint.Names[1]]
	if constraint.Rule.Kind != target.Kind {
		return fmt.Errorf("envschema: conditional rule must preserve the target kind")
	}
	if err := validateRule(*constraint.Rule, constraint.Names[1]+" condition"); err != nil {
		return err
	}
	if constraint.Rule.HasDefault {
		return fmt.Errorf("envschema: conditional rules cannot define defaults")
	}
	if _, err := parseRule(rules[constraint.Names[0]], constraint.Value, constraint.Names[0]+" condition"); err != nil {
		return err
	}

	return nil
}

func validateConditionalTarget(constraint Constraint, variable Variable, lookup LookupFunc) error {
	additional := *constraint.Rule
	additional.Redact = additional.Redact || variable.Rule.Redact || variable.Rule.Kind == KindSecret || variable.Rule.Kind == KindPrivateKey
	additional.Default = variable.Rule.Default
	additional.HasDefault = variable.Rule.HasDefault
	// Preserve file resolution while applying the additional rule.
	if values, ok := policy(variable.Rule, "fileSource"); ok {
		additional = additional.WithPolicy("fileSource", values...)
	}
	_, _, err := parseVariable(additional, variable.Name, variable.Fallbacks, lookup)

	return err
}

// ValidateWhen applies an additional rule when the condition's parsed value matches.
// The target retains its base parsed result. The additional rule must have the same kind.
func (schema Schema) ValidateWhen(name string, expected string, target string, rule Rule) Schema {
	schema.Constraints = append(append([]Constraint(nil), schema.Constraints...), Constraint{
		Kind:  ConstraintValidateWhen,
		Names: []string{name, target},
		Value: expected,
		Rule:  &rule,
	})
	schema.validated = false
	if err := schema.Validate(); err != nil {
		panic(err)
	}
	schema.validated = true

	return schema
}
