package envschema

import (
	"fmt"
	"net/url"
)

func validateQueryFields(rule Rule, path string) error {
	if len(rule.QueryFields) == 0 {
		return nil
	}

	if rule.Kind != KindURL && rule.Kind != KindURI {
		return fmt.Errorf("envschema: %s query parameters require URL or URI", path)
	}

	seen := make(map[string]bool)
	for _, field := range rule.QueryFields {
		if field.Name == "" || seen[field.Name] {
			return fmt.Errorf("envschema: duplicate or empty query parameter")
		}
		seen[field.Name] = true
		if field.Rule.Kind == KindCustom {
			return fmt.Errorf("envschema: query parameters do not support custom rules")
		}

		if err := validateRule(field.Rule, path+".query."+field.Name); err != nil {
			return err
		}

		if field.Rule.HasDefault {
			if _, err := parseRule(field.Rule, field.Rule.Default, path+".query."+field.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkQueryFields(rule Rule, value any, path string) error {
	if len(rule.QueryFields) == 0 {
		return nil
	}
	parsed, err := url.Parse(value.(string))
	if err != nil {
		return fmt.Errorf("[%s] invalid URL", path)
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return fmt.Errorf("[%s] invalid query encoding", path)
	}
	for _, field := range rule.QueryFields {
		values, present := query[field.Name]
		var raw any
		if !present {
			if field.Rule.HasDefault {
				raw = field.Rule.Default
			} else if field.Rule.Required {
				return fmt.Errorf("[%s.query.%s] required parameter is missing", path, field.Name)
			} else {
				continue
			}
		} else if field.Rule.Kind == KindArray {
			items := make([]any, len(values))
			for i, value := range values {
				items[i] = value
			}
			raw = items
		} else {
			if len(values) != 1 {
				return fmt.Errorf("[%s.query.%s] expected one value", path, field.Name)
			}
			raw = values[0]
		}

		if _, err := parseRule(field.Rule, raw, path+".query."+field.Name); err != nil {
			return err
		}
	}

	return nil
}

// QueryParameter validates a URL query parameter with an existing rule.
// Scalar parameters must occur once; Array rules validate repeated occurrences.
// Required, optional, and default behavior follows the parameter rule.
// Validation does not rewrite the returned URL or inject default query values.
func (rule Rule) QueryParameter(name string, parameter Rule) Rule {
	rule.QueryFields = append(append([]ObjectField(nil), rule.QueryFields...), Field(name, parameter))

	return rule
}
