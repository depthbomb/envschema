package envschema

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func containsSecrets(rule Rule) bool {
	if rule.Redact || rule.Kind == KindSecret || rule.Kind == KindPrivateKey {
		return true
	}
	if rule.Item != nil && containsSecrets(*rule.Item) {
		return true
	}
	for _, field := range rule.Fields {
		if containsSecrets(field.Rule) {
			return true
		}
	}

	return false
}

func defaultText(rule Rule) string {
	if containsSecrets(rule) {
		return "[redacted]"
	}
	switch value := rule.Default.(type) {
	case string:
		return value
	case time.Duration:
		return value.String()
	case time.Time:
		return value.Format(time.RFC3339Nano)
	case json.Number:
		return value.String()
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}

		return string(encoded)
	}
}

func markdownCell(text string) string {
	text = strings.ReplaceAll(text, "|", "\\|")

	return strings.ReplaceAll(strings.ReplaceAll(text, "\r", " "), "\n", " ")
}

// DescribedAs adds human-readable configuration documentation.
func (variable Variable) DescribedAs(description string) Variable {
	variable.Description = description

	return variable
}

// Example returns dotenv text with non-sensitive defaults and commented placeholders.
// Secret defaults, including nested secrets, are never emitted.
func Example(schema Schema) (string, error) {
	if err := schema.Validate(); err != nil {
		return "", err
	}
	var result strings.Builder
	for _, variable := range schema.Variables {
		if variable.Description != "" {
			for _, line := range strings.Split(strings.ReplaceAll(variable.Description, "\r", ""), "\n") {
				result.WriteString("# " + line + "\n")
			}
		}
		rule := variable.Rule
		_, explicit := policy(rule, "explicitInput")
		if rule.HasDefault && !containsSecrets(rule) && !explicit {
			encoded, _ := json.Marshal(defaultText(rule))
			fmt.Fprintf(&result, "%s=%s\n", variable.Name, encoded)
		} else {
			requirement := "optional"
			if rule.Required || explicit {
				requirement = "required"
			}
			fmt.Fprintf(&result, "# %s=<%s %s>\n", variable.Name, requirement, rule.Kind)
		}
		if values, ok := policy(rule, "fileSource"); ok {
			fmt.Fprintf(&result, "# %s=<file containing %s>\n", values[0], variable.Name)
		}
	}

	return result.String(), nil
}

// Documentation returns a Markdown table describing the environment contract.
func Documentation(schema Schema) (string, error) {
	if err := schema.Validate(); err != nil {
		return "", err
	}
	var result strings.Builder
	result.WriteString("| Variable | Rule | Required | Default | Description |\n| --- | --- | --- | --- | --- |\n")
	for _, variable := range schema.Variables {
		defaultValue := ""
		if variable.Rule.HasDefault {
			defaultValue = defaultText(variable.Rule)
		}
		description := variable.Description
		if variable.Deprecation != "" {
			description += " Deprecated: " + variable.Deprecation
		}
		fmt.Fprintf(&result, "| %s | %s | %t | %s | %s |\n", variable.Name, variable.Rule.Kind, variable.Rule.Required, markdownCell(defaultValue), markdownCell(description))
	}

	return result.String(), nil
}
