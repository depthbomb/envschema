package envschema

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Source provides stable values, names, and source labels for one load.
type Source interface {
	Lookup(string) (string, bool)
	Names() []string
	Origin(string) string
}

// MapSource is an enumerable source. Do not mutate Values during loading.
type MapSource struct {
	Values map[string]string
	Label  string
}

// ValueOrigin identifies the selected input without including its value.
type ValueOrigin struct {
	Name    string
	Source  string
	File    bool
	Default bool
}

// LoadReport records selected origins and migration notices.
type LoadReport struct {
	Origins map[string]ValueOrigin
	Notices []string
}

type layeredSource struct {
	values  map[string]string
	origins map[string]string
}

type FileConflict string

const (
	FileConflictError FileConflict = "error"
	PreferValue       FileConflict = "value"
	PreferFile        FileConflict = "file"
)

func readVariableSource(rule *Rule, name string, fallbacks []string, lookup LookupFunc) (string, bool, error) {
	value, exists := lookup(name)
	for _, fallback := range fallbacks {
		if exists {
			break
		}
		value, exists = lookup(fallback)
	}
	source, configured := policy(*rule, "fileSource")
	if !configured {
		return value, exists, nil
	}
	if len(source) != 2 {
		return "", false, fmt.Errorf("[%s] invalid file source", name)
	}
	filename, fileExists := lookup(source[0])
	if !fileExists {
		return value, exists, nil
	}
	if exists && source[1] == string(FileConflictError) {
		return "", false, fmt.Errorf("[%s] both value and file source are supplied", name)
	}
	if exists && source[1] == string(PreferValue) {
		return value, true, nil
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return "", false, fmt.Errorf("[%s] cannot read file source: %w", name, err)
	}

	return string(contents), true, nil
}

// FromFile allows a companion variable to supply a filename containing the value.
// File contents are preserved exactly; use Trimmed where appropriate.
func (rule Rule) FromFile(name string, conflict FileConflict) Rule {
	return rule.WithPolicy("fileSource", name, string(conflict))
}

func (source MapSource) Lookup(name string) (string, bool) {
	value, exists := source.Values[name]

	return value, exists
}

func (source MapSource) Names() []string {
	names := make([]string, 0, len(source.Values))
	for name := range source.Values {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

func (source MapSource) Origin(string) string {
	return source.Label
}

func (source layeredSource) Lookup(name string) (string, bool) {
	value, exists := source.values[name]

	return value, exists
}

func (source layeredSource) Names() []string {
	return (MapSource{Values: source.values}).Names()
}

func (source layeredSource) Origin(name string) string {
	return source.origins[name]
}

// ProcessSource snapshots the process environment.
func ProcessSource() Source {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			values[name] = value
		}
	}

	return MapSource{Values: values, Label: "process"}
}

// EnvFileSource reads .env then .env.local, with process values taking precedence.
func EnvFileSource(directory string, process Source) (Source, error) {
	result := layeredSource{values: make(map[string]string), origins: make(map[string]string)}
	for _, filename := range []string{".env", ".env.local"} {
		contents, err := os.ReadFile(filepath.Join(directory, filename))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		values, err := parseEnvFile(contents)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		for name, value := range values {
			result.values[name] = value
			result.origins[name] = filename
		}
	}
	if process != nil {
		for _, name := range process.Names() {
			if value, exists := process.Lookup(name); exists {
				result.values[name] = value
				result.origins[name] = process.Origin(name)
			}
		}
	}

	return result, nil
}

// LoadWithReport parses a source and records origins, defaults, and fallback use.
// Reports contain names and source labels, never input values or file contents.
func LoadWithReport(schema Schema, source Source) (Values, LoadReport, error) {
	report := LoadReport{Origins: make(map[string]ValueOrigin)}
	if err := schema.Validate(); err != nil {
		return nil, report, err
	}
	if source == nil {
		return nil, report, fmt.Errorf("envschema: nil source")
	}
	resolved := make(map[string]string)
	prepared := schema
	prepared.Variables = append([]Variable(nil), schema.Variables...)
	for i, variable := range schema.Variables {
		selected := variable.Name
		raw, present := source.Lookup(selected)
		for _, name := range variable.Fallbacks {
			if present {
				break
			}
			selected = name
			raw, present = source.Lookup(name)
		}
		origin := ValueOrigin{Name: selected, Source: source.Origin(selected)}
		if policyValues, configured := policy(variable.Rule, "fileSource"); configured && len(policyValues) == 2 {
			_, filePresent := source.Lookup(policyValues[0])
			if filePresent && (!present || policyValues[1] == string(PreferFile)) {
				origin = ValueOrigin{Name: policyValues[0], Source: source.Origin(policyValues[0]), File: true}
			}
		}
		var err error
		raw, present, err = readVariableSource(&variable.Rule, variable.Name, variable.Fallbacks, source.Lookup)
		if err != nil {
			return nil, report, err
		}
		if present {
			resolved[variable.Name] = raw
		}
		prepared.Variables[i].Fallbacks = nil
		prepared.Variables[i].Rule = variable.Rule.WithPolicy("fileSource")
		delete(prepared.Variables[i].Rule.Policies, "fileSource")
		if (!present || raw == "" && !variable.Rule.EmptyAllowed) && variable.Rule.HasDefault {
			origin = ValueOrigin{Source: "default", Default: true}
		} else if !present {
			continue
		}
		report.Origins[variable.Name] = origin
		if !origin.Default && !origin.File && selected != variable.Name {
			report.Notices = append(report.Notices, fmt.Sprintf("%s was supplied through fallback %s; migrate to %s", variable.Name, selected, variable.Name))
		}
		if variable.Deprecation != "" && !origin.Default {
			report.Notices = append(report.Notices, fmt.Sprintf("%s is deprecated: %s", variable.Name, variable.Deprecation))
		}

	}
	values, err := LoadFrom(prepared, func(name string) (string, bool) { value, ok := resolved[name]; return value, ok })

	return values, report, err
}

// Deprecated attaches migration guidance, emitted by LoadWithReport when supplied.
func (variable Variable) Deprecated(message string) Variable {
	variable.Deprecation = message

	return variable
}

// ValidateKnownVariables rejects undeclared names within the supplied prefixes.
// Primary names, fallback names, and companion file names are all recognized.
func ValidateKnownVariables(schema Schema, source Source, prefixes ...string) error {
	if err := schema.Validate(); err != nil {
		return err
	}
	if source == nil {
		return fmt.Errorf("envschema: nil source")
	}
	known := make(map[string]bool)
	for _, variable := range schema.Variables {
		known[variable.Name] = true
		for _, name := range variable.Fallbacks {
			known[name] = true
		}
		if values, ok := policy(variable.Rule, "fileSource"); ok {
			known[values[0]] = true
		}
	}
	unknown := make([]string, 0)
	for _, name := range source.Names() {
		if known[name] {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				unknown = append(unknown, name)
				break
			}
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		return fmt.Errorf("envschema: unknown environment variables: %s", strings.Join(unknown, ", "))
	}

	return nil
}

// LoadSource parses an enumerable source, rejecting unknown names within prefixes.
// With no prefixes, unrelated environment variables are allowed.
func LoadSource(schema Schema, source Source, prefixes ...string) (Values, error) {
	if err := ValidateKnownVariables(schema, source, prefixes...); err != nil {
		return nil, err
	}

	return LoadFrom(schema, source.Lookup)
}

type resolvedInput struct {
	value   string
	present bool
}

func snapshotFiles(schema Schema, lookup LookupFunc) (Schema, LookupFunc, map[string]error) {
	hasFiles := false
	for _, variable := range schema.Variables {
		if _, configured := policy(variable.Rule, "fileSource"); configured {
			hasFiles = true
			break
		}
	}
	if !hasFiles {
		return schema, lookup, nil
	}
	cached := make(map[string]resolvedInput, len(schema.Variables))
	var failures map[string]error
	schema.Variables = append([]Variable(nil), schema.Variables...)
	for i, variable := range schema.Variables {

		value, present, err := readVariableSource(&variable.Rule, variable.Name, variable.Fallbacks, lookup)
		if err != nil {
			if failures == nil {
				failures = make(map[string]error)
			}
			failures[variable.Name] = validationError(variable.Name, "source", err)
		}
		cached[variable.Name] = resolvedInput{value: value, present: present}
		schema.Variables[i].Fallbacks = nil
		schema.Variables[i].Rule = variable.Rule.WithPolicy("fileSource")
		delete(schema.Variables[i].Rule.Policies, "fileSource")
	}
	if cached == nil {
		return schema, lookup, nil
	}
	resolved := func(name string) (string, bool) {
		if input, ok := cached[name]; ok {
			return input.value, input.present
		}

		return lookup(name)
	}

	return schema, resolved, failures
}
