package envschema

import (
	"fmt"
	"os"
)

type FileConflict string

const (
	FileConflictError FileConflict = "error"
	PreferValue       FileConflict = "value"
	PreferFile        FileConflict = "file"
)

func readVariableSource(rule Rule, name string, fallbacks []string, lookup LookupFunc) (string, bool, error) {
	value, exists := lookup(name)
	for _, fallback := range fallbacks {
		if exists {
			break
		}
		value, exists = lookup(fallback)
	}
	source, configured := policy(rule, "fileSource")
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
