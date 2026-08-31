package envschema

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type envFileResult struct {
	contents []byte
	path     string
	err      error
}

func isEnvNameCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '_' || character == '.' || character == '-'
}

func skipHorizontalSpace(contents []byte, index int) int {
	for index < len(contents) && (contents[index] == ' ' || contents[index] == '\t' || contents[index] == '\r') {
		index++
	}

	return index
}

func parseQuotedEnvValue(contents []byte, index int, line *int) (string, int, error) {
	quote := contents[index]
	startLine := *line

	index++

	var value strings.Builder

	for index < len(contents) {
		character := contents[index]
		if character == quote {
			return value.String(), index + 1, nil
		}
		if character == '\n' {
			*line = *line + 1
		}

		if quote == '"' && character == '\\' && index+1 < len(contents) {
			index++
			switch contents[index] {
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case '"', '\\':
				value.WriteByte(contents[index])
			default:
				value.WriteByte('\\')
				value.WriteByte(contents[index])
			}
			index++
			continue
		}
		value.WriteByte(character)
		index++
	}

	return "", index, fmt.Errorf("line %d: unterminated quoted value", startLine)
}

func parseUnquotedEnvValue(contents []byte, index int) (string, int) {
	start := index
	for index < len(contents) && contents[index] != '\n' {
		if contents[index] == '#' && (index == start || contents[index-1] == ' ' || contents[index-1] == '\t') {
			break
		}
		index++
	}

	end := index
	for end > start && (contents[end-1] == ' ' || contents[end-1] == '\t' || contents[end-1] == '\r') {
		end--
	}

	for index < len(contents) && contents[index] != '\n' {
		index++
	}

	return string(contents[start:end]), index
}

func parseEnvFileInto(contents []byte, values map[string]string) error {
	index := 0
	line := 1
	if len(contents) >= 3 && string(contents[:3]) == "\xef\xbb\xbf" {
		index = 3
	}
	for index < len(contents) {
		index = skipHorizontalSpace(contents, index)
		if index >= len(contents) {
			break
		}
		if contents[index] == '\n' {
			index++
			line++

			continue
		}
		if contents[index] == '#' {
			for index < len(contents) && contents[index] != '\n' {
				index++
			}

			continue
		}
		if len(contents)-index >= len("export") && string(contents[index:index+len("export")]) == "export" {
			afterExport := index + len("export")
			if afterExport < len(contents) && (contents[afterExport] == ' ' || contents[afterExport] == '\t') {
				index = skipHorizontalSpace(contents, afterExport)
			}
		}

		nameStart := index

		for index < len(contents) && isEnvNameCharacter(contents[index]) {
			index++
		}

		if index == nameStart {
			return fmt.Errorf("line %d: expected an environment variable name", line)
		}
		name := string(contents[nameStart:index])

		index = skipHorizontalSpace(contents, index)
		if index >= len(contents) || contents[index] != '=' {
			return fmt.Errorf("line %d: expected '=' after %s", line, name)
		}
		index = skipHorizontalSpace(contents, index+1)

		value := ""
		if index < len(contents) && (contents[index] == '\'' || contents[index] == '"') {
			var err error
			value, index, err = parseQuotedEnvValue(contents, index, &line)
			if err != nil {
				return err
			}
			index = skipHorizontalSpace(contents, index)
			if index < len(contents) && contents[index] != '\n' && contents[index] != '#' {
				return fmt.Errorf("line %d: unexpected content after quoted value", line)
			}

			for index < len(contents) && contents[index] != '\n' {
				index++
			}
		} else {
			value, index = parseUnquotedEnvValue(contents, index)
		}

		values[name] = value
	}

	return nil
}

func parseEnvFile(contents []byte) (map[string]string, error) {
	values := make(map[string]string)
	if err := parseEnvFileInto(contents, values); err != nil {
		return nil, err
	}

	return values, nil
}

func lookupEnvFilesFrom(directory string, process LookupFunc) (LookupFunc, error) {
	filenames := []string{".env", ".env.local"}
	results := make([]envFileResult, len(filenames))

	var wait sync.WaitGroup
	wait.Add(len(filenames))

	for index, filename := range filenames {
		results[index].path = filepath.Join(directory, filename)
		go func(result *envFileResult) {
			defer wait.Done()

			result.contents, result.err = os.ReadFile(result.path)
		}(&results[index])
	}

	wait.Wait()

	values := make(map[string]string)
	for _, result := range results {
		if result.err != nil {
			if os.IsNotExist(result.err) {
				continue
			}

			return nil, fmt.Errorf("envschema: load %s: %w", result.path, result.err)
		}
		if err := parseEnvFileInto(result.contents, values); err != nil {
			return nil, fmt.Errorf("envschema: load %s: %w", result.path, err)
		}
	}

	return func(name string) (string, bool) {
		if value, exists := process(name); exists {
			return value, true
		}

		value, exists := values[name]

		return value, exists
	}, nil
}

// LookupEnvFiles returns a lookup that combines the process environment with
// .env files alongside the running executable. Later files override earlier
// files, while process environment variables override every file.
func LookupEnvFiles() (LookupFunc, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("envschema: locate executable: %w", err)
	}

	return lookupEnvFilesFrom(filepath.Dir(executable), lookupOS)
}
