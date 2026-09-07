package envschema

import (
	"errors"
	"strings"
)

// ValidationError identifies a failed value or constraint without requiring message parsing.
type ValidationError struct {
	Code  string
	Path  string
	Cause error
}

// ValidationErrors contains independent failures in schema traversal order.
type ValidationErrors struct {
	Issues []*ValidationError
}

func validationError(path, code string, err error) error {
	if err == nil {
		return nil
	}
	var issue *ValidationError
	var many *ValidationErrors
	if errors.As(err, &issue) || errors.As(err, &many) {
		return err
	}

	return &ValidationError{Code: code, Path: path, Cause: err}
}

func (issue *ValidationError) Error() string {
	return issue.Cause.Error()
}

func (issue *ValidationError) Unwrap() error {
	return issue.Cause
}

func (failures *ValidationErrors) Error() string {
	messages := make([]string, len(failures.Issues))
	for i, issue := range failures.Issues {
		messages[i] = issue.Error()
	}

	return strings.Join(messages, "; ")
}

func (failures *ValidationErrors) Unwrap() []error {
	result := make([]error, len(failures.Issues))
	for i, issue := range failures.Issues {
		result[i] = issue
	}

	return result
}

// JoinErrors combines validation failures, flattening nested collections.
// It returns nil when no failures were supplied.
func JoinErrors(failures ...error) error {
	if len(failures) == 0 {
		return nil
	}
	result := &ValidationErrors{}
	for _, err := range failures {
		if err == nil {
			continue
		}
		var many *ValidationErrors
		var issue *ValidationError
		if errors.As(err, &many) {
			result.Issues = append(result.Issues, many.Issues...)
		} else if errors.As(err, &issue) {
			result.Issues = append(result.Issues, issue)
		} else {
			result.Issues = append(result.Issues, &ValidationError{Code: "invalid", Cause: err})
		}
	}
	if len(result.Issues) == 0 {
		return nil
	}

	return result
}
