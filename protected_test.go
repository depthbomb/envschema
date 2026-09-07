package envschema_test

import (
	"github.com/depthbomb/envschema"
	"testing"
)

type protectedText string

func (value *protectedText) UnmarshalText(text []byte) error {
	*value = protectedText(text)

	return nil
}

func TestProtectedReaderMismatch(t *testing.T) {
	_, _, err := envschema.ReadText[protectedText](envschema.String().Sensitive(), "TOKEN", func(string) (string, bool) {
		return "private-value", true
	})
	if err == nil {
		t.Fatal("unprotected reader accepted a sensitive value")
	}
}
