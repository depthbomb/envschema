package schema

import (
	"fmt"
	"time"

	"github.com/depthbomb/envschema"
)

type Environment struct{}

type LogLevel string

func (level *LogLevel) UnmarshalText(value []byte) error {
	switch string(value) {
	case "debug", "info", "warn", "error":
		*level = LogLevel(value)

		return nil
	default:
		return fmt.Errorf("unsupported log level %q", value)
	}
}

func (Environment) EnvSchema() envschema.Schema {
	return envschema.Must(
		envschema.Var("DATABASE_URL", envschema.URL()),
		envschema.Var("PORT", envschema.Port().DefaultTo(8080)),
		envschema.Var("DEBUG", envschema.Boolean().Optional()),
		envschema.Var("REQUEST_TIMEOUT", envschema.Duration().DefaultTo(5*time.Second)),
		envschema.Var("ALLOWED_HOSTS", envschema.List(envschema.Host()).UniqueItems()),
		envschema.Var("API_TOKEN", envschema.Secret()),
		envschema.Var("LOG_LEVEL", envschema.Custom[LogLevel]().DefaultTo("info")),
	)
}
