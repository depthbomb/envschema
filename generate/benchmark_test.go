package generate_test

import (
	"fmt"
	"testing"

	"github.com/depthbomb/envschema"
	"github.com/depthbomb/envschema/generate"
)

var benchmarkSource []byte

func generatorSchema(size int) envschema.Schema {
	variables := make([]envschema.Variable, 0, size)
	for index := range size {
		name := fmt.Sprintf("VALUE_%03d", index)
		rule := envschema.String()
		if index%3 == 0 {
			rule = envschema.List(envschema.Int()).UniqueItems()
		}
		variables = append(variables, envschema.Var(name, rule))
	}

	return envschema.Must(variables...)
}

func benchmarkGenerateSource(b *testing.B, size int) {
	schema := generatorSchema(size)
	options := generate.Options{Package: "config", Type: "Config"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		source, err := generate.Source(schema, options)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSource = source
	}
}

func BenchmarkSource10(b *testing.B) {
	benchmarkGenerateSource(b, 10)
}

func BenchmarkSource250(b *testing.B) {
	benchmarkGenerateSource(b, 250)
}

func BenchmarkLoadPackage(b *testing.B) {
	for range b.N {
		if _, err := generate.LoadPackage("../example/config/schema", ""); err != nil {
			b.Fatal(err)
		}
	}
}
