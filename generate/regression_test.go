package generate_test

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/depthbomb/envschema"
	"github.com/depthbomb/envschema/generate"
)

func testGeneratedPackage(t *testing.T, schema envschema.Schema, testSource string) {
	t.Helper()
	source, err := generate.Source(schema, generate.Options{
		Package: "config",
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "config_gen.go")
	fixture := filepath.Join(directory, "config_test.go")
	if err := os.WriteFile(filename, source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte(testSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", filename, fixture)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated package failed: %v\n%s\n%s", err, output, source)
	}
}

func TestGeneratedNumericDefaults(t *testing.T) {
	schema := envschema.Must(
		envschema.Var("UINT", envschema.Uint().DefaultTo(uint64(math.MaxUint64))),
		envschema.Var("INT", envschema.Int().DefaultTo(int64(math.MaxInt64))),
		envschema.Var("DURATION", envschema.Duration().DefaultTo(int64(1000))),
		envschema.Var("FLOAT", envschema.Float().DefaultTo(float64(2))),
		envschema.Var("ARRAY", envschema.Array(envschema.Uint()).DefaultTo([]uint64{math.MaxUint64})),
	)
	const fixture = `package config
import (
	"math"
	"testing"
	"time"
)
func TestDefaults(t *testing.T) {
	value, err := LoadFrom(func(string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.Uint != math.MaxUint64 || value.Int != math.MaxInt64 || value.Duration != time.Second || value.Float != 2 || value.Array[0] != math.MaxUint64 {
		t.Fatalf("defaults changed: %+v", value)
	}
}


`
	testGeneratedPackage(t, schema, fixture)
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	testGeneratedPackage(t, envschema.MustSchemaJSON(string(encoded)), fixture)
}

func TestGeneratedEmptySchema(t *testing.T) {
	testGeneratedPackage(t, envschema.Must(), `package config
import "testing"
func TestEmpty(t *testing.T) {
	_, err := LoadFrom(func(string) (string, bool) {
		t.Fatal("empty schema performed a lookup")

		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
}
`)
}

func TestGeneratedConstrainedValues(t *testing.T) {
	schema := envschema.Must(
		envschema.Var("LEFT", envschema.Array(envschema.Int())),
		envschema.Var("RIGHT", envschema.Array(envschema.Int())),
		envschema.Var("TEXT", envschema.String().Optional()).FallbackTo("OLD_TEXT"),
		envschema.Var("PATTERN", envschema.Regexp().Optional()),
		envschema.Var("LABELS", envschema.Map(envschema.String(), envschema.Int()).Optional()),
		envschema.Var("LEVEL", envschema.CustomNamed("github.com/depthbomb/envschema/example/config/schema", "LogLevel").Optional()).FallbackTo("OLD_LEVEL"),
	).EqualValues("LEFT", "RIGHT")
	testGeneratedPackage(t, schema, `package config
import "testing"
func TestConstrainedValues(t *testing.T) {
	values := map[string]string{
		"LEFT": "[1,2]",
		"RIGHT": "[1,2]",
	}
	lookup := func(name string) (string, bool) {
		value, exists := values[name]

		return value, exists
	}
	config, err := LoadFrom(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if config.Text != nil || config.Pattern != nil || config.Labels != nil || config.Level != nil {
		t.Fatalf("absent optionals gained values: %+v", config)
	}
	values["OLD_TEXT"] = "fallback"
	values["OLD_LEVEL"] = "debug"
	values["PATTERN"] = "^ok$"
	values["LABELS"] = "workers=3"
	config, err = LoadFrom(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if *config.Text != "fallback" || *config.Level != "debug" || !config.Pattern.MatchString("ok") || (*config.Labels)["workers"] != 3 {
		t.Fatalf("constrained conversion changed values: %+v", config)
	}
	values["RIGHT"] = "[2,3]"
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("unequal arrays satisfied equality")
	}
	values["RIGHT"] = "[1,2]"
	values["OLD_LEVEL"] = "invalid"
	if _, err := LoadFrom(lookup); err == nil {
		t.Fatal("custom validation was skipped")
	}
}
`)
}

func TestGeneratedSensitive(t *testing.T) {
	schema := envschema.Must(envschema.Var("TOKEN", envschema.Int().Sensitive()), envschema.Var("TOKENS", envschema.List(envschema.String().Sensitive())))
	testGeneratedPackage(t, schema, `package config
import "testing"
func TestSensitive(t *testing.T) {
 config,err:=LoadFrom(func(name string)(string,bool){if name=="TOKEN"{return "42",true};return "a,b",true})
 if err!=nil || config.Token.Release()!=int64(42) || config.Tokens[1].Release()!="b" {t.Fatalf("%v %v",config,err)}
}
`)
}

func TestGeneratedObjects(t *testing.T) {
	schema := envschema.Must(envschema.Var("BACKEND", envschema.Object(envschema.Field("port", envschema.Port()), envschema.Field("timeout", envschema.Duration().DefaultTo("2s")), envschema.Field("token", envschema.String().Sensitive().Optional()))))
	testGeneratedPackage(t, schema, `package config
import ("testing";"time")
func TestObject(t *testing.T) {
 config,err:=LoadFrom(func(string)(string,bool){return "{\"port\":8080,\"token\":\"abc\"}",true})
 if err!=nil || config.Backend.Port!=8080 || config.Backend.Timeout!=2*time.Second || config.Backend.Token.Release()!="abc" {t.Fatalf("%v %v",config,err)}
}
`)
}

func TestGeneratedGroups(t *testing.T) {
	fragment := envschema.Must(envschema.Var("PORT", envschema.Port().DefaultTo(8080)))
	schema := envschema.Must().WithGroup("Primary", "PRIMARY_", fragment).WithGroup("Replica", "REPLICA_", fragment)
	testGeneratedPackage(t, schema, `package config
import "testing"
func TestGroups(t *testing.T) {
 config,err:=LoadFrom(func(string)(string,bool){return "",false})
 if err!=nil || config.Primary.Port!=8080 || config.Replica.Port!=8080 {t.Fatalf("%v %v",config,err)}
}
`)
}

func TestGeneratedAggregatedErrors(t *testing.T) {
	schema := envschema.Must(envschema.Var("A", envschema.Int()), envschema.Var("B", envschema.Boolean()))
	testGeneratedPackage(t, schema, `package config
import ("testing";"errors";"github.com/depthbomb/envschema")
func TestErrors(t *testing.T) {
 _,err:=LoadFrom(func(string)(string,bool){return "bad",true})
 var failures *envschema.ValidationErrors
 if !errors.As(err,&failures) || len(failures.Issues)!=2 || failures.Issues[1].Path!="B" {t.Fatalf("%v",err)}
}
`)
}

func TestGeneratedFeatureComposition(t *testing.T) {
	fragment := envschema.Must(
		envschema.Var("MODE", envschema.OneOf("local", "production").DefaultTo("production")),
		envschema.Var("URL", envschema.URL().QueryParameter("timeout", envschema.Int().PositiveOnly())).FallbackTo("OLD_URL").DescribedAs("Service URL"),
		envschema.Var("TOKEN", envschema.String().Sensitive().ExplicitInput().FromFile("TOKEN_FILE", envschema.PreferFile)).Deprecated("rotate regularly"),
		envschema.Var("UINT", envschema.Uint().AtMostUint64(18446744073709551614).DefaultTo(uint64(18446744073709551614))),
		envschema.Var("AMOUNT", envschema.Decimal().WithPrecision(4).WithScale(2).MultipleOfDecimal("0.01").DefaultTo("12.34")),
		envschema.Var("REGION", envschema.String().DefaultTo("a")),
		envschema.Var("REGIONS", envschema.List(envschema.String()).DefaultTo("a,b")),
		envschema.Var("REGIONS_COPY", envschema.List(envschema.String()).DefaultTo("a,b,c")),
		envschema.Var("DISABLED", envschema.Map(envschema.String(), envschema.Int()).AllowedKeys("c").RequiredKeys("c").UniqueKeys().DefaultTo("c=1")),
		envschema.Var("SUBNETS", envschema.List(envschema.CIDR()).NonOverlapping().SubnetsOf("10.0.0.0/8").DefaultTo("10.0.0.0/24,10.1.0.0/24")),
		envschema.Var("OBJECTS", envschema.Array(envschema.Object(envschema.Field("items", envschema.List(envschema.Int())), envschema.Field("tag", envschema.String().Optional())))),
	).ValidateWhen("MODE", "production", "URL", envschema.URL().HTTPSOnly()).MemberOf("REGION", "REGIONS").DisjointWith("REGIONS", "DISABLED").SubsetOf("REGIONS", "REGIONS_COPY")
	schema := envschema.Must().WithGroup("Service", "APP_", fragment)
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []envschema.Schema{schema, envschema.MustSchemaJSON(string(encoded))} {
		testGeneratedPackage(t, candidate, `package config
import (
 "testing"
 "os"
 "path/filepath"
 "strings"
 "github.com/depthbomb/envschema"
)
func TestComposition(t *testing.T) {
 filename:=filepath.Join(t.TempDir(),"token")
 if err:=os.WriteFile(filename,[]byte("secret-value"),0600);err!=nil{t.Fatal(err)}
 input:=envschema.MapSource{Values:map[string]string{
  "APP_OLD_URL":"https://host?timeout=2",
  "APP_TOKEN_FILE":filename,
  "APP_OBJECTS":"[{\"items\":\"1,2\"}]",
 },Label:"test"}
 config,report,err:=LoadWithReport(input)
 if err!=nil{t.Fatal(err)}
 if config.Service.Token.Release()!="secret-value" || !report.Origins["APP_TOKEN"].File || len(report.Notices)!=2 || config.Service.Uint!=uint64(18446744073709551614) || config.Service.Objects[0].Items[1]!=2 || config.Service.Objects[0].Tag!=nil {t.Fatalf("%v %+v",config,report)}
 if _,err:=LoadSource(input,"APP_");err!=nil{t.Fatal(err)}
 input.Values["APP_TYPO"]="x"
 if _,err:=LoadSource(input,"APP_");err==nil{t.Fatal("unknown input accepted")}
 delete(input.Values,"APP_TYPO")
 input.Values["APP_OLD_URL"]="http://host?timeout=2"
 if _,err:=LoadFrom(input.Lookup);err==nil{t.Fatal("conditional rule skipped")}
 input.Values["APP_OLD_URL"]="https://host?timeout=0"
 if _,err:=LoadFrom(input.Lookup);err==nil || !strings.Contains(err.Error(),"query.timeout"){t.Fatalf("query rule skipped: %v",err)}
}
`)
	}
}
