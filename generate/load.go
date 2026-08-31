package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/depthbomb/envschema"
	"golang.org/x/tools/go/packages"
)

// LoadedSchema describes a discovered provider and its validated schema.
type LoadedSchema struct {
	Schema       envschema.Schema
	Directory    string
	PackagePath  string
	PackageName  string
	ProviderName string
}

type providerType struct {
	name    string
	pointer bool
}

func packageConfig(path string) (*packages.Config, string, error) {
	config := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedModule,
	}
	pattern := path
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		directory, absoluteErr := filepath.Abs(path)
		if absoluteErr != nil {
			return nil, "", fmt.Errorf("generate: resolve schema directory: %w", absoluteErr)
		}
		config.Dir = directory
		pattern = "."
	} else if err != nil && !os.IsNotExist(err) {
		return nil, "", fmt.Errorf("generate: inspect schema path: %w", err)
	}

	return config, pattern, nil
}

func packageErrors(pkg *packages.Package) error {
	if len(pkg.Errors) == 0 {
		return nil
	}

	messages := make([]string, len(pkg.Errors))
	for index, packageErr := range pkg.Errors {
		messages[index] = packageErr.Error()
	}

	return fmt.Errorf("generate: load schema package:\n%s", strings.Join(messages, "\n"))
}

func providerInterface(pkg *packages.Package) (*types.Interface, error) {
	packagePath := reflect.TypeFor[envschema.Schema]().PkgPath()
	dependency, ok := pkg.Imports[packagePath]
	if !ok || dependency.Types == nil {
		return nil, fmt.Errorf("generate: schema package must import %s", packagePath)
	}
	object := dependency.Types.Scope().Lookup("Provider")
	if object == nil {
		return nil, fmt.Errorf("generate: %s.Provider was not found", packagePath)
	}
	provider, ok := object.Type().Underlying().(*types.Interface)
	if !ok {
		return nil, fmt.Errorf("generate: %s.Provider is not an interface", packagePath)
	}
	provider.Complete()

	return provider, nil
}

func providers(pkg *packages.Package, provider *types.Interface) []providerType {
	names := pkg.Types.Scope().Names()
	sort.Strings(names)
	discovered := make([]providerType, 0)
	for _, name := range names {
		object, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || !object.Exported() {
			continue
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, ok := named.Underlying().(*types.Struct); !ok {
			continue
		}

		if types.Implements(named, provider) {
			discovered = append(discovered, providerType{name: name})

			continue
		}
		if types.Implements(types.NewPointer(named), provider) {
			discovered = append(discovered, providerType{name: name, pointer: true})
		}
	}

	return discovered
}

func selectProvider(discovered []providerType, requested string) (providerType, error) {
	if requested != "" {
		for _, provider := range discovered {
			if provider.name == requested {
				return provider, nil
			}
		}

		return providerType{}, fmt.Errorf("generate: provider %q was not found", requested)
	}

	if len(discovered) == 0 {
		return providerType{}, fmt.Errorf("generate: no exported type implements envschema.Provider")
	}
	if len(discovered) > 1 {
		names := make([]string, len(discovered))
		for index, provider := range discovered {
			names[index] = provider.name
		}

		return providerType{}, fmt.Errorf("generate: multiple schema providers found (%s); select one with -name", strings.Join(names, ", "))
	}

	return discovered[0], nil
}

func loaderSource(rootPackagePath string, packagePath string, provider providerType, output string) ([]byte, error) {
	providerExpression := "schema." + provider.name + "{}"
	if provider.pointer {
		providerExpression = "&" + providerExpression
	}

	var source bytes.Buffer
	source.WriteString("package main\n\n")
	source.WriteString("import (\n\t\"encoding/json\"\n\t\"fmt\"\n\t\"os\"\n\n")
	fmt.Fprintf(&source, "\tenvschema %s\n\tschema %s\n)\n\n", strconv.Quote(rootPackagePath), strconv.Quote(packagePath))
	source.WriteString("func main() {\n")
	fmt.Fprintf(&source, "\tvar provider envschema.Provider = %s\n", providerExpression)
	source.WriteString("\tdefinition := provider.EnvSchema()\n")
	source.WriteString("\tif err := definition.Validate(); err != nil {\n\t\tfmt.Fprintln(os.Stderr, err)\n\t\tos.Exit(1)\n\t}\n")
	source.WriteString("\tdata, err := json.Marshal(definition)\n\tif err != nil {\n\t\tfmt.Fprintln(os.Stderr, err)\n\t\tos.Exit(1)\n\t}\n")
	fmt.Fprintf(&source, "\tif err := os.WriteFile(%s, data, 0o600); err != nil {\n", strconv.Quote(output))
	source.WriteString("\t\tfmt.Fprintln(os.Stderr, err)\n\t\tos.Exit(1)\n\t}\n}\n")

	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return nil, fmt.Errorf("generate: format schema loader: %w", err)
	}

	return formatted, nil
}

func executeLoader(pkg *packages.Package, provider providerType) (envschema.Schema, error) {
	if pkg.Module == nil || pkg.Module.Dir == "" {
		return envschema.Schema{}, fmt.Errorf("generate: schema package must belong to a Go module")
	}

	temporaryDirectory, err := os.MkdirTemp(pkg.Module.Dir, ".envschema-")
	if err != nil {
		return envschema.Schema{}, fmt.Errorf("generate: create schema loader directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)

	loaderFilename := filepath.Join(temporaryDirectory, "main.go")
	outputFilename := filepath.Join(temporaryDirectory, "schema.json")
	rootPackagePath := reflect.TypeFor[envschema.Schema]().PkgPath()
	source, err := loaderSource(rootPackagePath, pkg.PkgPath, provider, outputFilename)
	if err != nil {
		return envschema.Schema{}, err
	}
	if err := os.WriteFile(loaderFilename, source, 0o600); err != nil {
		return envschema.Schema{}, fmt.Errorf("generate: write schema loader: %w", err)
	}

	command := exec.Command("go", "run", loaderFilename)
	command.Dir = pkg.Module.Dir
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return envschema.Schema{}, fmt.Errorf("generate: execute schema provider: %w", err)
	}

	data, err := os.ReadFile(outputFilename)
	if err != nil {
		return envschema.Schema{}, fmt.Errorf("generate: read loaded schema: %w", err)
	}
	var schema envschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return envschema.Schema{}, fmt.Errorf("generate: decode loaded schema: %w", err)
	}
	if err := schema.Validate(); err != nil {
		return envschema.Schema{}, err
	}

	return schema, nil
}

// LoadPackage discovers, compiles, and executes a trusted schema provider.
func LoadPackage(path string, providerName string) (LoadedSchema, error) {
	config, pattern, err := packageConfig(path)
	if err != nil {
		return LoadedSchema{}, err
	}

	loaded, err := packages.Load(config, pattern)
	if err != nil {
		return LoadedSchema{}, fmt.Errorf("generate: load schema package: %w", err)
	}
	if len(loaded) != 1 {
		return LoadedSchema{}, fmt.Errorf("generate: schema path resolved to %d packages, want 1", len(loaded))
	}
	pkg := loaded[0]
	if err := packageErrors(pkg); err != nil {
		return LoadedSchema{}, err
	}

	providerInterface, err := providerInterface(pkg)
	if err != nil {
		return LoadedSchema{}, err
	}
	provider, err := selectProvider(providers(pkg, providerInterface), providerName)
	if err != nil {
		return LoadedSchema{}, err
	}
	schema, err := executeLoader(pkg, provider)
	if err != nil {
		return LoadedSchema{}, err
	}

	directory := ""
	if len(pkg.GoFiles) != 0 {
		directory = filepath.Dir(pkg.GoFiles[0])
	}

	return LoadedSchema{
		Schema:       schema,
		Directory:    directory,
		PackagePath:  pkg.PkgPath,
		PackageName:  pkg.Name,
		ProviderName: provider.name,
	}, nil
}
