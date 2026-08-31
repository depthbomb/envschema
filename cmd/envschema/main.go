package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/depthbomb/envschema/generate"
)

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: envschema generate [options] schema-package")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Options:")
	fmt.Fprintln(writer, "  -name string      provider type when the package contains more than one")
	fmt.Fprintln(writer, "  -target string    generated package directory (default: schema parent)")
	fmt.Fprintln(writer, "  -output string    generated filename (default: config_gen.go)")
	fmt.Fprintln(writer, "  -package string   generated package name (default: target directory name)")
	fmt.Fprintln(writer, "  -type string      generated configuration type (default: Config)")
}

func packageName(directory string) string {
	name := filepath.Base(filepath.Clean(directory))
	var builder strings.Builder
	for _, character := range name {
		if unicode.IsLetter(character) || character == '_' || builder.Len() > 0 && unicode.IsDigit(character) {
			builder.WriteRune(character)
		}
	}

	return builder.String()
}

func run(arguments []string, stderr io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "generate" {
		usage(stderr)

		return fmt.Errorf("expected the generate command")
	}

	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	providerName := flags.String("name", "", "provider type")
	target := flags.String("target", "", "generated package directory")
	output := flags.String("output", "config_gen.go", "generated filename")
	packageFlag := flags.String("package", "", "generated package name")
	typeName := flags.String("type", "Config", "generated configuration type")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("expected exactly one schema package")
	}

	loaded, err := generate.LoadPackage(flags.Arg(0), *providerName)
	if err != nil {
		return err
	}
	targetDirectory := *target
	if targetDirectory == "" {
		targetDirectory = filepath.Dir(loaded.Directory)
	}
	absoluteTarget, err := filepath.Abs(targetDirectory)
	if err != nil {
		return fmt.Errorf("resolve target directory: %w", err)
	}
	packageValue := *packageFlag
	if packageValue == "" {
		packageValue = packageName(absoluteTarget)
	}
	outputFilename := *output
	if !filepath.IsAbs(outputFilename) {
		outputFilename = filepath.Join(absoluteTarget, outputFilename)
	}

	options := generate.Options{Package: packageValue, Type: *typeName}
	if err := generate.File(outputFilename, loaded.Schema, options); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "envschema: %v\n", err)
		os.Exit(1)
	}
}
