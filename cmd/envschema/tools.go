package main

import (
	"flag"
	"fmt"
	"github.com/depthbomb/envschema"
	"github.com/depthbomb/envschema/generate"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func checkPackage(loaded generate.LoadedSchema, directory, prefix string, output io.Writer) error {
	generated, err := generate.Source(loaded.Schema, generate.Options{Package: "main", Type: "Config"})
	if err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("", "envschema-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	configFile := filepath.Join(temporary, "config.go")
	mainFile := filepath.Join(temporary, "main.go")
	mainSource := "package main\nimport (\"fmt\";\"os\";\"github.com/depthbomb/envschema\")\nfunc main(){ source,err:=envschema.EnvFileSource(" + strconv.Quote(directory) + ",envschema.ProcessSource());if err==nil {_,err=LoadSource(source"
	if prefix != "" {
		mainSource += "," + strconv.Quote(prefix)
	}
	mainSource += ")};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}"
	if err := os.WriteFile(configFile, generated, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(mainFile, []byte(mainSource), 0600); err != nil {
		return err
	}
	command := exec.Command("go", "run", configFile, mainFile)
	command.Dir = loaded.Directory
	command.Stdout = output
	command.Stderr = output

	return command.Run()
}

func runTool(arguments []string, output, stderr io.Writer) error {
	command := arguments[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	provider := flags.String("name", "", "provider type")
	directory := flags.String("directory", ".", "dotenv directory for check")
	prefix := flags.String("prefix", "", "reject unknown variables within this prefix")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("expected exactly one schema package")
	}
	loaded, err := generate.LoadPackage(flags.Arg(0), *provider)
	if err != nil {
		return err
	}
	switch command {
	case "check":
		absolute, err := filepath.Abs(*directory)
		if err != nil {
			return err
		}
		if err := checkPackage(loaded, absolute, *prefix, output); err != nil {
			return fmt.Errorf("configuration check failed: %w", err)
		}
		_, err = fmt.Fprintln(output, "Configuration is valid.")

		return err
	case "example":
		text, err := envschema.Example(loaded.Schema)
		if err != nil {
			return err
		}
		_, err = io.WriteString(output, text)

		return err
	case "describe":
		text, err := envschema.Documentation(loaded.Schema)
		if err != nil {
			return err
		}
		_, err = io.WriteString(output, text)

		return err
	}

	return fmt.Errorf("unknown command %q", command)
}
