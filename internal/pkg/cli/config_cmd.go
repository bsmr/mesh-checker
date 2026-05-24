package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func init() {
	register("config", "configuration helpers: validate", runConfig)
}

func runConfig(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("config: missing subcommand (validate)")
	}
	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("config: unknown subcommand %q", args[0])
	}
}

func runConfigValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	warnings, err := config.ValidateWithWarnings(cfg)
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "OK")
	return nil
}
