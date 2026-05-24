package cli

import (
	"flag"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

const defaultConfigPath = "/etc/mesh-checker/config.json"

// addConfigFlag registers --config on fs and returns the bound pointer.
func addConfigFlag(fs *flag.FlagSet) *string {
	return fs.String("config", defaultConfigPath, "path to config.json")
}

// loadAndMutate is the canonical edit-config workflow: Load, run fn, Save.
// File permission check (CheckMode) is skipped here because mutating
// subcommands also run on freshly-created config files during bootstrap.
func loadAndMutate(path string, fn func(*config.Config) error) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return config.Save(path, cfg)
}
