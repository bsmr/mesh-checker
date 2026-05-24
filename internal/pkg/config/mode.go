package config

import (
	"fmt"
	"os"
)

// CheckMode verifies the file is owner-readable only (mode == 0600).
// Returns a descriptive error otherwise.
func CheckMode(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("config: %s has insecure mode %o; expected 0600", path, perm)
	}
	return nil
}
