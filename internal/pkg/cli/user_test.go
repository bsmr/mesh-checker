package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

func TestUserAddStoresBcryptHash(t *testing.T) {
	path := writeMinimalConfig(t)
	passwordReader = func() (string, error) { return "s3cret!", nil }
	t.Cleanup(func() { passwordReader = readPasswordFromTerminal })

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"user", "add", "admin", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatalf("user add: %v", err)
	}
	cfg, _ := config.Load(path)
	if len(cfg.UI.Users) != 1 {
		t.Fatalf("users = %v", cfg.UI.Users)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.UI.Users[0].PasswordHash), []byte("s3cret!")); err != nil {
		t.Errorf("bcrypt verify failed: %v", err)
	}
}

func TestUserRemoveDropsUser(t *testing.T) {
	path := writeMinimalConfig(t)
	passwordReader = func() (string, error) { return "x", nil }
	t.Cleanup(func() { passwordReader = readPasswordFromTerminal })
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"user", "add", "admin", "--config", path}, &stdout, &stderr)
	if err := Run(context.Background(), []string{"user", "remove", "admin", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(path)
	if len(cfg.UI.Users) != 0 {
		t.Errorf("expected 0 users, got %d", len(cfg.UI.Users))
	}
	if !strings.Contains(stdout.String(), "removed") {
		t.Errorf("expected 'removed' in output, got %q", stdout.String())
	}
}
