# mesh-checker 0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver mesh-checker 0.1.0 per spec `docs/superpowers/specs/2026-05-24-mesh-checker-0.1.0-design.md`: a single Linux binary that probes ICMP/TCP/UDP/HTTPS reachability between mesh peers, exposes an authenticated UI with SSE, and an mTLS inter-host API for peer-pull aggregation.

**Architecture:** Domain-oriented Go packages under `internal/pkg/`. One process (`mesh-checker serve`) hosts a scheduler-driven probe engine writing into an in-memory ringbuffer, plus three HTTP/UDP listeners (mTLS inter-host, authenticated UI, unauthenticated probe target). CLI subcommands manage JSON config, mesh PKI, and UI users.

**Tech Stack:** Go 1.26, stdlib-first (`crypto/tls`, `crypto/x509`, `encoding/json`, `net/http`, `log/slog`, `embed`); `golang.org/x/net/icmp` for ICMP, `golang.org/x/crypto/bcrypt` for passwords. No web framework, no ORM, no DB.

**Reference Spec:** `docs/superpowers/specs/2026-05-24-mesh-checker-0.1.0-design.md` — every task below maps back to a section there.

---

## File Map

```
cmd/mesh-checker/main.go                 # exists; unchanged after Phase A wiring
internal/pkg/cli/
  cli.go                                 # exists; dispatcher rewritten in Task 1
  pki.go, host.go, user.go, config_cmd.go, status.go, serve.go  # Phase A & C
internal/pkg/config/
  config.go, validate.go, mode.go        # Phase A
internal/pkg/pki/
  pki.go                                 # Phase A
internal/pkg/probe/
  probe.go                               # interface + types (Phase B)
  tcp/tcp.go, http/http.go               # Phase B
  udp/udp.go, udp/payload.go             # Phase B
  icmp/icmp.go, icmp/icmp_integration_test.go  # Phase B
internal/pkg/store/store.go              # Phase B
internal/pkg/classifier/classifier.go    # Phase B
internal/pkg/scheduler/scheduler.go      # Phase B
internal/pkg/aggregator/aggregator.go    # Phase C
internal/pkg/server/
  interhost/server.go                    # Phase C
  ui/handlers.go, login.go, session.go, sse.go  # Phase C
  ui/static/{index.html,app.js,style.css}       # Phase C
  ui/assets.go                           # Phase C (go:embed)
  probe/server.go, probe/udp_echo.go     # Phase C
internal/pkg/version/version.go          # Phase A (small)
contrib/systemd/mesh-checker.service     # Phase C
VERSION                                  # exists, contains "0.1.0"
```

Every `.go` file gets a sibling `_test.go`. Tests come **before** implementation in every task — TDD is mandatory per CLAUDE.md.

**Conventions used in this plan:**
- "Run: `go test ./internal/pkg/foo/...`" assumes you are at the repo root.
- Build: `go build -o bin/mesh-checker ./cmd/mesh-checker` (never bare `go build`).
- Commit signoff is required: `git commit -s`. Conventional Commits style: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`.
- All commits in this plan are made on branch `development-0.1.0-work`.

---

# Phase A — Foundation (Config + PKI + Admin Subcommands)

**Phase A milestone:** an admin can run `mesh-checker pki init`, `mesh-checker pki cert node-a`, `mesh-checker host add ...`, `mesh-checker user add admin`, `mesh-checker config validate` against a freshly-created `/etc/mesh-checker/config.json` (or any `--config` path), and every operation round-trips through the JSON schema. No daemon yet.

---

### Task 1: CLI dispatcher with subcommand registry

**Files:**
- Modify: `internal/pkg/cli/cli.go`
- Modify: `internal/pkg/cli/cli_test.go`

The current `Run` parses one global flag set. Replace with a subcommand dispatcher so later tasks can register handlers without touching this file again. Subcommands chosen by `args[0]`; remaining args go to the subcommand's own `flag.FlagSet`.

- [ ] **Step 1: Write the failing test**

Add to `internal/pkg/cli/cli_test.go` (replace `TestRunParsesCommaSeparatedPeers` and `TestRunReturnsErrorOnUnknownFlag` with the tests below; keep `TestSplitPeersTrimsAndFiltersEmpty` only if `splitPeers` still exists — Task 1 removes it):

```go
func TestRunWithoutSubcommandPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when no subcommand given")
	}
	if !strings.Contains(stderr.String(), "subcommand") {
		t.Errorf("expected usage to mention 'subcommand', got %q", stderr.String())
	}
}

func TestRunUnknownSubcommandReturnsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"frobnicate"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error should name the unknown subcommand, got %v", err)
	}
}

func TestRunDispatchesToRegisteredSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	register("ping", "test stub", func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
		called = true
		if len(args) != 2 || args[0] != "-n" || args[1] != "3" {
			t.Errorf("subcommand got wrong args: %v", args)
		}
		return nil
	})
	t.Cleanup(func() { delete(subcommands, "ping") })

	if err := Run(context.Background(), []string{"ping", "-n", "3"}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("subcommand handler was not invoked")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/pkg/cli/`
Expected: FAIL — undefined symbols `register`, `subcommands`, plus removed `checker.ErrNoPeers` references.

- [ ] **Step 3: Implement the dispatcher**

Replace `internal/pkg/cli/cli.go` with:

```go
// Package cli wires the mesh-checker subcommands. Run dispatches to a
// handler registered by name; handlers parse their own flags. Kept
// separate from package main so it can be tested without os.Exit.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
)

// Handler is the contract every subcommand fulfils.
type Handler func(ctx context.Context, args []string, stdout, stderr io.Writer) error

type subcommand struct {
	name, summary string
	run           Handler
}

var subcommands = map[string]subcommand{}

// register adds a subcommand; called from init() in each subcommand file.
func register(name, summary string, run Handler) {
	if _, dup := subcommands[name]; dup {
		panic("cli: duplicate subcommand " + name)
	}
	subcommands[name] = subcommand{name, summary, run}
}

// Run dispatches to the subcommand named by args[0].
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("no subcommand given")
	}
	name := args[0]
	sc, ok := subcommands[name]
	if !ok {
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", name)
	}
	return sc.run(ctx, args[1:], stdout, stderr)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mesh-checker <subcommand> [flags]")
	fmt.Fprintln(w, "subcommands:")
	names := make([]string, 0, len(subcommands))
	for n := range subcommands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-12s %s\n", n, subcommands[n].summary)
	}
}
```

Remove the obsolete `splitPeers`, the `checker` import, and the old peers-flag test cases. Update `main.go` if needed (the existing call site `cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)` is unchanged, so `cmd/mesh-checker/main.go` stays as is).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./...`
Expected: all packages PASS. `cmd/mesh-checker` has no test files (still expected).

- [ ] **Step 5: Build and commit**

```bash
go build -o bin/mesh-checker ./cmd/mesh-checker
./bin/mesh-checker || true  # prints usage + exits non-zero, both expected
git add internal/pkg/cli/cli.go internal/pkg/cli/cli_test.go
git commit -s -m "refactor: turn cli.Run into a subcommand dispatcher"
```

---

### Task 2: Version package

**Files:**
- Create: `internal/pkg/version/version.go`
- Create: `internal/pkg/version/version_test.go`

Single source of truth for the version string. Read at startup from the embedded `VERSION` file so the value cannot drift between binary and disk.

- [ ] **Step 1: Write the failing test**

```go
package version

import (
	"strings"
	"testing"
)

func TestStringMatchesEmbeddedFile(t *testing.T) {
	v := String()
	if v == "" {
		t.Fatal("version string is empty")
	}
	if strings.ContainsAny(v, " \t\r\n") {
		t.Errorf("version string has whitespace: %q", v)
	}
}
```

- [ ] **Step 2: Run to verify FAIL**

Run: `go test ./internal/pkg/version/`
Expected: build failure — package does not exist.

- [ ] **Step 3: Implement**

```go
// Package version exposes the build's semantic version, embedded from
// the repo-root VERSION file so the binary and the file cannot drift.
package version

import (
	_ "embed"
	"strings"
)

//go:embed ../../../VERSION
var versionFile string

// String returns the trimmed version, e.g. "0.1.0".
func String() string {
	return strings.TrimSpace(versionFile)
}
```

- [ ] **Step 4: Verify**

Run: `go test ./internal/pkg/version/ -v`
Expected: PASS, `TestStringMatchesEmbeddedFile`.

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/version/
git commit -s -m "feat: add version package backed by embedded VERSION file"
```

---

### Task 3: Config types and JSON round-trip

**Files:**
- Create: `internal/pkg/config/config.go`
- Create: `internal/pkg/config/config_test.go`

Types matching spec §6.1. `Load(path)` reads + JSON-unmarshals; `Save(path, cfg)` writes atomically (`os.WriteFile` to `path+".tmp"` then `os.Rename`).

- [ ] **Step 1: Write the failing test**

```go
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	in := &Config{
		SchemaVersion: 1,
		Host:          HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI: PKIPaths{
			CACertPath:   "/etc/mesh-checker/pki/ca.crt",
			CAKeyPath:    "/etc/mesh-checker/pki/ca.key",
			HostCertPath: "/etc/mesh-checker/pki/node-a.crt",
			HostKeyPath:  "/etc/mesh-checker/pki/node-a.key",
		},
		Listeners: Listeners{
			InterHost: ListenerAddr{Addr: "0.0.0.0:8443"},
			UI:        ListenerAddr{Addr: "0.0.0.0:8080"},
			Probe:     ProbeListener{HTTPAddr: "0.0.0.0:7080", UDPAddr: "0.0.0.0:7081"},
		},
		Probe: ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", // 32 bytes
		},
		Peers: []Peer{{Name: "node-b", Addr: "10.0.0.2", Checks: []string{"icmp", "tcp", "udp", "https"}, TCPPort: 8443, UDPPort: 7081, HTTPSURL: "https://10.0.0.2:8080/probe"}},
		UI: UI{
			Users:             []User{{Name: "admin", PasswordHash: "$2b$12$abcdefghijklmnopqrstuv"}},
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 28800,
		},
		Log: Log{Level: "info"},
	}

	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{SchemaVersion: 1, Host: HostInfo{Name: "x"}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	// .tmp must not linger
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned up: err=%v", err)
	}
}

func TestLoadMissingFileReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error loading missing file")
	}
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/config/` — expect build failure (types missing).

- [ ] **Step 3: Implement**

```go
// Package config defines the on-disk JSON schema and provides atomic
// load/save plus permission validation (see mode.go) and structural
// validation (see validate.go).
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

const SchemaVersion = 1

type Config struct {
	SchemaVersion int           `json:"schemaVersion"`
	Host          HostInfo      `json:"host"`
	PKI           PKIPaths      `json:"pki"`
	Listeners     Listeners     `json:"listeners"`
	Probe         ProbeSettings `json:"probe"`
	Peers         []Peer        `json:"peers"`
	UI            UI            `json:"ui"`
	Log           Log           `json:"log"`
}

type HostInfo struct {
	Name          string `json:"name"`
	AdvertiseAddr string `json:"advertiseAddr"`
}

type PKIPaths struct {
	CACertPath   string `json:"caCertPath"`
	CAKeyPath    string `json:"caKeyPath"`
	HostCertPath string `json:"hostCertPath"`
	HostKeyPath  string `json:"hostKeyPath"`
}

type Listeners struct {
	InterHost ListenerAddr  `json:"interhost"`
	UI        ListenerAddr  `json:"ui"`
	Probe     ProbeListener `json:"probe"`
}

type ListenerAddr struct {
	Addr string `json:"addr"`
}

type ProbeListener struct {
	HTTPAddr string `json:"httpAddr"`
	UDPAddr  string `json:"udpAddr"`
}

type ProbeSettings struct {
	IntervalSeconds  int    `json:"intervalSeconds"`
	JitterPercent    int    `json:"jitterPercent"`
	TimeoutSeconds   int    `json:"timeoutSeconds"`
	FailureWindow    int    `json:"failureWindow"`
	FailureThreshold int    `json:"failureThreshold"`
	RingbufferSize   int    `json:"ringbufferSize"`
	UDPSharedSecret  string `json:"udpSharedSecret"`
}

type Peer struct {
	Name     string   `json:"name"`
	Addr     string   `json:"addr"`
	Checks   []string `json:"checks"`
	TCPPort  int      `json:"tcpPort,omitempty"`
	UDPPort  int      `json:"udpPort,omitempty"`
	HTTPSURL string   `json:"httpsURL,omitempty"`
}

type UI struct {
	Users             []User `json:"users"`
	SessionSecret     string `json:"sessionSecret"`
	SessionTTLSeconds int    `json:"sessionTTLSeconds"`
}

type User struct {
	Name         string `json:"name"`
	PasswordHash string `json:"passwordHash"`
}

type Log struct {
	Level string `json:"level"`
}

// Load reads and JSON-decodes a config file. Permission and structural
// checks are separate (see mode.Check and Validate).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := &Config{}
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically: marshal -> temp file -> rename.
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

func bytesReader(b []byte) *bytesReaderType { return &bytesReaderType{b: b} }

type bytesReaderType struct {
	b []byte
	i int
}

func (r *bytesReaderType) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

var errEOF = fmt.Errorf("EOF")
```

Replace the custom `bytesReader` with `bytes.NewReader` — keeping it tiny and idiomatic:

After writing the above, simplify by removing `bytesReader*` and `errEOF`, and import `bytes`:

```go
import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// in Load:
dec := json.NewDecoder(bytes.NewReader(b))
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/config/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/config/
git commit -s -m "feat: add config types with atomic load/save"
```

---

### Task 4: Config file-mode enforcement

**Files:**
- Create: `internal/pkg/config/mode.go`
- Create: `internal/pkg/config/mode_test.go`

The daemon refuses to start if `/etc/mesh-checker/config.json` is not `0600`. Same applies to PKI private keys later.

- [ ] **Step 1: Failing test**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckModeAcceptsTight(t *testing.T) {
	p := writeFile(t, 0o600)
	if err := CheckMode(p); err != nil {
		t.Errorf("0600 should be accepted, got %v", err)
	}
}

func TestCheckModeRejectsLoose(t *testing.T) {
	for _, m := range []os.FileMode{0o644, 0o640, 0o660, 0o666} {
		p := writeFile(t, m)
		if err := CheckMode(p); err == nil {
			t.Errorf("mode %o should be rejected", m)
		}
	}
}

func writeFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours umask; explicitly Chmod to the requested mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/config/` — `CheckMode` undefined.

- [ ] **Step 3: Implement**

```go
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
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/config/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/config/mode.go internal/pkg/config/mode_test.go
git commit -s -m "feat(config): enforce 0600 permissions"
```

---

### Task 5: Config schema validation

**Files:**
- Create: `internal/pkg/config/validate.go`
- Create: `internal/pkg/config/validate_test.go`

Enforce spec §6.2 rules.

- [ ] **Step 1: Failing tests**

```go
package config

import (
	"strings"
	"testing"
)

func validCfg() *Config {
	return &Config{
		SchemaVersion: 1,
		Host:          HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI:           PKIPaths{CACertPath: "x", CAKeyPath: "y", HostCertPath: "z", HostKeyPath: "k"},
		Listeners: Listeners{
			InterHost: ListenerAddr{Addr: "0.0.0.0:8443"},
			UI:        ListenerAddr{Addr: "0.0.0.0:8080"},
			Probe:     ProbeListener{HTTPAddr: "0.0.0.0:7080", UDPAddr: "0.0.0.0:7081"},
		},
		Probe: ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		},
		Peers: []Peer{{Name: "node-b", Addr: "10.0.0.2", Checks: []string{"tcp"}}},
		UI: UI{
			Users:             []User{{Name: "admin", PasswordHash: "$2b$12$x"}},
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 3600,
		},
		Log: Log{Level: "info"},
	}
}

func TestValidateAcceptsGoodConfig(t *testing.T) {
	if err := Validate(validCfg()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateRejectsWrongSchemaVersion(t *testing.T) {
	c := validCfg()
	c.SchemaVersion = 2
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("want schemaVersion error, got %v", err)
	}
}

func TestValidateRejectsDuplicatePeerNames(t *testing.T) {
	c := validCfg()
	c.Peers = append(c.Peers, Peer{Name: "node-b", Addr: "10.0.0.3", Checks: []string{"tcp"}})
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate error, got %v", err)
	}
}

func TestValidateRejectsBadSecretLength(t *testing.T) {
	c := validCfg()
	c.Probe.UDPSharedSecret = "AAA=" // 2 bytes
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "udpSharedSecret") {
		t.Errorf("want udpSharedSecret error, got %v", err)
	}
}

func TestValidateRejectsThresholdGreaterThanWindow(t *testing.T) {
	c := validCfg()
	c.Probe.FailureThreshold = 99
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "failureThreshold") {
		t.Errorf("want threshold error, got %v", err)
	}
}

func TestValidateWarnsOnUnknownCheck(t *testing.T) {
	c := validCfg()
	c.Peers[0].Checks = []string{"tcp", "smtp"}
	warnings, err := ValidateWithWarnings(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "smtp") {
		t.Errorf("expected warning about 'smtp', got %v", warnings)
	}
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/config/`

- [ ] **Step 3: Implement**

```go
package config

import (
	"encoding/base64"
	"fmt"
)

var validChecks = map[string]bool{"icmp": true, "tcp": true, "udp": true, "https": true}

// Validate returns the first hard error; warnings are silently dropped.
// Use ValidateWithWarnings to also collect non-fatal warnings.
func Validate(c *Config) error {
	_, err := ValidateWithWarnings(c)
	return err
}

// ValidateWithWarnings checks structural rules and returns
// (warnings, hardError). On hard error, warnings may be partial.
func ValidateWithWarnings(c *Config) ([]string, error) {
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("config: schemaVersion %d unsupported (want %d)", c.SchemaVersion, SchemaVersion)
	}
	if c.Host.Name == "" {
		return nil, fmt.Errorf("config: host.name is required")
	}
	if c.Probe.FailureThreshold > c.Probe.FailureWindow {
		return nil, fmt.Errorf("config: probe.failureThreshold (%d) must be <= failureWindow (%d)",
			c.Probe.FailureThreshold, c.Probe.FailureWindow)
	}
	if err := checkSecret("probe.udpSharedSecret", c.Probe.UDPSharedSecret); err != nil {
		return nil, err
	}
	if err := checkSecret("ui.sessionSecret", c.UI.SessionSecret); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var warnings []string
	for _, p := range c.Peers {
		if seen[p.Name] {
			return warnings, fmt.Errorf("config: duplicate peer name %q", p.Name)
		}
		seen[p.Name] = true
		for _, ch := range p.Checks {
			if !validChecks[ch] {
				warnings = append(warnings, fmt.Sprintf("peer %q: unknown check %q (ignored)", p.Name, ch))
			}
		}
	}
	return warnings, nil
}

func checkSecret(field, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("config: %s is not valid base64: %w", field, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("config: %s must decode to 32 bytes, got %d", field, len(raw))
	}
	return nil
}
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/config/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/config/validate.go internal/pkg/config/validate_test.go
git commit -s -m "feat(config): add schema validation with warnings"
```

---

### Task 6: PKI — CA and host cert generation

**Files:**
- Create: `internal/pkg/pki/pki.go`
- Create: `internal/pkg/pki/pki_test.go`

Generate an Ed25519-based Mesh CA and host certificates with Server+Client EKU. All in-memory APIs; file I/O happens in the `pki` subcommand (Task 7).

- [ ] **Step 1: Failing tests**

```go
package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateCAProducesValidSelfSignedCert(t *testing.T) {
	ca, err := GenerateCA("mesh-checker test CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert not marked IsCA")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert missing KeyUsageCertSign")
	}
	if ca.PrivateKey == nil {
		t.Error("CA private key is nil")
	}
}

func TestGenerateHostCertSignedByCA(t *testing.T) {
	ca, err := GenerateCA("CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	host, err := GenerateHostCert(ca, "node-a", []string{"10.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := host.Cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("host cert did not verify against CA: %v", err)
	}
	if host.Cert.Subject.CommonName != "node-a" {
		t.Errorf("CN = %q, want node-a", host.Cert.Subject.CommonName)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	ca, _ := GenerateCA("CA", 24*time.Hour)
	certPEM, keyPEM, err := Encode(ca)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if back.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Error("serial mismatch after round-trip")
	}
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/pki/`

- [ ] **Step 3: Implement**

```go
// Package pki creates and loads the mesh-checker mTLS PKI material:
// one Ed25519 Mesh CA and one host cert per node, with Server+Client EKU.
// No file I/O lives here; encoding is PEM-in-memory.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Material is a cert + the private key that signs/owns it.
type Material struct {
	Cert       *x509.Certificate
	DERCert    []byte
	PrivateKey ed25519.PrivateKey
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// GenerateCA returns a self-signed CA valid for the given lifetime.
func GenerateCA(commonName string, lifetime time.Duration) (*Material, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: cert, DERCert: der, PrivateKey: priv}, nil
}

// GenerateHostCert signs a host cert with Server+Client EKU under ca.
// hostName becomes the CN; sans are added as DNS or IP SANs.
func GenerateHostCert(ca *Material, hostName string, sans []string, lifetime time.Duration) (*Material, error) {
	if ca == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: ca material missing private key")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostName},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: cert, DERCert: der, PrivateKey: priv}, nil
}

// Encode returns PEM-encoded cert and private key.
func Encode(m *Material) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.DERCert})
	keyDER, err := x509.MarshalPKCS8PrivateKey(m.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Decode parses PEM cert + key back into Material.
func Decode(certPEM, keyPEM []byte) (*Material, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pki: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	m := &Material{Cert: cert, DERCert: cb.Bytes}
	if keyPEM != nil {
		kb, _ := pem.Decode(keyPEM)
		if kb == nil || kb.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("pki: invalid key PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, err
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pki: key is not ed25519")
		}
		m.PrivateKey = edKey
	}
	return m, nil
}

// LoadCertOnly reads only the cert PEM (no key) — used by the daemon
// to load the CA bundle without touching the CA private key.
func LoadCertOnly(certPEM []byte) (*Material, error) {
	return Decode(certPEM, nil)
}
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/pki/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/pki/
git commit -s -m "feat(pki): generate ed25519 mesh CA and host certificates"
```

---

### Task 7: CLI subcommand `pki init` and `pki cert`

**Files:**
- Create: `internal/pkg/cli/pki.go`
- Create: `internal/pkg/cli/pki_test.go`

Wraps Task 6 with filesystem persistence. Writes go to paths from the config; if no config exists yet, the user provides explicit `--ca-cert` / `--ca-key` / `--out-cert` / `--out-key` flags.

- [ ] **Step 1: Failing tests**

```go
package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPKIInitWritesCAFilesWithStrictMode(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr)
	if err != nil {
		t.Fatalf("pki init failed: %v (stderr=%q)", err, stderr.String())
	}
	st, err := os.Stat(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestPKICertWritesHostMaterial(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	hostCert := filepath.Join(dir, "node-a.crt")
	hostKey := filepath.Join(dir, "node-a.key")

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(),
		[]string{"pki", "cert", "node-a",
			"--ca-cert", caCert, "--ca-key", caKey,
			"--out-cert", hostCert, "--out-key", hostKey,
			"--san", "10.0.0.1"},
		&stdout, &stderr); err != nil {
		t.Fatalf("pki cert failed: %v (stderr=%q)", err, stderr.String())
	}
	if _, err := os.Stat(hostCert); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(hostKey); st.Mode().Perm() != 0o600 {
		t.Errorf("host key mode = %o", st.Mode().Perm())
	}
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/cli/`

- [ ] **Step 3: Implement**

```go
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func init() {
	register("pki", "PKI helpers: 'pki init' or 'pki cert <host>'", runPKI)
}

func runPKI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("pki: missing subcommand (init|cert)")
	}
	switch args[0] {
	case "init":
		return runPKIInit(args[1:], stdout, stderr)
	case "cert":
		return runPKICert(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("pki: unknown subcommand %q", args[0])
	}
}

func runPKIInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caCert := fs.String("ca-cert", "", "output path for the CA certificate (required)")
	caKey := fs.String("ca-key", "", "output path for the CA private key (required)")
	cn := fs.String("cn", "mesh-checker CA", "common name for the CA")
	lifetime := fs.Duration("lifetime", 10*365*24*time.Hour, "CA validity duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caCert == "" || *caKey == "" {
		return errors.New("pki init: --ca-cert and --ca-key are required")
	}
	ca, err := pki.GenerateCA(*cn, *lifetime)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := pki.Encode(ca)
	if err != nil {
		return err
	}
	if err := writeStrict(*caCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeStrict(*caKey, keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s and %s\n", *caCert, *caKey)
	return nil
}

func runPKICert(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pki cert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caCert := fs.String("ca-cert", "", "path to CA certificate (required)")
	caKey := fs.String("ca-key", "", "path to CA private key (required)")
	outCert := fs.String("out-cert", "", "output path for host certificate (required)")
	outKey := fs.String("out-key", "", "output path for host private key (required)")
	var sans multiString
	fs.Var(&sans, "san", "additional SAN (DNS or IP). May be repeated.")
	lifetime := fs.Duration("lifetime", 365*24*time.Hour, "host cert validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("pki cert: exactly one positional argument required (hostName)")
	}
	hostName := rest[0]
	if *caCert == "" || *caKey == "" || *outCert == "" || *outKey == "" {
		return errors.New("pki cert: --ca-cert, --ca-key, --out-cert, --out-key are required")
	}
	caCertPEM, err := os.ReadFile(*caCert)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(*caKey)
	if err != nil {
		return err
	}
	ca, err := pki.Decode(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	host, err := pki.GenerateHostCert(ca, hostName, sans, *lifetime)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := pki.Encode(host)
	if err != nil {
		return err
	}
	if err := writeStrict(*outCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeStrict(*outKey, keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s and %s\n", *outCert, *outKey)
	return nil
}

func writeStrict(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

type multiString []string

func (m *multiString) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiString) Set(v string) error { *m = append(*m, v); return nil }
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/cli/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/pki.go internal/pkg/cli/pki_test.go
git commit -s -m "feat(cli): add 'pki init' and 'pki cert' subcommands"
```

---

### Task 8: CLI subcommands `host add | remove | list`

**Files:**
- Create: `internal/pkg/cli/host.go`
- Create: `internal/pkg/cli/host_test.go`
- Helper: `internal/pkg/cli/configio.go` (load + save helper used by all config-mutating subcommands)
- Helper test: `internal/pkg/cli/configio_test.go`

The helper centralises the "load config, mutate, save back" pattern (DRY for upcoming `user` and `config validate` subcommands).

- [ ] **Step 1: Failing tests**

```go
// internal/pkg/cli/host_test.go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func TestHostAddAppendsPeerToConfig(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"host", "add", "node-b", "10.0.0.2", "--config", path},
		&stdout, &stderr); err != nil {
		t.Fatalf("host add: %v (stderr=%q)", err, stderr.String())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Name != "node-b" {
		t.Errorf("peers = %v", cfg.Peers)
	}
}

func TestHostListPrintsPeers(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"host", "add", "node-b", "10.0.0.2", "--config", path}, &stdout, &stderr)
	stdout.Reset()
	if err := Run(context.Background(), []string{"host", "list", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "node-b") {
		t.Errorf("expected 'node-b' in output, got %q", stdout.String())
	}
}

func TestHostRemoveDropsPeer(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"host", "add", "node-b", "10.0.0.2", "--config", path}, &stdout, &stderr)
	_ = Run(context.Background(), []string{"host", "remove", "node-b", "--config", path}, &stdout, &stderr)
	cfg, _ := config.Load(path)
	if len(cfg.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(cfg.Peers))
	}
}
```

```go
// internal/pkg/cli/configio_test.go
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

// writeMinimalConfig writes a permission-correct config with one host but
// no peers. Shared test helper for cli tests.
func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	cfg := &config.Config{
		SchemaVersion: 1,
		Host:          config.HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI:           config.PKIPaths{CACertPath: "x", CAKeyPath: "y", HostCertPath: "z", HostKeyPath: "k"},
		Listeners: config.Listeners{
			InterHost: config.ListenerAddr{Addr: "0.0.0.0:8443"},
			UI:        config.ListenerAddr{Addr: "0.0.0.0:8080"},
			Probe:     config.ProbeListener{HTTPAddr: "0.0.0.0:7080", UDPAddr: "0.0.0.0:7081"},
		},
		Probe: config.ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		},
		UI: config.UI{
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 3600,
		},
		Log: config.Log{Level: "info"},
	}
	if err := config.Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
```

- [ ] **Step 2: Verify FAIL**

Run: `go test ./internal/pkg/cli/`

- [ ] **Step 3: Implement helper and subcommand**

```go
// internal/pkg/cli/configio.go
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
// Skips the file-mode check (writing to a test temp dir is common).
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
```

```go
// internal/pkg/cli/host.go
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func init() {
	register("host", "manage peer hosts: add|remove|list", runHost)
}

func runHost(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("host: missing subcommand (add|remove|list)")
	}
	switch args[0] {
	case "add":
		return runHostAdd(args[1:], stdout, stderr)
	case "remove":
		return runHostRemove(args[1:], stdout, stderr)
	case "list":
		return runHostList(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("host: unknown subcommand %q", args[0])
	}
}

func runHostAdd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("host add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	var checks multiString
	fs.Var(&checks, "check", "enable check (icmp|tcp|udp|https); may repeat. Default: all four.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return errors.New("host add: usage: host add <name> <addr>")
	}
	name, addr := rest[0], rest[1]
	if len(checks) == 0 {
		checks = []string{"icmp", "tcp", "udp", "https"}
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for _, p := range c.Peers {
			if p.Name == name {
				return fmt.Errorf("host add: peer %q already exists", name)
			}
		}
		c.Peers = append(c.Peers, config.Peer{Name: name, Addr: addr, Checks: checks})
		fmt.Fprintf(stdout, "added peer %s (%s)\n", name, addr)
		return nil
	})
}

func runHostRemove(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("host remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("host remove: usage: host remove <name>")
	}
	name := rest[0]
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for i, p := range c.Peers {
			if p.Name == name {
				c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
				fmt.Fprintf(stdout, "removed peer %s\n", name)
				return nil
			}
		}
		return fmt.Errorf("host remove: peer %q not found", name)
	})
}

func runHostList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("host list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDR\tCHECKS")
	for _, p := range cfg.Peers {
		fmt.Fprintf(tw, "%s\t%s\t%v\n", p.Name, p.Addr, p.Checks)
	}
	return tw.Flush()
}
```

- [ ] **Step 4: Verify PASS**

Run: `go test ./internal/pkg/cli/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/host.go internal/pkg/cli/host_test.go internal/pkg/cli/configio.go internal/pkg/cli/configio_test.go
git commit -s -m "feat(cli): add 'host add|remove|list' subcommands"
```

---

### Task 9: CLI subcommand `user add | remove`

**Files:**
- Create: `internal/pkg/cli/user.go`
- Create: `internal/pkg/cli/user_test.go`
- Modify: `go.mod` (will pull in `golang.org/x/crypto`)

Uses bcrypt cost 12. Reads password from stdin (no-echo via `golang.org/x/term` for the real CLI; in tests we read from a `strings.NewReader` passed via a new `stdin io.Reader` parameter — but the existing `Handler` signature has no `stdin`. To stay TDD-friendly without changing every handler signature, this task introduces a package-level `var passwordReader func() (string, error)` that tests override.)

- [ ] **Step 1: Failing tests**

```go
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
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/cli/`

- [ ] **Step 3: Add dependency, implement**

```bash
go get golang.org/x/crypto/bcrypt
go get golang.org/x/term
go mod tidy
```

```go
// internal/pkg/cli/user.go
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func init() {
	register("user", "manage UI users: add|remove", runUser)
}

// passwordReader is overridable in tests.
var passwordReader = readPasswordFromTerminal

func readPasswordFromTerminal() (string, error) {
	fmt.Fprint(os.Stderr, "password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func runUser(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("user: missing subcommand (add|remove)")
	}
	switch args[0] {
	case "add":
		return runUserAdd(args[1:], stdout, stderr)
	case "remove":
		return runUserRemove(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("user: unknown subcommand %q", args[0])
	}
}

func runUserAdd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("user add: usage: user add <name>")
	}
	name := rest[0]
	pw, err := passwordReader()
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("user add: empty password not allowed")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for _, u := range c.UI.Users {
			if u.Name == name {
				return fmt.Errorf("user add: user %q already exists", name)
			}
		}
		c.UI.Users = append(c.UI.Users, config.User{Name: name, PasswordHash: string(hash)})
		fmt.Fprintf(stdout, "added user %s\n", name)
		return nil
	})
}

func runUserRemove(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("user remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("user remove: usage: user remove <name>")
	}
	name := rest[0]
	return loadAndMutate(*cfgPath, func(c *config.Config) error {
		for i, u := range c.UI.Users {
			if u.Name == name {
				c.UI.Users = append(c.UI.Users[:i], c.UI.Users[i+1:]...)
				fmt.Fprintf(stdout, "removed user %s\n", name)
				return nil
			}
		}
		return fmt.Errorf("user remove: user %q not found", name)
	})
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/cli/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/user.go internal/pkg/cli/user_test.go go.mod go.sum
git commit -s -m "feat(cli): add 'user add|remove' subcommands (bcrypt cost 12)"
```

---

### Task 10: CLI subcommand `config validate`

**Files:**
- Create: `internal/pkg/cli/config_cmd.go`
- Create: `internal/pkg/cli/config_cmd_test.go`

Loads the file, checks mode (warns instead of failing for non-root paths), runs `config.ValidateWithWarnings`, prints warnings to stderr, exits 0 on success.

- [ ] **Step 1: Failing tests**

```go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestConfigValidateAcceptsGoodConfig(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"config", "validate", "--config", path}, &stdout, &stderr); err != nil {
		t.Errorf("expected nil, got %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK") {
		t.Errorf("expected OK in stdout, got %q", stdout.String())
	}
}

func TestConfigValidateRejectsBadSchema(t *testing.T) {
	path := writeMinimalConfig(t)
	// Corrupt schemaVersion by reloading, mutating, saving
	_ = Run(context.Background(), []string{"host", "add", "x", "1.1.1.1", "--config", path}, new(bytes.Buffer), new(bytes.Buffer))
	// Now manually break it by writing junk
	if err := writeStrict(path, []byte(`{"schemaVersion":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"config", "validate", "--config", path}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for bad schema, got nil")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/cli/`

- [ ] **Step 3: Implement**

```go
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
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/cli/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/config_cmd.go internal/pkg/cli/config_cmd_test.go
git commit -s -m "feat(cli): add 'config validate' subcommand"
```

---

### Phase A Milestone Smoke

- [ ] **Step 1: Build**

```bash
go build -o bin/mesh-checker ./cmd/mesh-checker
```

- [ ] **Step 2: Bootstrap a fake mesh in /tmp**

```bash
D=$(mktemp -d)
./bin/mesh-checker pki init --ca-cert "$D/ca.crt" --ca-key "$D/ca.key"
./bin/mesh-checker pki cert node-a --ca-cert "$D/ca.crt" --ca-key "$D/ca.key" --out-cert "$D/node-a.crt" --out-key "$D/node-a.key" --san 127.0.0.1
ls -l "$D"
# (manually craft a tiny config.json, then:)
# ./bin/mesh-checker host add node-b 10.0.0.2 --config $D/config.json
# ./bin/mesh-checker user add admin --config $D/config.json
# ./bin/mesh-checker config validate --config $D/config.json
```

- [ ] **Step 3: Verify all files are 0600 / 0644 as appropriate**

- [ ] **Step 4: Run full test suite + commit Phase A end marker**

```bash
go test ./...
git tag phase-a-complete
```

End of Phase A. Continue to Phase B.

---

# Phase B — Probe Engine + Scheduler (no listeners yet)

**Phase B milestone:** the daemon can run a scheduler that drives probes against a local `httptest.Server` (HTTPS), a local TCP listener, and a local UDP echo (in-process), writes results into the ringbuffer, and the classifier returns the expected state. ICMP is covered by pure packet build/parse tests; live ICMP gated by build tag.

---

### Task 11: Probe interface and shared types

**Files:**
- Create: `internal/pkg/probe/probe.go`
- Create: `internal/pkg/probe/probe_test.go`

- [ ] **Step 1: Failing test**

```go
package probe

import (
	"context"
	"testing"
	"time"
)

type fakeProber struct{ ok bool }

func (f *fakeProber) Probe(ctx context.Context, t Target) (Result, error) {
	return Result{Timestamp: time.Now(), Latency: 1, OK: f.ok}, nil
}

func TestProberInterfaceSatisfied(t *testing.T) {
	var _ Prober = (*fakeProber)(nil)
}

func TestResultZeroValueIsFailure(t *testing.T) {
	var r Result
	if r.OK {
		t.Error("zero-value Result.OK must be false")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/`

- [ ] **Step 3: Implement**

```go
// Package probe defines the Prober interface and shared types used by
// the scheduler and every protocol-specific implementation.
package probe

import (
	"context"
	"time"
)

// Protocol identifies one of the four checks.
type Protocol string

const (
	ICMP  Protocol = "icmp"
	TCP   Protocol = "tcp"
	UDP   Protocol = "udp"
	HTTPS Protocol = "https"
)

// Target describes one peer that a Prober will probe.
type Target struct {
	Name     string
	Addr     string
	TCPPort  int
	UDPPort  int
	HTTPSURL string
}

// Result is one sample, success or failure.
type Result struct {
	Timestamp time.Time
	Latency   time.Duration
	OK        bool
	Err       string
}

// Prober probes one target. Implementations live in subpackages
// (tcp, http, udp, icmp).
type Prober interface {
	Probe(ctx context.Context, target Target) (Result, error)
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/probe/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/
git commit -s -m "feat(probe): add Prober interface and shared types"
```

---

### Task 12: Ringbuffer store

**Files:**
- Create: `internal/pkg/store/store.go`
- Create: `internal/pkg/store/store_test.go`

Thread-safe ringbuffer keyed by `(peer, protocol)`, capacity from config.

- [ ] **Step 1: Failing tests**

```go
package store

import (
	"sync"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestAppendAndSnapshotReturnsInOrder(t *testing.T) {
	s := New(3)
	s.Append("node-b", probe.TCP, probe.Result{Timestamp: time.Unix(1, 0), OK: true})
	s.Append("node-b", probe.TCP, probe.Result{Timestamp: time.Unix(2, 0), OK: false})
	snap := s.Snapshot("node-b", probe.TCP)
	if len(snap) != 2 {
		t.Fatalf("len = %d", len(snap))
	}
	if !snap[0].OK || snap[1].OK {
		t.Errorf("ordering wrong: %+v", snap)
	}
}

func TestRingbufferEvictsOldest(t *testing.T) {
	s := New(2)
	for i := 1; i <= 5; i++ {
		s.Append("p", probe.TCP, probe.Result{Timestamp: time.Unix(int64(i), 0), OK: true})
	}
	snap := s.Snapshot("p", probe.TCP)
	if len(snap) != 2 {
		t.Fatalf("len = %d", len(snap))
	}
	if snap[0].Timestamp.Unix() != 4 || snap[1].Timestamp.Unix() != 5 {
		t.Errorf("expected ts 4,5 got %d,%d", snap[0].Timestamp.Unix(), snap[1].Timestamp.Unix())
	}
}

func TestAllKeysListed(t *testing.T) {
	s := New(2)
	s.Append("a", probe.TCP, probe.Result{OK: true})
	s.Append("a", probe.UDP, probe.Result{OK: true})
	s.Append("b", probe.HTTPS, probe.Result{OK: true})
	keys := s.Keys()
	if len(keys) != 3 {
		t.Errorf("keys = %v", keys)
	}
}

func TestConcurrentAppendsSafe(t *testing.T) {
	s := New(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Append("p", probe.TCP, probe.Result{OK: true})
		}()
	}
	wg.Wait()
	if got := len(s.Snapshot("p", probe.TCP)); got != 50 {
		t.Errorf("expected 50, got %d", got)
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/store/`

- [ ] **Step 3: Implement**

```go
// Package store keeps a fixed-capacity ringbuffer of probe.Result
// per (peer, protocol) key. Thread-safe.
package store

import (
	"sync"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

type Key struct {
	Peer     string
	Protocol probe.Protocol
}

type Store struct {
	cap  int
	mu   sync.RWMutex
	bufs map[Key]*ring
}

func New(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{cap: capacity, bufs: map[Key]*ring{}}
}

func (s *Store) Append(peer string, p probe.Protocol, r probe.Result) {
	k := Key{peer, p}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bufs[k]
	if !ok {
		b = newRing(s.cap)
		s.bufs[k] = b
	}
	b.push(r)
}

func (s *Store) Snapshot(peer string, p probe.Protocol) []probe.Result {
	k := Key{peer, p}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bufs[k]
	if !ok {
		return nil
	}
	return b.snapshot()
}

func (s *Store) Keys() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.bufs))
	for k := range s.bufs {
		out = append(out, k)
	}
	return out
}

type ring struct {
	buf  []probe.Result
	head int // next write position
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]probe.Result, n)} }

func (r *ring) push(v probe.Result) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	if r.head == 0 {
		r.full = true
	}
}

func (r *ring) snapshot() []probe.Result {
	if !r.full {
		out := make([]probe.Result, r.head)
		copy(out, r.buf[:r.head])
		return out
	}
	out := make([]probe.Result, len(r.buf))
	copy(out, r.buf[r.head:])
	copy(out[len(r.buf)-r.head:], r.buf[:r.head])
	return out
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/store/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/store/
git commit -s -m "feat(store): add per-(peer,protocol) ringbuffer"
```

---

### Task 13: Sliding-window classifier

**Files:**
- Create: `internal/pkg/classifier/classifier.go`
- Create: `internal/pkg/classifier/classifier_test.go`

Pure function over `[]probe.Result`: `up | degraded | down` per spec §8.2.

- [ ] **Step 1: Failing tests**

```go
package classifier

import (
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func mkResults(oks ...bool) []probe.Result {
	out := make([]probe.Result, len(oks))
	for i, ok := range oks {
		out[i] = probe.Result{OK: ok}
	}
	return out
}

func TestUpWhenAllPass(t *testing.T) {
	got := Classify(mkResults(true, true, true, true, true), 5, 3)
	if got != Up {
		t.Errorf("got %v, want Up", got)
	}
}

func TestDownWhenThresholdFailures(t *testing.T) {
	got := Classify(mkResults(false, false, false, true, true), 5, 3)
	if got != Down {
		t.Errorf("got %v, want Down", got)
	}
}

func TestDegradedWhenSomeFail(t *testing.T) {
	got := Classify(mkResults(true, false, true, true, true), 5, 3)
	if got != Degraded {
		t.Errorf("got %v, want Degraded", got)
	}
}

func TestUnknownWhenInsufficientSamples(t *testing.T) {
	got := Classify(mkResults(true, true), 5, 3)
	if got != Unknown {
		t.Errorf("got %v, want Unknown", got)
	}
}

func TestUsesOnlyTailWhenMoreSamplesThanWindow(t *testing.T) {
	// First 5 fail, last 5 pass. Window=5 should consider only the last 5.
	got := Classify(mkResults(false, false, false, false, false, true, true, true, true, true), 5, 3)
	if got != Up {
		t.Errorf("got %v, want Up", got)
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/classifier/`

- [ ] **Step 3: Implement**

```go
// Package classifier maps a sliding window of probe.Result samples to
// a coarse state: Up, Degraded, Down, or Unknown (too few samples).
package classifier

import "github.com/bsmr/mesh-checker/internal/pkg/probe"

type State string

const (
	Unknown  State = "unknown"
	Up       State = "up"
	Degraded State = "degraded"
	Down     State = "down"
)

// Classify inspects the trailing `window` samples of results.
// - Unknown if fewer than `window` samples available.
// - Down if at least `threshold` of the last `window` failed.
// - Up if all `window` succeeded.
// - Degraded otherwise.
func Classify(results []probe.Result, window, threshold int) State {
	if len(results) < window {
		return Unknown
	}
	tail := results[len(results)-window:]
	fails := 0
	for _, r := range tail {
		if !r.OK {
			fails++
		}
	}
	switch {
	case fails >= threshold:
		return Down
	case fails == 0:
		return Up
	default:
		return Degraded
	}
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/classifier/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/classifier/
git commit -s -m "feat(classifier): add sliding-window state classifier"
```

---

### Task 14: TCP prober

**Files:**
- Create: `internal/pkg/probe/tcp/tcp.go`
- Create: `internal/pkg/probe/tcp/tcp_test.go`

- [ ] **Step 1: Failing tests**

```go
package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestProbeReturnsOKWhenListenerAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	p := New(500 * time.Millisecond)
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", TCPPort: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestProbeReturnsFailWhenPortClosed(t *testing.T) {
	p := New(100 * time.Millisecond)
	res, _ := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", TCPPort: 1}) // assume nothing on port 1
	if res.OK {
		t.Errorf("expected failure, got OK")
	}
	if res.Err == "" {
		t.Error("expected non-empty Err")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/tcp/`

- [ ] **Step 3: Implement**

```go
// Package tcp implements probe.Prober via TCP connect + immediate close.
package tcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

type Prober struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Prober { return &Prober{Timeout: timeout} }

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	d := net.Dialer{}
	addr := fmt.Sprintf("%s:%d", target.Addr, target.TCPPort)
	conn, err := d.DialContext(ctx, "tcp", addr)
	r := probe.Result{Timestamp: start, Latency: time.Since(start)}
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	conn.Close()
	r.OK = true
	return r, nil
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/probe/tcp/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/tcp/
git commit -s -m "feat(probe/tcp): connect-and-close prober"
```

---

### Task 15: HTTPS prober

**Files:**
- Create: `internal/pkg/probe/http/http.go`
- Create: `internal/pkg/probe/http/http_test.go`

Uses an injected `*tls.Config` so the test can supply the test server's CA via `httptest.NewTLSServer`.

- [ ] **Step 1: Failing tests**

```go
package http

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func newTestServer(body string, status int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/probe") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestProbeOKWhenBodyMatches(t *testing.T) {
	ts := newTestServer("mesh-checker 0.1.0\n", 200)
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	p := New(pool, 2*time.Second)
	res, err := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestProbeFailsOnWrongBody(t *testing.T) {
	ts := newTestServer("nope", 200)
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	p := New(pool, 2*time.Second)
	res, _ := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if res.OK {
		t.Errorf("expected failure (wrong body), got OK")
	}
}

func TestProbeFailsOnUntrustedCert(t *testing.T) {
	ts := newTestServer("mesh-checker 0.1.0\n", 200)
	defer ts.Close()

	p := New(x509.NewCertPool(), 2*time.Second) // empty CA pool
	res, _ := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if res.OK {
		t.Errorf("expected TLS failure, got OK")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/http/`

- [ ] **Step 3: Implement**

```go
// Package http implements an HTTPS prober that verifies peer certs
// against the mesh CA pool and looks for "mesh-checker" in the body.
package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

const bodyMarker = "mesh-checker"

type Prober struct {
	client *http.Client
}

func New(meshCA *x509.CertPool, timeout time.Duration) *Prober {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: meshCA, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &Prober{client: &http.Client{Transport: tr, Timeout: timeout}}
}

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", target.HTTPSURL, nil)
	if err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	resp, err := p.client.Do(req)
	r := probe.Result{Timestamp: start, Latency: time.Since(start)}
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r.Err = fmt.Sprintf("status %d", resp.StatusCode)
		return r, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if !strings.Contains(string(body), bodyMarker) {
		r.Err = "body marker missing"
		return r, nil
	}
	r.OK = true
	return r, nil
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/probe/http/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/http/
git commit -s -m "feat(probe/http): https prober with mesh CA verification"
```

---

### Task 16: UDP payload codec (HMAC + nonce + replay-cache)

**Files:**
- Create: `internal/pkg/probe/udp/payload.go`
- Create: `internal/pkg/probe/udp/payload_test.go`

Encodes the request/response wire format and provides a replay-protection cache used by the echo server (Task 27).

- [ ] **Step 1: Failing tests**

```go
package udp

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestEncodeDecodeRequestRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	nonce, _ := NewNonce()
	req, err := EncodeRequest(secret, nonce, time.Unix(1700000000, 0), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeRequest(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HostName != "node-a" {
		t.Errorf("hostName = %q", parsed.HostName)
	}
	if !bytes.Equal(parsed.Nonce[:], nonce[:]) {
		t.Errorf("nonce mismatch")
	}
}

func TestDecodeRequestFailsOnBadHMAC(t *testing.T) {
	secret := make([]byte, 32)
	nonce, _ := NewNonce()
	req, _ := EncodeRequest(secret, nonce, time.Now(), "node-a")
	req[len(req)-1] ^= 0xFF
	if _, err := DecodeRequest(secret, req); err == nil {
		t.Error("expected HMAC verification failure")
	}
}

func TestResponseIsSmallerThanRequest(t *testing.T) {
	secret := make([]byte, 32)
	nonce, _ := NewNonce()
	req, _ := EncodeRequest(secret, nonce, time.Now(), "node-a-long-name")
	resp, _ := EncodeResponse(secret, nonce, time.Now())
	if len(resp) >= len(req) {
		t.Errorf("response (%d) must be < request (%d)", len(resp), len(req))
	}
}

func TestReplayCacheDetectsDuplicate(t *testing.T) {
	c := NewReplayCache(60 * time.Second)
	nonce, _ := NewNonce()
	if c.SeenOrAdd(nonce, time.Now()) {
		t.Error("first call must not be Seen")
	}
	if !c.SeenOrAdd(nonce, time.Now()) {
		t.Error("second call must be Seen")
	}
}

func TestReplayCacheEvictsExpired(t *testing.T) {
	c := NewReplayCache(10 * time.Millisecond)
	nonce, _ := NewNonce()
	c.SeenOrAdd(nonce, time.Now().Add(-time.Hour))
	if c.SeenOrAdd(nonce, time.Now()) {
		t.Error("expired entry should have been evicted")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/udp/`

- [ ] **Step 3: Implement**

```go
// Package udp contains the UDP probe wire format, HMAC verification,
// and a nonce replay cache. The client side (Prober) and server side
// (echo) both consume these primitives.
package udp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	nonceLen = 16
	tsLen    = 8
	hmacLen  = 32
)

type Nonce [nonceLen]byte

func NewNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}

// Request wire format: nonce(16) || ts(8, BE unix nano) || hostName(...) || HMAC-SHA256(...)(32)
type Request struct {
	Nonce     Nonce
	Timestamp time.Time
	HostName  string
}

func EncodeRequest(secret []byte, nonce Nonce, ts time.Time, hostName string) ([]byte, error) {
	if len(hostName) == 0 {
		return nil, errors.New("udp: hostName must not be empty")
	}
	body := make([]byte, 0, nonceLen+tsLen+len(hostName)+hmacLen)
	body = append(body, nonce[:]...)
	tsBuf := make([]byte, tsLen)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts.UnixNano()))
	body = append(body, tsBuf...)
	body = append(body, []byte(hostName)...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	body = mac.Sum(body)
	return body, nil
}

func DecodeRequest(secret, buf []byte) (Request, error) {
	if len(buf) < nonceLen+tsLen+1+hmacLen {
		return Request{}, errors.New("udp: request too short")
	}
	macStart := len(buf) - hmacLen
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:macStart])
	if !hmac.Equal(mac.Sum(nil), buf[macStart:]) {
		return Request{}, errors.New("udp: hmac mismatch")
	}
	var n Nonce
	copy(n[:], buf[:nonceLen])
	tsNs := binary.BigEndian.Uint64(buf[nonceLen : nonceLen+tsLen])
	return Request{
		Nonce:     n,
		Timestamp: time.Unix(0, int64(tsNs)),
		HostName:  string(buf[nonceLen+tsLen : macStart]),
	}, nil
}

// Response wire format: nonce(16) || ts(8) || HMAC(32). Strictly smaller
// than the request (no hostName) -> anti-amplification.
func EncodeResponse(secret []byte, nonce Nonce, ts time.Time) ([]byte, error) {
	body := make([]byte, 0, nonceLen+tsLen+hmacLen)
	body = append(body, nonce[:]...)
	tsBuf := make([]byte, tsLen)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts.UnixNano()))
	body = append(body, tsBuf...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	body = mac.Sum(body)
	return body, nil
}

func DecodeResponse(secret, buf []byte) (Nonce, time.Time, error) {
	if len(buf) != nonceLen+tsLen+hmacLen {
		return Nonce{}, time.Time{}, errors.New("udp: response wrong length")
	}
	macStart := len(buf) - hmacLen
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:macStart])
	if !hmac.Equal(mac.Sum(nil), buf[macStart:]) {
		return Nonce{}, time.Time{}, errors.New("udp: response hmac mismatch")
	}
	var n Nonce
	copy(n[:], buf[:nonceLen])
	tsNs := binary.BigEndian.Uint64(buf[nonceLen : nonceLen+tsLen])
	return n, time.Unix(0, int64(tsNs)), nil
}

// ReplayCache rejects repeated nonces within the TTL window.
type ReplayCache struct {
	ttl  time.Duration
	mu   sync.Mutex
	seen map[Nonce]time.Time
}

func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{ttl: ttl, seen: map[Nonce]time.Time{}}
}

// SeenOrAdd returns true if the nonce was already in the cache and not
// expired. It also expires stale entries on each call.
func (c *ReplayCache) SeenOrAdd(n Nonce, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.ttl)
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[n]; ok {
		return true
	}
	c.seen[n] = now
	return false
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/probe/udp/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/udp/payload.go internal/pkg/probe/udp/payload_test.go
git commit -s -m "feat(probe/udp): wire format with HMAC and replay cache"
```

---

### Task 17: UDP client prober

**Files:**
- Create: `internal/pkg/probe/udp/udp.go`
- Create: `internal/pkg/probe/udp/udp_test.go`

Sends request, awaits matching nonce response within timeout. Tests start a goroutine that echoes via `EncodeResponse`.

- [ ] **Step 1: Failing tests**

```go
package udp

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func startEchoFake(t *testing.T, secret []byte) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			req, err := DecodeRequest(secret, buf[:n])
			if err != nil {
				continue
			}
			resp, _ := EncodeResponse(secret, req.Nonce, time.Now())
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { close(done); pc.Close() }
}

func TestUDPProberRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	port, stop := startEchoFake(t, secret)
	defer stop()

	p := New(secret, "node-a", 500*time.Millisecond)
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", UDPPort: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestUDPProberTimesOutWithoutResponder(t *testing.T) {
	secret := make([]byte, 32)
	p := New(secret, "node-a", 100*time.Millisecond)
	res, _ := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", UDPPort: 1})
	if res.OK {
		t.Errorf("expected failure, got OK")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/udp/`

- [ ] **Step 3: Implement**

```go
package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

type Prober struct {
	Secret   []byte
	HostName string
	Timeout  time.Duration
}

func New(secret []byte, hostName string, timeout time.Duration) *Prober {
	return &Prober{Secret: secret, HostName: hostName, Timeout: timeout}
}

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	r := probe.Result{Timestamp: start}

	nonce, err := NewNonce()
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	req, err := EncodeRequest(p.Secret, nonce, start, p.HostName)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	addr := fmt.Sprintf("%s:%d", target.Addr, target.UDPPort)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	defer conn.Close()
	deadline := start.Add(p.Timeout)
	conn.SetDeadline(deadline)
	if _, err := conn.Write(req); err != nil {
		r.Err = err.Error()
		return r, nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	r.Latency = time.Since(start)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	gotNonce, _, err := DecodeResponse(p.Secret, buf[:n])
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	if !bytes.Equal(gotNonce[:], nonce[:]) {
		r.Err = "nonce mismatch"
		return r, nil
	}
	r.OK = true
	return r, nil
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/probe/udp/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/udp/udp.go internal/pkg/probe/udp/udp_test.go
git commit -s -m "feat(probe/udp): udp client prober"
```

---

### Task 18: ICMP prober (pure parser + integration test)

**Files:**
- Create: `internal/pkg/probe/icmp/icmp.go`
- Create: `internal/pkg/probe/icmp/icmp_test.go`
- Create: `internal/pkg/probe/icmp/icmp_integration_test.go` (build-tagged)

Pure tests exercise echo-request/reply packet build and parse via `golang.org/x/net/icmp`. Integration test (live socket) only runs under `-tags integration` and requires `cap_net_raw`.

- [ ] **Step 1: Failing tests (pure only)**

```go
// internal/pkg/probe/icmp/icmp_test.go
package icmp

import (
	"bytes"
	"testing"
)

func TestBuildAndParseEchoRequest(t *testing.T) {
	pkt, err := buildEcho(0x4242, 7, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	id, seq, payload, err := parseEchoReply(pkt) // reply has the same structure for the test
	if err != nil {
		t.Fatal(err)
	}
	if id != 0x4242 {
		t.Errorf("id = %x", id)
	}
	if seq != 7 {
		t.Errorf("seq = %d", seq)
	}
	if !bytes.Equal(payload, []byte("ping")) {
		t.Errorf("payload = %q", payload)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, _, _, err := parseEchoReply([]byte{0, 1, 2}); err == nil {
		t.Error("expected error on garbage input")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/probe/icmp/`

- [ ] **Step 3: Add dependency, implement pure code**

```bash
go get golang.org/x/net/icmp
go mod tidy
```

```go
// Package icmp implements probe.Prober via ICMP Echo. Requires
// cap_net_raw on the binary. Pure packet build/parse is unit-tested;
// live socket behaviour is covered by an integration test behind
// the //go:build integration tag.
package icmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func buildEcho(id, seq int, payload []byte) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
	}
	return msg.Marshal(nil)
}

func parseEchoReply(b []byte) (id, seq int, payload []byte, err error) {
	m, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply.Protocol()), b)
	if err != nil {
		// Also try parsing as echo request (used in unit tests where we
		// "round-trip" through Marshal+ParseMessage on the request side).
		m, err = icmp.ParseMessage(1, b)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok {
		return 0, 0, nil, errors.New("icmp: not an echo body")
	}
	return e.ID, e.Seq, e.Data, nil
}

// Prober owns a raw socket and demultiplexes replies by sequence.
type Prober struct {
	id      int
	timeout time.Duration

	mu      sync.Mutex
	nextSeq int
	pending map[int]chan probe.Result
	conn    *icmp.PacketConn
}

// New opens a raw ICMP socket. Caller must hold cap_net_raw.
func New(timeout time.Duration) (*Prober, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp: %w", err)
	}
	p := &Prober{
		id:      os.Getpid() & 0xffff,
		timeout: timeout,
		pending: map[int]chan probe.Result{},
		conn:    c,
	}
	go p.readLoop()
	return p, nil
}

func (p *Prober) Close() error { return p.conn.Close() }

func (p *Prober) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, seq, _, err := parseEchoReply(buf[:n])
		if err != nil {
			continue
		}
		p.mu.Lock()
		ch, ok := p.pending[seq]
		delete(p.pending, seq)
		p.mu.Unlock()
		if ok {
			ch <- probe.Result{Timestamp: time.Now(), OK: true}
		}
	}
}

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	p.mu.Lock()
	p.nextSeq = (p.nextSeq + 1) & 0xffff
	seq := p.nextSeq
	ch := make(chan probe.Result, 1)
	p.pending[seq] = ch
	p.mu.Unlock()

	pkt, err := buildEcho(p.id, seq, []byte("mesh-checker"))
	if err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	if _, err := p.conn.WriteTo(pkt, &net.IPAddr{IP: net.ParseIP(target.Addr)}); err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	select {
	case r := <-ch:
		r.Latency = time.Since(start)
		r.Timestamp = start
		return r, nil
	case <-time.After(p.timeout):
		p.mu.Lock()
		delete(p.pending, seq)
		p.mu.Unlock()
		return probe.Result{Timestamp: start, Latency: time.Since(start), Err: "timeout"}, nil
	case <-ctx.Done():
		return probe.Result{Timestamp: start, Err: ctx.Err().Error()}, nil
	}
}
```

Add the build-tagged integration test:

```go
//go:build integration

package icmp

import (
	"context"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestICMPProbesLoopback(t *testing.T) {
	p, err := New(2 * time.Second)
	if err != nil {
		t.Skipf("ICMP socket unavailable (cap_net_raw missing?): %v", err)
	}
	defer p.Close()
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("loopback ICMP failed: %+v", res)
	}
}
```

- [ ] **Step 4: Verify PASS** (default — only pure tests run)

Run: `go test ./internal/pkg/probe/icmp/ -v`
Optional privileged: `sudo go test -tags integration ./internal/pkg/probe/icmp/`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/probe/icmp/ go.mod go.sum
git commit -s -m "feat(probe/icmp): icmp echo prober with build-tagged integration test"
```

---

### Task 19: Scheduler (worker pool + jitter)

**Files:**
- Create: `internal/pkg/scheduler/scheduler.go`
- Create: `internal/pkg/scheduler/scheduler_test.go`

- [ ] **Step 1: Failing tests**

```go
package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

type countingProber struct{ n atomic.Int64 }

func (c *countingProber) Probe(ctx context.Context, t probe.Target) (probe.Result, error) {
	c.n.Add(1)
	return probe.Result{Timestamp: time.Now(), OK: true}, nil
}

func TestSchedulerRunsConfiguredJobs(t *testing.T) {
	st := store.New(10)
	cp := &countingProber{}
	jobs := []Job{
		{Peer: "node-b", Protocol: probe.TCP, Target: probe.Target{Name: "node-b"}, Prober: cp},
	}
	cfg := Config{Interval: 30 * time.Millisecond, JitterPercent: 0, Workers: 2}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	s := New(cfg, jobs, st)
	s.Run(ctx)

	if got := cp.n.Load(); got < 3 {
		t.Errorf("expected >=3 probes in 120ms, got %d", got)
	}
	if snap := st.Snapshot("node-b", probe.TCP); len(snap) < 3 {
		t.Errorf("store has %d samples, want >=3", len(snap))
	}
}

func TestSchedulerStopsOnContextCancel(t *testing.T) {
	st := store.New(10)
	cp := &countingProber{}
	jobs := []Job{{Peer: "p", Protocol: probe.TCP, Prober: cp}}
	cfg := Config{Interval: 20 * time.Millisecond, JitterPercent: 0, Workers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(cfg, jobs, st)
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("scheduler did not stop after cancel")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/scheduler/`

- [ ] **Step 3: Implement**

```go
// Package scheduler drives Probers on a periodic schedule and writes
// their Results into the store. Each Job runs every Interval (±jitter)
// dispatched on a bounded worker pool.
package scheduler

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

type Job struct {
	Peer     string
	Protocol probe.Protocol
	Target   probe.Target
	Prober   probe.Prober
}

type Config struct {
	Interval      time.Duration
	JitterPercent int // 0..100
	Workers       int
	Timeout       time.Duration
}

type Scheduler struct {
	cfg   Config
	jobs  []Job
	store *store.Store
}

func New(cfg Config, jobs []Job, st *store.Store) *Scheduler {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	return &Scheduler{cfg: cfg, jobs: jobs, store: st}
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	jobs := make(chan Job, len(s.jobs))
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs)
		}()
	}
	var tickerWG sync.WaitGroup
	for _, j := range s.jobs {
		j := j
		tickerWG.Add(1)
		go func() {
			defer tickerWG.Done()
			s.tickerLoop(ctx, j, jobs)
		}()
	}
	tickerWG.Wait()
	close(jobs)
	wg.Wait()
}

func (s *Scheduler) tickerLoop(ctx context.Context, j Job, out chan<- Job) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.next()):
			select {
			case out <- j:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scheduler) next() time.Duration {
	base := s.cfg.Interval
	if s.cfg.JitterPercent <= 0 {
		return base
	}
	delta := int64(base) * int64(s.cfg.JitterPercent) / 100
	if delta == 0 {
		return base
	}
	jit := rand.Int63n(2*delta+1) - delta
	return base + time.Duration(jit)
}

func (s *Scheduler) worker(ctx context.Context, in <-chan Job) {
	for j := range in {
		probeCtx := ctx
		if s.cfg.Timeout > 0 {
			var cancel context.CancelFunc
			probeCtx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
			r, _ := j.Prober.Probe(probeCtx, j.Target)
			cancel()
			s.store.Append(j.Peer, j.Protocol, r)
		} else {
			r, _ := j.Prober.Probe(probeCtx, j.Target)
			s.store.Append(j.Peer, j.Protocol, r)
		}
	}
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/scheduler/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/scheduler/
git commit -s -m "feat(scheduler): worker-pool scheduler with jitter"
```

---

### Phase B Milestone

- [ ] **Step 1: Run full test suite with race detector**

```bash
go test -race ./...
```

- [ ] **Step 2: Tag**

```bash
git tag phase-b-complete
```

End of Phase B. Continue to Phase C.

---

# Phase C — Server, UI, Aggregator, and Daemon Wiring

**Phase C milestone:** `mesh-checker serve` brings up all three listeners with a real config and PKI material; a second daemon on a different config can pull `/api/peer/status` over mTLS; a browser at `https://localhost:8080/ui/` logs in and sees a live SSE-updated mesh matrix that also reflects the peer's view.

---

### Task 20: Probe-target listener (HTTP `/probe` + UDP echo server)

**Files:**
- Create: `internal/pkg/server/probe/server.go`
- Create: `internal/pkg/server/probe/server_test.go`
- Create: `internal/pkg/server/probe/udp_echo.go`
- Create: `internal/pkg/server/probe/udp_echo_test.go`

The HTTP side is trivial (200 + body). The UDP side runs an echo loop using the udp payload package; rejects unknown peers, expired timestamps, and replays.

- [ ] **Step 1: Failing tests**

```go
// internal/pkg/server/probe/server_test.go
package probe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

func TestHTTPProbeHandlerReturnsBody(t *testing.T) {
	h := NewHTTPHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mesh-checker") {
		t.Errorf("body = %q", string(b))
	}
	if !strings.Contains(string(b), version.String()) {
		t.Errorf("version not in body: %q", string(b))
	}
}

func TestHTTPProbeRejectsOtherPaths(t *testing.T) {
	h := NewHTTPHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/foo")
	if resp.StatusCode != 404 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
```

```go
// internal/pkg/server/probe/udp_echo_test.go
package probe

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	udppayload "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
)

func TestUDPEchoServerEchoesAuthorisedPeer(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	allowed := map[string]bool{"127.0.0.1": true}

	s, err := NewUDPEcho("127.0.0.1:0", secret, allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")

	conn, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n >= len(req) {
		t.Errorf("response (%d) must be < request (%d)", n, len(req))
	}
}

func TestUDPEchoRejectsBadHMAC(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s, _ := NewUDPEcho("127.0.0.1:0", secret, map[string]bool{"127.0.0.1": true})
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")
	req[len(req)-1] ^= 0xff
	conn, _ := net.Dial("udp", s.Addr())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	conn.Write(req)
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected no response on bad HMAC")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/probe/`

- [ ] **Step 3: Implement**

```go
// Package probe (server) implements the probe-target listeners:
// an HTTP /probe handler (anyone can hit it) and a UDP echo server
// that authenticates requests via HMAC and a peer-IP allowlist.
package probe

import (
	"fmt"
	"net/http"

	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

// NewHTTPHandler returns a handler that responds 200 to GET /probe
// and 404 to everything else. No state, no auth.
func NewHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "mesh-checker %s\n", version.String())
	})
	return mux
}
```

```go
// internal/pkg/server/probe/udp_echo.go
package probe

import (
	"log/slog"
	"net"
	"sync"
	"time"

	udppayload "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
)

type UDPEcho struct {
	pc       net.PacketConn
	secret   []byte
	allowed  map[string]bool
	replay   *udppayload.ReplayCache
	mu       sync.Mutex
	closed   bool
	tsWindow time.Duration
}

func NewUDPEcho(listenAddr string, secret []byte, allowedIPs map[string]bool) (*UDPEcho, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &UDPEcho{
		pc: pc, secret: secret, allowed: allowedIPs,
		replay:   udppayload.NewReplayCache(60 * time.Second),
		tsWindow: 30 * time.Second,
	}, nil
}

func (s *UDPEcho) Addr() string { return s.pc.LocalAddr().String() }

func (s *UDPEcho) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.pc.Close()
}

func (s *UDPEcho) Run() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			slog.Warn("udp echo read", "err", err)
			continue
		}
		s.handle(buf[:n], addr)
	}
}

func (s *UDPEcho) handle(pkt []byte, addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil || !s.allowed[host] {
		return
	}
	req, err := udppayload.DecodeRequest(s.secret, pkt)
	if err != nil {
		return
	}
	now := time.Now()
	if diff := now.Sub(req.Timestamp); diff > s.tsWindow || diff < -s.tsWindow {
		return
	}
	if s.replay.SeenOrAdd(req.Nonce, now) {
		return
	}
	resp, err := udppayload.EncodeResponse(s.secret, req.Nonce, now)
	if err != nil {
		return
	}
	_, _ = s.pc.WriteTo(resp, addr)
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/server/probe/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/server/probe/
git commit -s -m "feat(server/probe): http /probe handler and udp echo server"
```

---

### Task 21: UI session cookie

**Files:**
- Create: `internal/pkg/server/ui/session.go`
- Create: `internal/pkg/server/ui/session_test.go`

- [ ] **Step 1: Failing tests**

```go
package ui

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSessionIssueAndVerify(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s := NewSession(secret, time.Hour)
	tok, err := s.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.Verify(tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if user != "admin" {
		t.Errorf("user = %q", user)
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	s := NewSession(make([]byte, 32), time.Second)
	tok, _ := s.Issue("admin", time.Now().Add(-time.Hour))
	if _, err := s.Verify(tok, time.Now()); err == nil {
		t.Error("expected expiry error")
	}
}

func TestSessionRejectsTampered(t *testing.T) {
	s := NewSession(make([]byte, 32), time.Hour)
	tok, _ := s.Issue("admin", time.Now())
	bad := strings.Replace(tok, "a", "b", 1)
	if _, err := s.Verify(bad, time.Now()); err == nil {
		t.Error("expected HMAC failure")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/ui/`

- [ ] **Step 3: Implement**

```go
// Package ui implements the authenticated UI listener.
package ui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Session struct {
	secret []byte
	ttl    time.Duration
}

func NewSession(secret []byte, ttl time.Duration) *Session {
	return &Session{secret: secret, ttl: ttl}
}

func (s *Session) Issue(user string, now time.Time) (string, error) {
	if strings.ContainsAny(user, ":|") {
		return "", errors.New("ui: user name contains forbidden char")
	}
	exp := now.Add(s.ttl).Unix()
	payload := fmt.Sprintf("%s:%d", user, exp)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(append([]byte(payload+":"), sig...)), nil
}

func (s *Session) Verify(token string, now time.Time) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	if len(raw) <= 33 {
		return "", errors.New("ui: token too short")
	}
	macStart := len(raw) - 32
	if raw[macStart-1] != ':' {
		return "", errors.New("ui: token malformed")
	}
	payload := raw[:macStart-1]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), raw[macStart:]) {
		return "", errors.New("ui: hmac mismatch")
	}
	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return "", errors.New("ui: payload malformed")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", err
	}
	if now.Unix() >= exp {
		return "", errors.New("ui: session expired")
	}
	return parts[0], nil
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/server/ui/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/server/ui/session.go internal/pkg/server/ui/session_test.go
git commit -s -m "feat(ui): signed session cookie issue/verify"
```

---

### Task 22: UI login handler

**Files:**
- Create: `internal/pkg/server/ui/login.go`
- Create: `internal/pkg/server/ui/login_test.go`

Form POST, bcrypt verify, 250 ms fixed delay on failure.

- [ ] **Step 1: Failing tests**

```go
package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func mkUsers(t *testing.T, name, password string) []config.User {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	return []config.User{{Name: name, PasswordHash: string(h)}}
}

func TestLoginSetsCookieOnGoodCreds(t *testing.T) {
	users := mkUsers(t, "admin", "s3cret!")
	sess := NewSession(make([]byte, 32), time.Hour)
	h := NewLoginHandler(users, sess, 1*time.Millisecond)

	body := url.Values{"name": {"admin"}, "password": {"s3cret!"}}.Encode()
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookieName {
		t.Fatalf("cookies = %v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie not hardened: %+v", cookies[0])
	}
}

func TestLoginRejectsBadCreds(t *testing.T) {
	users := mkUsers(t, "admin", "s3cret!")
	sess := NewSession(make([]byte, 32), time.Hour)
	h := NewLoginHandler(users, sess, 1*time.Millisecond)
	body := url.Values{"name": {"admin"}, "password": {"wrong"}}.Encode()
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/ui/`

- [ ] **Step 3: Implement**

```go
package ui

import (
	"crypto/subtle"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

const cookieName = "mesh-session"

type loginHandler struct {
	users     []config.User
	session   *Session
	failDelay time.Duration
}

func NewLoginHandler(users []config.User, sess *Session, failDelay time.Duration) http.Handler {
	return &loginHandler{users: users, session: sess, failDelay: failDelay}
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	password := r.FormValue("password")
	if h.authenticate(name, password) {
		tok, err := h.session.Issue(name, time.Now())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: tok,
			Path: "/ui/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}
	time.Sleep(h.failDelay)
	http.Error(w, "unauthorised", http.StatusUnauthorized)
}

func (h *loginHandler) authenticate(name, password string) bool {
	for _, u := range h.users {
		if subtle.ConstantTimeCompare([]byte(u.Name), []byte(name)) == 1 {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err == nil {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/server/ui/ -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/server/ui/login.go internal/pkg/server/ui/login_test.go
git commit -s -m "feat(ui): login handler with bcrypt and failure delay"
```

---

### Task 23: UI assets (embedded vanilla HTML/JS/CSS) and base handlers

**Files:**
- Create: `internal/pkg/server/ui/assets.go`
- Create: `internal/pkg/server/ui/handlers.go`
- Create: `internal/pkg/server/ui/handlers_test.go`
- Create: `internal/pkg/server/ui/static/index.html`
- Create: `internal/pkg/server/ui/static/login.html`
- Create: `internal/pkg/server/ui/static/app.js`
- Create: `internal/pkg/server/ui/static/style.css`

The UI listener also serves `/probe` (unauth, per spec §7.2 — that is the HTTPS check target). **All DOM construction in `app.js` uses `createElement` + `textContent`** to avoid XSS — peer names and protocol strings come from config and could otherwise be a vector.

- [ ] **Step 1: Failing tests**

```go
package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeHandlerOnUIListener(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mesh-checker") {
		t.Errorf("body = %q", string(b))
	}
}

func TestIndexRequiresAuth(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := c.Get(srv.URL + "/ui/")
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d (want 401 or 303)", resp.StatusCode)
	}
}

func TestLoginPageServedUnauthenticated(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/ui/login")
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/ui/`

- [ ] **Step 3: Create asset files**

`internal/pkg/server/ui/static/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>mesh-checker</title>
  <link rel="stylesheet" href="/ui/assets/style.css">
</head>
<body>
  <header><h1>mesh-checker</h1><form action="/ui/logout" method="post"><button>logout</button></form></header>
  <main>
    <h2>Mesh status</h2>
    <div id="status">connecting…</div>
  </main>
  <script src="/ui/assets/app.js"></script>
</body>
</html>
```

`internal/pkg/server/ui/static/login.html`:

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>login — mesh-checker</title>
<link rel="stylesheet" href="/ui/assets/style.css"></head>
<body><main><h1>mesh-checker</h1>
<form action="/ui/login" method="post">
  <label>name <input name="name" required></label>
  <label>password <input name="password" type="password" required></label>
  <button>log in</button>
</form></main></body></html>
```

`internal/pkg/server/ui/static/style.css`:

```css
body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; background: #fafafa; }
header { display: flex; justify-content: space-between; align-items: center; }
h1 { margin: 0; font-size: 1.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { padding: 0.4rem 0.6rem; border-bottom: 1px solid #ddd; text-align: left; font-size: 0.9rem; }
.up { color: #1a7f37; }
.degraded { color: #9a6700; }
.down { color: #cf222e; }
.unknown { color: #57606a; }
```

`internal/pkg/server/ui/static/app.js` — **no `innerHTML` anywhere**; every node built via `createElement` and filled via `textContent`. Peer names from config are treated as untrusted.

```javascript
(() => {
  const root = document.getElementById("status");
  const PROTOS = ["icmp", "tcp", "udp", "https"];
  const es = new EventSource("/ui/sse/status");

  es.addEventListener("status", (ev) => {
    let data;
    try { data = JSON.parse(ev.data); }
    catch (e) { setMessage(root, "parse error"); return; }
    replaceWith(root, renderTable(data));
  });
  es.onerror = () => { setMessage(root, "stream lost; reconnecting…"); };

  function setMessage(parent, msg) {
    const p = document.createElement("p");
    p.textContent = msg;
    replaceWith(parent, p);
  }

  function replaceWith(parent, node) {
    parent.replaceChildren(node);
  }

  function renderTable(data) {
    const observers = Object.keys(data.observers || {}).sort();
    if (observers.length === 0) {
      const p = document.createElement("p");
      p.textContent = "no data yet";
      return p;
    }
    const peers = new Set();
    observers.forEach(o => Object.keys((data.observers[o] || {}).samples || {}).forEach(p => peers.add(p)));
    const peerList = Array.from(peers).sort();

    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["observer", "peer", ...PROTOS].forEach(h => {
      const th = document.createElement("th");
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    observers.forEach(observer => {
      peerList.forEach(peer => {
        const row = document.createElement("tr");
        appendCell(row, observer);
        appendCell(row, peer);
        const samples = ((data.observers[observer] || {}).samples || {})[peer] || {};
        PROTOS.forEach(proto => {
          const cell = document.createElement("td");
          const state = (samples[proto] && samples[proto].state) || "unknown";
          cell.textContent = state;
          cell.className = state;
          row.appendChild(cell);
        });
        tbody.appendChild(row);
      });
    });
    table.appendChild(tbody);
    return table;
  }

  function appendCell(row, text) {
    const td = document.createElement("td");
    td.textContent = text;
    row.appendChild(td);
  }
})();
```

- [ ] **Step 4: Implement Go side**

```go
// internal/pkg/server/ui/assets.go
package ui

import "embed"

//go:embed static/*
var staticFS embed.FS
```

```go
// internal/pkg/server/ui/handlers.go
package ui

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	serverprobe "github.com/bsmr/mesh-checker/internal/pkg/server/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

// Deps is the wiring struct for NewMux. nil fields disable features.
type Deps struct {
	Login   http.Handler
	SSE     http.Handler
	Session *Session
}

// NewMux assembles the UI listener's full mux.
func NewMux(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/probe", serverprobe.NewHTTPHandler())
	mux.HandleFunc("/ui/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && d.Login != nil {
			d.Login.ServeHTTP(w, r)
			return
		}
		serveStatic(w, r, "static/login.html", "text/html; charset=utf-8")
	})
	mux.HandleFunc("/ui/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", MaxAge: -1, Path: "/ui/"})
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
	})
	mux.HandleFunc("/ui/assets/", func(w http.ResponseWriter, r *http.Request) {
		name := "static/" + r.URL.Path[len("/ui/assets/"):]
		serveStatic(w, r, name, contentTypeFor(name))
	})
	mux.Handle("/ui/", authMiddleware(d.Session, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ui/" {
			http.NotFound(w, r)
			return
		}
		serveStatic(w, r, "static/index.html", "text/html; charset=utf-8")
	})))
	if d.SSE != nil {
		mux.Handle("/ui/sse/status", authMiddleware(d.Session, d.SSE))
	}
	return withCommonHeaders(mux)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "application/javascript"
	case strings.HasSuffix(name, ".css"):
		return "text/css"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func serveStatic(w http.ResponseWriter, r *http.Request, name, contentType string) {
	b, err := fs.ReadFile(staticFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Mesh-Checker-Version", version.String())
	w.Write(b)
}

func withCommonHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func authMiddleware(sess *Session, next http.Handler) http.Handler {
	if sess == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "auth not configured", http.StatusUnauthorized)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			redirectOrUnauth(w, r)
			return
		}
		user, err := sess.Verify(c.Value, time.Now())
		if err != nil {
			redirectOrUnauth(w, r)
			return
		}
		r.Header.Set("X-Mesh-User", user)
		next.ServeHTTP(w, r)
	})
}

func redirectOrUnauth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("WWW-Authenticate", "Cookie")
	http.Error(w, "unauthorised", http.StatusUnauthorized)
}
```

- [ ] **Step 5: Verify PASS** — `go test ./internal/pkg/server/ui/ -v`

- [ ] **Step 6: Commit**

```bash
git add internal/pkg/server/ui/assets.go internal/pkg/server/ui/handlers.go internal/pkg/server/ui/handlers_test.go internal/pkg/server/ui/static/
git commit -s -m "feat(ui): embed assets and add /probe + asset handlers (XSS-safe DOM)"
```

---

### Task 24: Aggregator (peer fan-out)

**Files:**
- Create: `internal/pkg/aggregator/aggregator.go`
- Create: `internal/pkg/aggregator/aggregator_test.go`

Builds the local view from the store and fans out to peers' `/api/peer/status` via an injected `PeerClient` interface (so tests don't need a real mTLS server).

- [ ] **Step 1: Failing tests**

```go
package aggregator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/classifier"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

type fakeClient struct {
	views map[string]ObserverView
	err   map[string]error
}

func (f *fakeClient) Fetch(ctx context.Context, peer string) (ObserverView, error) {
	if e, ok := f.err[peer]; ok && e != nil {
		return ObserverView{}, e
	}
	return f.views[peer], nil
}

func TestAggregateIncludesLocalAndPeers(t *testing.T) {
	st := store.New(5)
	st.Append("node-b", probe.TCP, probe.Result{OK: true})
	cl := &fakeClient{views: map[string]ObserverView{
		"node-b": {Host: "node-b", Samples: map[string]map[probe.Protocol]Sample{
			"node-a": {probe.TCP: {State: classifier.Up}},
		}},
	}}
	a := New(cl, st, "node-a", []string{"node-b"}, 5, 3, 100*time.Millisecond)
	mv := a.Aggregate(context.Background())
	if _, ok := mv.Observers["node-a"]; !ok {
		t.Fatal("local view missing")
	}
	if _, ok := mv.Observers["node-b"]; !ok {
		t.Fatal("peer view missing")
	}
}

func TestAggregateMarksUnreachablePeer(t *testing.T) {
	st := store.New(5)
	cl := &fakeClient{err: map[string]error{"node-b": errors.New("conn refused")}}
	a := New(cl, st, "node-a", []string{"node-b"}, 5, 3, 50*time.Millisecond)
	mv := a.Aggregate(context.Background())
	v, ok := mv.Observers["node-b"]
	if !ok {
		t.Fatal("peer placeholder missing")
	}
	if v.Reachable {
		t.Error("expected Reachable=false")
	}
	if v.Reason == "" {
		t.Error("expected non-empty Reason")
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/aggregator/`

- [ ] **Step 3: Implement**

```go
// Package aggregator builds the merged mesh view shown in the UI by
// combining the local store with peers' /api/peer/status pulls.
package aggregator

import (
	"context"
	"sync"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/classifier"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

// Sample is one classified probe entry shown in the matrix.
type Sample struct {
	State  classifier.State `json:"state"`
	LastTS time.Time        `json:"lastTs,omitempty"`
}

// ObserverView is one host's view of every other host. Returned by
// /api/peer/status and produced locally.
type ObserverView struct {
	Host      string                                       `json:"host"`
	Samples   map[string]map[probe.Protocol]Sample         `json:"samples"`
	Reachable bool                                         `json:"reachable"`
	Reason    string                                       `json:"reason,omitempty"`
}

// MeshView is the merged response sent over SSE.
type MeshView struct {
	GeneratedAt time.Time               `json:"generatedAt"`
	Observers   map[string]ObserverView `json:"observers"`
}

// PeerClient fetches a peer's ObserverView over mTLS.
type PeerClient interface {
	Fetch(ctx context.Context, peer string) (ObserverView, error)
}

type Aggregator struct {
	client    PeerClient
	store     *store.Store
	localHost string
	peers     []string
	window    int
	threshold int
	timeout   time.Duration
}

func New(c PeerClient, st *store.Store, localHost string, peers []string, window, threshold int, peerTimeout time.Duration) *Aggregator {
	return &Aggregator{c, st, localHost, peers, window, threshold, peerTimeout}
}

// Aggregate runs once and returns the merged view.
func (a *Aggregator) Aggregate(ctx context.Context) MeshView {
	mv := MeshView{GeneratedAt: time.Now(), Observers: map[string]ObserverView{}}
	mv.Observers[a.localHost] = a.localView()

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range a.peers {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			peerCtx, cancel := context.WithTimeout(ctx, a.timeout)
			defer cancel()
			v, err := a.client.Fetch(peerCtx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				mv.Observers[p] = ObserverView{Host: p, Reachable: false, Reason: err.Error()}
				return
			}
			v.Reachable = true
			mv.Observers[p] = v
		}()
	}
	wg.Wait()
	return mv
}

func (a *Aggregator) localView() ObserverView {
	v := ObserverView{Host: a.localHost, Reachable: true, Samples: map[string]map[probe.Protocol]Sample{}}
	for _, k := range a.store.Keys() {
		samples := a.store.Snapshot(k.Peer, k.Protocol)
		state := classifier.Classify(samples, a.window, a.threshold)
		var lastTS time.Time
		if len(samples) > 0 {
			lastTS = samples[len(samples)-1].Timestamp
		}
		if v.Samples[k.Peer] == nil {
			v.Samples[k.Peer] = map[probe.Protocol]Sample{}
		}
		v.Samples[k.Peer][k.Protocol] = Sample{State: state, LastTS: lastTS}
	}
	return v
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/aggregator/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/aggregator/
git commit -s -m "feat(aggregator): merge local store with peer fan-out"
```

---

### Task 25: SSE handler

**Files:**
- Create: `internal/pkg/server/ui/sse.go`
- Create: `internal/pkg/server/ui/sse_test.go`

Tick once per second, run the aggregator, emit one named SSE event.

- [ ] **Step 1: Failing test**

```go
package ui

import (
	"bufio"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

type fakeAgg struct{ v aggregator.MeshView }

func (f *fakeAgg) Aggregate(ctx context.Context) aggregator.MeshView { return f.v }

func TestSSEEmitsStatusEvent(t *testing.T) {
	agg := &fakeAgg{v: aggregator.MeshView{GeneratedAt: time.Now(), Observers: map[string]aggregator.ObserverView{}}}
	h := NewSSEHandler(agg, 20*time.Millisecond)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	gotEvent := false
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: status") {
			gotEvent = true
			break
		}
	}
	if !gotEvent {
		t.Errorf("no status event seen")
	}
}
```

Add to imports if missing: `net/http`.

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/ui/`

- [ ] **Step 3: Implement**

```go
// internal/pkg/server/ui/sse.go
package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

// Aggregator is the subset of aggregator.Aggregator the SSE handler uses.
type Aggregator interface {
	Aggregate(ctx context.Context) aggregator.MeshView
}

type sseHandler struct {
	agg      Aggregator
	interval time.Duration
}

func NewSSEHandler(agg Aggregator, interval time.Duration) http.Handler {
	return &sseHandler{agg: agg, interval: interval}
}

func (h *sseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	ctx := r.Context()
	t := time.NewTicker(h.interval)
	defer t.Stop()
	h.emit(w, flusher, ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.emit(w, flusher, ctx)
		}
	}
}

func (h *sseHandler) emit(w http.ResponseWriter, f http.Flusher, ctx context.Context) {
	view := h.agg.Aggregate(ctx)
	b, err := json.Marshal(view)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", b)
	f.Flush()
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/server/ui/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/server/ui/sse.go internal/pkg/server/ui/sse_test.go
git commit -s -m "feat(ui): SSE status stream"
```

---

### Task 26: Inter-host mTLS listener and client

**Files:**
- Create: `internal/pkg/server/interhost/server.go`
- Create: `internal/pkg/server/interhost/server_test.go`
- Create: `internal/pkg/server/interhost/client.go`
- Create: `internal/pkg/server/interhost/client_test.go`

Provides:
- `NewServer(meshCA *x509.CertPool, hostCert tls.Certificate, peers map[string]bool, fetchLocal func() aggregator.ObserverView) *http.Server` — handles `/api/peer/status` and `/api/peer/version`. Enforces mTLS and CN-against-peer-list.
- `NewClient(caPool, hostCert) PeerClient` — implements `aggregator.PeerClient` via mTLS HTTPS GET.

- [ ] **Step 1: Failing tests**

```go
// internal/pkg/server/interhost/server_test.go
package interhost

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func mintTestPKI(t *testing.T, name string, ca *pki.Material) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	host, err := pki.GenerateHostCert(ca, name, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := pki.Encode(host)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return tlsCert, pool
}

func TestServerAcceptsAuthorisedClientAndReturnsView(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "node-b", ca)

	deps := Deps{
		MeshCA:   pool,
		HostCert: srvCert,
		Peers:    map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView {
			return aggregator.ObserverView{Host: "node-a", Reachable: true}
		},
	}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = serverTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clCert},
	}}}
	resp, err := cl.Get(ts.URL + "/api/peer/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	var v aggregator.ObserverView
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Host != "node-a" {
		t.Errorf("host = %q", v.Host)
	}
}

func TestServerRejectsClientWithUnknownCN(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "stranger", ca)

	deps := Deps{MeshCA: pool, HostCert: srvCert, Peers: map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{} }}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = serverTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{clCert},
	}}}
	resp, _ := cl.Get(ts.URL + "/api/peer/status")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}
```

```go
// internal/pkg/server/interhost/client_test.go
package interhost

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func TestClientFetchesViewFromServer(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "node-b", ca)

	deps := Deps{MeshCA: pool, HostCert: srvCert, Peers: map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{Host: "node-a"} }}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = serverTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	c := NewClient(pool, clCert, map[string]string{"node-a": ts.URL})
	v, err := c.Fetch(context.Background(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if v.Host != "node-a" {
		t.Errorf("host = %q", v.Host)
	}
}
```

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/server/interhost/`

- [ ] **Step 3: Implement**

```go
// Package interhost is the mTLS inter-host API: read-only status and
// version endpoints, plus a peer client that other nodes' aggregators use.
package interhost

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

type Deps struct {
	MeshCA     *x509.CertPool
	HostCert   tls.Certificate
	Peers      map[string]bool
	FetchLocal func() aggregator.ObserverView
}

// NewMux returns the inter-host HTTP routes. The TLS layer is set up
// by the caller using ServerTLSConfig.
func NewMux(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/peer/status", peerCNCheck(d.Peers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.FetchLocal())
	})))
	mux.Handle("/api/peer/version", peerCNCheck(d.Peers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":%q,"schemaVersion":1}`, version.String())
	})))
	return mux
}

func peerCNCheck(peers map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mTLS required", http.StatusForbidden)
			return
		}
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if !peers[cn] {
			http.Error(w, "unknown peer", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServerTLSConfig returns the *tls.Config to install on the inter-host
// listener. Renamed from serverTLSConfig to be exported.
func ServerTLSConfig(cert tls.Certificate, ca *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// internal alias used by tests in this package
var serverTLSConfig = ServerTLSConfig
```

```go
// internal/pkg/server/interhost/client.go
package interhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

type Client struct {
	urls   map[string]string // peer name -> base URL
	client *http.Client
}

func NewClient(caPool *x509.CertPool, cert tls.Certificate, peerURLs map[string]string) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: caPool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}}
	return &Client{urls: peerURLs, client: &http.Client{Transport: tr, Timeout: 5 * time.Second}}
}

func (c *Client) Fetch(ctx context.Context, peer string) (aggregator.ObserverView, error) {
	base, ok := c.urls[peer]
	if !ok {
		return aggregator.ObserverView{}, fmt.Errorf("interhost: no URL configured for peer %q", peer)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/peer/status", nil)
	if err != nil {
		return aggregator.ObserverView{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return aggregator.ObserverView{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return aggregator.ObserverView{}, fmt.Errorf("interhost: peer %q returned %d", peer, resp.StatusCode)
	}
	var v aggregator.ObserverView
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return aggregator.ObserverView{}, err
	}
	return v, nil
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/server/interhost/ -race -v`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/server/interhost/
git commit -s -m "feat(server/interhost): mTLS API and peer client"
```

---

### Task 27: `serve` subcommand wiring

**Files:**
- Create: `internal/pkg/cli/serve.go`
- Create: `internal/pkg/cli/serve_test.go`

This is the integration glue. It loads config, loads cert material, builds the store, builds prober instances per `peers[].checks`, starts the scheduler, brings up all three listeners, and blocks on context.

- [ ] **Step 1: Failing test (smoke only; full integration in Phase C milestone)**

```go
package cli

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestServeStartsAndStopsCleanly writes a working config and PKI tree,
// runs `serve` for ~150ms, cancels, and asserts no error returned.
func TestServeStartsAndStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	hostCert := filepath.Join(dir, "node-a.crt")
	hostKey := filepath.Join(dir, "node-a.key")
	if err := Run(context.Background(),
		[]string{"pki", "cert", "node-a",
			"--ca-cert", caCert, "--ca-key", caKey,
			"--out-cert", hostCert, "--out-key", hostKey,
			"--san", "127.0.0.1"},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeServeConfig(t, dir, caCert, hostCert, hostKey)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := Run(ctx, []string{"serve", "--config", cfgPath}, &stdout, &stderr)
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("serve returned unexpected error: %v (stderr=%q)", err, stderr.String())
	}
}

// writeServeConfig produces a config that binds to :0 (random) ports.
// Add this helper alongside writeMinimalConfig in configio_test.go.
func writeServeConfig(t *testing.T, dir, caCert, hostCert, hostKey string) string {
	t.Helper()
	freePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	freeUDP := func() int {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	cfg := newConfigSkeleton("node-a", "127.0.0.1", caCert, hostCert, hostKey, freePort(), freePort(), freePort(), freeUDP())
	p := filepath.Join(dir, "config.json")
	if err := saveStrict(p, cfg); err != nil {
		t.Fatal(err)
	}
	return p
}
```

`newConfigSkeleton` and `saveStrict` are helpers to add in `internal/pkg/cli/configio.go` as part of Step 3.

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/cli/`

- [ ] **Step 3: Implement helpers and `serve`**

Add helpers to `internal/pkg/cli/configio.go`:

```go
func newConfigSkeleton(hostName, addr, caCert, hostCert, hostKey string, ihPort, uiPort, probeHTTP, probeUDP int) *config.Config {
	const sec = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	return &config.Config{
		SchemaVersion: 1,
		Host:          config.HostInfo{Name: hostName, AdvertiseAddr: addr},
		PKI:           config.PKIPaths{CACertPath: caCert, CAKeyPath: "", HostCertPath: hostCert, HostKeyPath: hostKey},
		Listeners: config.Listeners{
			InterHost: config.ListenerAddr{Addr: fmt.Sprintf("127.0.0.1:%d", ihPort)},
			UI:        config.ListenerAddr{Addr: fmt.Sprintf("127.0.0.1:%d", uiPort)},
			Probe:     config.ProbeListener{HTTPAddr: fmt.Sprintf("127.0.0.1:%d", probeHTTP), UDPAddr: fmt.Sprintf("127.0.0.1:%d", probeUDP)},
		},
		Probe: config.ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: sec,
		},
		UI: config.UI{SessionSecret: sec, SessionTTLSeconds: 3600},
		Log: config.Log{Level: "info"},
	}
}

func saveStrict(path string, c *config.Config) error {
	if err := config.Save(path, c); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
```

(Add imports: `fmt`, `os`.)

Now `internal/pkg/cli/serve.go`:

```go
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/config"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	httpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/http"
	icmpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/icmp"
	tcpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/tcp"
	udpprobe "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
	"github.com/bsmr/mesh-checker/internal/pkg/scheduler"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
	serverprobe "github.com/bsmr/mesh-checker/internal/pkg/server/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/server/ui"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

func init() {
	register("serve", "run daemon + all three listeners", runServe)
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, err := config.ValidateWithWarnings(cfg); err != nil {
		return err
	}
	// In production refuse loose perms; in tests permissions can be 0600
	// already. The Chmod in CLI helpers takes care of this.
	if err := config.CheckMode(*cfgPath); err != nil {
		slog.Warn("serve: config permissions", "err", err)
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caPEM, err := os.ReadFile(cfg.PKI.CACertPath)
	if err != nil {
		return fmt.Errorf("serve: read CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return errors.New("serve: CA bundle has no certs")
	}
	hostTLSCert, err := tls.LoadX509KeyPair(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	if err != nil {
		return fmt.Errorf("serve: load host cert: %w", err)
	}

	udpSecret, err := base64.StdEncoding.DecodeString(cfg.Probe.UDPSharedSecret)
	if err != nil {
		return fmt.Errorf("serve: decode udp secret: %w", err)
	}
	sessionSecret, err := base64.StdEncoding.DecodeString(cfg.UI.SessionSecret)
	if err != nil {
		return err
	}

	st := store.New(cfg.Probe.RingbufferSize)

	probers := mustProbers(caPool, udpSecret, cfg)
	jobs := buildJobs(cfg, probers)

	sched := scheduler.New(scheduler.Config{
		Interval:      time.Duration(cfg.Probe.IntervalSeconds) * time.Second,
		JitterPercent: cfg.Probe.JitterPercent,
		Workers:       max(2*len(jobs), 4),
		Timeout:       time.Duration(cfg.Probe.TimeoutSeconds) * time.Second,
	}, jobs, st)

	_, ihPort, err := net.SplitHostPort(cfg.Listeners.InterHost.Addr)
	if err != nil {
		return fmt.Errorf("serve: parse interhost addr: %w", err)
	}
	peerNames := map[string]bool{cfg.Host.Name: true}
	peerURLs := map[string]string{cfg.Host.Name: "https://" + net.JoinHostPort(cfg.Host.AdvertiseAddr, ihPort)}
	for _, p := range cfg.Peers {
		peerNames[p.Name] = true
		peerURLs[p.Name] = "https://" + net.JoinHostPort(p.Addr, ihPort)
	}
	cl := interhost.NewClient(caPool, hostTLSCert, peerURLs)

	agg := aggregator.New(cl, st, cfg.Host.Name, peerNamesList(cfg), cfg.Probe.FailureWindow, cfg.Probe.FailureThreshold, 2*time.Second)

	ihMux := interhost.NewMux(interhost.Deps{
		MeshCA: caPool, HostCert: hostTLSCert, Peers: peerNames,
		FetchLocal: func() aggregator.ObserverView { return agg.Aggregate(context.Background()).Observers[cfg.Host.Name] },
	})
	ihServer := &http.Server{Addr: cfg.Listeners.InterHost.Addr, Handler: ihMux, TLSConfig: interhost.ServerTLSConfig(hostTLSCert, caPool)}

	sess := ui.NewSession(sessionSecret, time.Duration(cfg.UI.SessionTTLSeconds)*time.Second)
	loginH := ui.NewLoginHandler(cfg.UI.Users, sess, 250*time.Millisecond)
	sseH := ui.NewSSEHandler(agg, time.Second)
	uiMux := ui.NewMux(ui.Deps{Login: loginH, SSE: sseH, Session: sess})
	uiServer := &http.Server{Addr: cfg.Listeners.UI.Addr, Handler: uiMux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{hostTLSCert}, MinVersion: tls.VersionTLS12}}

	probeServer := &http.Server{Addr: cfg.Listeners.Probe.HTTPAddr, Handler: serverprobe.NewHTTPHandler()}

	allowed := map[string]bool{}
	for _, p := range cfg.Peers {
		allowed[p.Addr] = true
	}
	udpEcho, err := serverprobe.NewUDPEcho(cfg.Listeners.Probe.UDPAddr, udpSecret, allowed)
	if err != nil {
		return err
	}

	errCh := make(chan error, 4)
	go func() { errCh <- ihServer.ListenAndServeTLS(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath) }()
	go func() { errCh <- uiServer.ListenAndServeTLS(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath) }()
	go func() { errCh <- probeServer.ListenAndServe() }()
	go func() { udpEcho.Run(); errCh <- nil }()
	go sched.Run(ctx)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ihServer.Shutdown(shutdownCtx)
	_ = uiServer.Shutdown(shutdownCtx)
	_ = probeServer.Shutdown(shutdownCtx)
	_ = udpEcho.Close()
	return nil
}

func mustProbers(caPool *x509.CertPool, udpSecret []byte, cfg *config.Config) map[probe.Protocol]probe.Prober {
	timeout := time.Duration(cfg.Probe.TimeoutSeconds) * time.Second
	pr := map[probe.Protocol]probe.Prober{
		probe.TCP:   tcpprobe.New(timeout),
		probe.HTTPS: httpprobe.New(caPool, timeout),
		probe.UDP:   udpprobe.New(udpSecret, cfg.Host.Name, timeout),
	}
	icmpP, err := icmpprobe.New(timeout)
	if err != nil {
		slog.Warn("icmp prober unavailable; icmp checks will be skipped", "err", err)
	} else {
		pr[probe.ICMP] = icmpP
	}
	return pr
}

func buildJobs(cfg *config.Config, pr map[probe.Protocol]probe.Prober) []scheduler.Job {
	var jobs []scheduler.Job
	for _, p := range cfg.Peers {
		target := probe.Target{Name: p.Name, Addr: p.Addr, TCPPort: p.TCPPort, UDPPort: p.UDPPort, HTTPSURL: p.HTTPSURL}
		for _, ch := range p.Checks {
			pp := probe.Protocol(ch)
			prober, ok := pr[pp]
			if !ok {
				continue
			}
			jobs = append(jobs, scheduler.Job{Peer: p.Name, Protocol: pp, Target: target, Prober: prober})
		}
	}
	return jobs
}

func peerNamesList(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		out = append(out, p.Name)
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
```

The smoke test in Step 1 binds listeners to `127.0.0.1:<random>` and does not require the peer URLs to resolve to live hosts; only the local listener startup is exercised.

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/cli/ -v -run Serve`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/serve.go internal/pkg/cli/serve_test.go internal/pkg/cli/configio.go
git commit -s -m "feat(cli): add 'serve' subcommand wiring daemon + listeners"
```

---

### Task 28: `status` subcommand

**Files:**
- Create: `internal/pkg/cli/status.go`
- Create: `internal/pkg/cli/status_test.go`

Short-lived: builds a peer client from config + cert material, calls `/api/peer/status` on the local advertise address and every peer, prints the matrix as a tabwriter table.

- [ ] **Step 1: Failing test (with running stub server in-process)**

```go
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
)

func TestStatusTableContainsPeerName(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	hostA, _ := pki.GenerateHostCert(ca, "node-a", []string{"127.0.0.1"}, time.Hour)
	caCertPEM, _, _ := pki.Encode(ca)
	hostCertPEM, hostKeyPEM, _ := pki.Encode(hostA)
	dir := t.TempDir()
	must(t, writeStrict(dir+"/ca.crt", caCertPEM, 0o644))
	must(t, writeStrict(dir+"/node-a.crt", hostCertPEM, 0o644))
	must(t, writeStrict(dir+"/node-a.key", hostKeyPEM, 0o600))

	tlsCert, _ := tls.X509KeyPair(hostCertPEM, hostKeyPEM)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	deps := interhost.Deps{MeshCA: pool, HostCert: tlsCert, Peers: map[string]bool{"node-a": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{Host: "node-a", Reachable: true} }}
	ts := httptest.NewUnstartedServer(interhost.NewMux(deps))
	ts.TLS = interhost.ServerTLSConfig(tlsCert, pool)
	ts.StartTLS()
	defer ts.Close()

	port := ts.Listener.Addr().(*net.TCPAddr).Port

	cfg := newConfigSkeleton("node-a", "127.0.0.1", dir+"/ca.crt", dir+"/node-a.crt", dir+"/node-a.key", port, 0, 0, 0)
	cfgPath := dir + "/config.json"
	must(t, saveStrict(cfgPath, cfg))

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"status", "--config", cfgPath}, &stdout, &stderr); err != nil {
		t.Fatalf("status: %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "node-a") {
		t.Errorf("expected node-a in output, got %q", stdout.String())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
```

Remove the `"net/http"` import from the test if it is not otherwise needed; the production code (Step 3) uses it but the test file only needs `httptest` and the `interhost` helpers.

- [ ] **Step 2: Verify FAIL** — `go test ./internal/pkg/cli/`

- [ ] **Step 3: Implement**

```go
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
)

func init() {
	register("status", "show mesh status table", runStatus)
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := addConfigFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(cfg.PKI.CACertPath)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	tlsCert, err := tls.LoadX509KeyPair(cfg.PKI.HostCertPath, cfg.PKI.HostKeyPath)
	if err != nil {
		return err
	}

	_, ihPort, err := net.SplitHostPort(cfg.Listeners.InterHost.Addr)
	if err != nil {
		return err
	}
	urls := map[string]string{cfg.Host.Name: "https://" + net.JoinHostPort(cfg.Host.AdvertiseAddr, ihPort)}
	for _, p := range cfg.Peers {
		urls[p.Name] = "https://" + net.JoinHostPort(p.Addr, ihPort)
	}
	cl := interhost.NewClient(caPool, tlsCert, urls)

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tREACHABLE\tDETAIL")
	for name := range urls {
		ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
		v, err := cl.Fetch(ctx2, name)
		cancel()
		if err != nil {
			fmt.Fprintf(tw, "%s\tno\t%s\n", name, err.Error())
			continue
		}
		fmt.Fprintf(tw, "%s\tyes\t%d peers known\n", v.Host, len(v.Samples))
	}
	return tw.Flush()
}
```

- [ ] **Step 4: Verify PASS** — `go test ./internal/pkg/cli/ -v -run Status`

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/cli/status.go internal/pkg/cli/status_test.go
git commit -s -m "feat(cli): add 'status' subcommand"
```

---

### Task 29: systemd unit and install notes

**Files:**
- Create: `contrib/systemd/mesh-checker.service`
- Modify: `README.md`

- [ ] **Step 1: Write the unit**

```ini
[Unit]
Description=mesh-checker daemon
Documentation=https://git.nebula.muehmer.eu/bsmr/mesh-checker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mesh-checker
Group=mesh-checker
ExecStart=/usr/bin/mesh-checker serve --config /etc/mesh-checker/config.json
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/mesh-checker
ReadOnlyPaths=/etc/mesh-checker
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Extend README**

Replace the existing one-liner README with a short install/usage section that documents:
- `useradd --system mesh-checker`
- `setcap cap_net_raw=ep /usr/bin/mesh-checker`
- `mesh-checker pki init` / `pki cert` workflow
- `systemctl enable --now mesh-checker`
- the three default listener ports (8443/8080/7080+udp/7081)
- the mTLS trust assumption

Keep it under 80 lines. Do not duplicate the spec.

- [ ] **Step 3: Commit**

```bash
git add contrib/systemd/mesh-checker.service README.md
git commit -s -m "docs: add systemd unit and install instructions"
```

---

### Phase C Milestone — End-to-End Smoke

This is intentionally manual (or a `make e2e` if you want to encode it in compose). It is the proof that 0.1.0 actually works as one mesh.

- [ ] **Step 1: Generate three host certs**

```bash
D=/tmp/mesh-smoke && rm -rf $D && mkdir -p $D/{a,b,c}
./bin/mesh-checker pki init --ca-cert $D/ca.crt --ca-key $D/ca.key
for n in a b c; do
  ./bin/mesh-checker pki cert node-$n --ca-cert $D/ca.crt --ca-key $D/ca.key \
    --out-cert $D/$n/host.crt --out-key $D/$n/host.key --san 127.0.0.1
done
```

- [ ] **Step 2: Write three configs that point at each other on distinct port triplets**

(Use ports 8443/8080/7080/7081 for node-a; 8543/8180/7180/7181 for node-b; 8643/8280/7280/7281 for node-c. Each config lists the other two as peers.)

- [ ] **Step 3: Launch three daemons in three terminals**

```bash
./bin/mesh-checker serve --config $D/a/config.json
./bin/mesh-checker serve --config $D/b/config.json
./bin/mesh-checker serve --config $D/c/config.json
```

- [ ] **Step 4: Verify reachability**

```bash
./bin/mesh-checker status --config $D/a/config.json
# every host should show REACHABLE=yes
```

- [ ] **Step 5: Browse the UI**

Open `https://127.0.0.1:8080/ui/`, accept self-signed cert, log in with a user added via `mesh-checker user add admin --config $D/a/config.json`. Confirm: three observers, three peers, four protocols, all `up` after ~30 s.

- [ ] **Step 6: Tag and final commit**

```bash
git tag 0.1.0-rc1
go test -race ./...
```

End of Phase C. Merge `development-0.1.0-work` → `development-0.1.0-main` via squash + signoff (see global CLAUDE.md "Merge Rules"), then `-main` → `main`, then create `production-0.1.0`.

---

# Final Checklist

- [ ] All packages have `_test.go` coverage; `go test -race ./...` is green
- [ ] `govulncheck ./...` reports no high-severity findings (install: `go install golang.org/x/vuln/cmd/govulncheck@latest`)
- [ ] `bin/mesh-checker` is in `.gitignore` (already done in initial commit)
- [ ] `VERSION` file matches `internal/pkg/version.String()` (embedded — automatic)
- [ ] Phase C smoke passes locally with three daemons
- [ ] README + systemd unit committed
- [ ] Spec and plan committed to `docs/superpowers/{specs,plans}/`



