# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

`mesh-checker` checks ICMP, TCP, and UDP connections between nodes in a mesh network. The repository is in its initial state: a Go module (`github.com/bsmr/mesh-checker`, Go 1.26.3) is initialized but no source code exists yet.

Note: the module path is `github.com/bsmr/...` while the canonical hosting is `git.nebula.muehmer.eu/mesh-checker`. If a non-GitHub origin is intended as canonical, the module path should be updated before publishing the first tagged release — changing it later breaks importers.

When implementing, treat the README's one-liner as the canonical scope: a tool that probes reachability of mesh peers across ICMP/TCP/UDP. Any deviation (web UI, persistence layer, agent/collector split, etc.) is a design decision that must be brainstormed with the user first, not assumed.

## Language & Communication

- **Responses to the user**: always in Deutsch — short, precise, technical.
- **Everything else** (code, commits, code comments, file contents): always in English.
- **Prompt correction**: before answering, check the user's Deutsch prompt for style, grammar, and spelling. On errors: short correction first, then the actual answer.
- **Style (all languages)**: precise, terse, technical. No filler.

## Go Conventions

This is a Go project (per `.gitignore` template). The following are mandatory:

### `main()` → `run()` pattern

`main()` is a thin wrapper; all logic lives in `run()` so the CLI is unit-testable (`main()` calls `os.Exit`, which cannot be intercepted in tests).

```go
func main() {
	if err := run(context.Background(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// flag parsing, config assembly...
	// delegate to a service package in internal/pkg/
	return nil
}
```

Rules:
- `os.Exit` lives only in `main()`.
- `run()` handles the CLI layer (flags, env, config) and delegates business logic to a package in `internal/pkg/`.
- `run()` accepts `context.Context` and `io.Writer`s — no globals, no direct `os.Stdout`/`os.Stderr` access inside the service.
- Signal handling via `signal.NotifyContext` inside `run()`.
- Return errors; never log-and-exit.

### Build output

- Always build into `bin/`: `go build -o bin/<name> ./cmd/<name>`.
- Never run bare `go build` — it pollutes the project root.
- `bin/` must be in `.gitignore` once it exists.

### Tests and documentation

- Every package needs `_test.go` files with meaningful coverage.
- Write tests first, then implement.
- Non-obvious logic gets inline comments; the package gets package-level docs.

## Caveats Specific to this Project

- ICMP typically requires elevated privileges (raw sockets or `CAP_NET_RAW` on Linux, root on most other UNIX-likes). Either document the privilege requirement or use the unprivileged "ping group" mechanism (`net.ListenPacket("ip4:icmp", …)` won't work unprivileged — use `ListenPacket("udp4", …)` with `setcap cap_net_raw` or the `ping_group_range` sysctl). Decide explicitly before implementing.
- For mesh checks, the input format (peer list, mesh topology source) is not yet defined. Confirm with the user before assuming a format (static file vs. discovery vs. integration with an existing mesh controller like Nebula).
