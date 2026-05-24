# mesh-checker 0.1.0 — Design Specification

- **Date:** 2026-05-24
- **Target release:** 0.1.0
- **Status:** Draft, pending user review

## 1. Goals

Provide a self-hosted mesh reachability monitor that runs on every participating Linux host. Each node:

1. Probes every other node on ICMP, TCP, UDP, and HTTPS at a configurable interval.
2. Stores the last N samples per `(peer, protocol)` in memory.
3. Serves a browser UI that shows the full mesh view by pulling each peer's local view via an authenticated inter-host API and merging the responses.
4. Serves as a probe target for its peers (HTTP `/probe`, TCP connect, UDP echo).
5. Is administered by a CLI that edits a single JSON configuration file and bootstraps the PKI material.

Non-goals for 0.1.0: remote installation, remote daemon administration, persistent history, automatic certificate rotation, IPv6, non-Linux platforms.

## 2. Distribution

- One binary, `mesh-checker`, with subcommands for every role (daemon, CLI helpers, PKI helpers).
- Linux only, `amd64` and `arm64`. Built with `go build -o bin/mesh-checker ./cmd/mesh-checker`.
- Runtime user: a dedicated system user `mesh-checker`. The binary carries `cap_net_raw=ep` (set by the package post-install, or manually by the admin) so the daemon can open ICMP sockets without running as root.

## 3. Architecture

```
                +-------------------+      mTLS pull (status fan-out)
                |   mesh-checker    |  <----------------------+
                |       serve       |                         |
+---------+     |                   |     +------------+      |
|  Admin  |---->|  CLI subcommands  |     |  Other     |------+
| (shell) |     |  - host …         |     |  daemon    |
+---------+     |  - user …         |     |  (peer)    |
                |  - pki …          |     +------------+
                |  - status         |
                |  - config …       |
                +---------+---------+
                          |
                +---------v---------+
                |     Daemon        |
                |  - Scheduler      |
                |  - Worker pool    |
                |  - 4 Probers      |
                |  - Ringbuffer     |
                |  - Classifier     |
                +---------+---------+
                          |
        +-----------------+--------------------+
        |                 |                    |
+-------v-------+  +------v------+  +----------v---------+
| Listener:     |  | Listener:   |  | Listener:          |
| Inter-host    |  | UI          |  | Probe target       |
| HTTPS + mTLS  |  | HTTPS+Auth  |  | HTTP /probe + UDP  |
| /api/peer/*   |  | /ui/* + SSE |  | echo               |
| :8443         |  | :8080       |  | :7080 / udp:7081   |
+---------------+  +-------------+  +--------------------+
```

A single long-running process (`mesh-checker serve`) hosts the daemon and all three listeners. CLI helper subcommands are short-lived; they read or rewrite the JSON config and exit.

## 4. Code Layout

Domain-oriented packages under `internal/pkg/`. Each package owns one concept and is independently testable:

```
cmd/mesh-checker/         # main() only; dispatches to internal/pkg/cli
internal/pkg/cli/         # subcommand wiring (flag.NewFlagSet per subcommand)
internal/pkg/config/      # JSON load/save/validate, schema versioning, file-mode check
internal/pkg/pki/         # CA + host cert generation, loading, validation
internal/pkg/probe/       # Prober interface + icmp, tcp, udp, http implementations
internal/pkg/scheduler/   # ticker, jitter, worker pool, job dispatch
internal/pkg/store/       # in-memory ringbuffer per (peer, protocol)
internal/pkg/classifier/  # sliding-window state machine (up | degraded | down)
internal/pkg/server/      # three listener constructors + handlers
internal/pkg/aggregator/  # peer fan-out for the UI view
internal/pkg/ui/          # go:embed assets + SSE handler
internal/pkg/version/     # build-info constants (set via -ldflags)
```

## 5. CLI Reference

All subcommands take `--config <path>` (default `/etc/mesh-checker/config.json`).

| Subcommand                            | Purpose                                                                 |
| ------------------------------------- | ----------------------------------------------------------------------- |
| `serve`                               | Run the daemon and all three listeners until signalled.                 |
| `pki init`                            | Generate Mesh CA (key + cert). Writes to `pki.caCertPath` / `caKeyPath`.|
| `pki cert <host>`                     | Generate a host cert (server+client EKU) signed by the Mesh CA.         |
| `host add <name> <addr> [--checks …]` | Add a peer to `peers[]`. Default checks: all four.                      |
| `host remove <name>`                  | Remove a peer.                                                          |
| `host list`                           | Print peers as a table.                                                 |
| `user add <name>`                     | Prompt for password (stdin, no echo), append bcrypt hash to `ui.users`. |
| `user remove <name>`                  | Remove UI user.                                                         |
| `status`                              | Print the mesh matrix as a table. The CLI process is short-lived and has no in-memory store; it builds the matrix by calling `/api/peer/status` on every peer **and** on the local advertise address (using the local host cert as both server and client material). If the local daemon isn't running, the local column shows `unknown` and the command exits 0 with a stderr note. |
| `config validate`                     | Parse, schema-check, file-mode-check; exit 0 on success.                |

The CA private key is only read by `pki init` and `pki cert`. The daemon never needs it.

## 6. Configuration

Single JSON file. Default path `/etc/mesh-checker/config.json`. File mode must be `0600`, owner `mesh-checker:mesh-checker`; the daemon refuses to start otherwise.

### 6.1 Schema (v1)

```json
{
  "schemaVersion": 1,
  "host": {
    "name": "node-a",
    "advertiseAddr": "10.0.0.1"
  },
  "pki": {
    "caCertPath":   "/etc/mesh-checker/pki/ca.crt",
    "caKeyPath":    "/etc/mesh-checker/pki/ca.key",
    "hostCertPath": "/etc/mesh-checker/pki/node-a.crt",
    "hostKeyPath":  "/etc/mesh-checker/pki/node-a.key"
  },
  "listeners": {
    "interhost": { "addr": "0.0.0.0:8443" },
    "ui":        { "addr": "0.0.0.0:8080" },
    "probe":     { "httpAddr": "0.0.0.0:7080", "udpAddr": "0.0.0.0:7081" }
  },
  "probe": {
    "intervalSeconds":  10,
    "jitterPercent":    10,
    "timeoutSeconds":   3,
    "failureWindow":    5,
    "failureThreshold": 3,
    "ringbufferSize":   100,
    "udpSharedSecret":  "<base64 32 bytes>"
  },
  "peers": [
    { "name": "node-b", "addr": "10.0.0.2",
      "checks": ["icmp", "tcp", "udp", "https"],
      "tcpPort": 8443, "udpPort": 7081, "httpsURL": "https://10.0.0.2:8080/probe" }
  ],
  "ui": {
    "users": [
      { "name": "admin", "passwordHash": "$2b$12$..." }
    ],
    "sessionSecret": "<base64 32 bytes>",
    "sessionTTLSeconds": 28800
  },
  "log": { "level": "info" }
}
```

### 6.2 Validation Rules

- `schemaVersion` must equal 1; on mismatch the daemon refuses to start.
- `host.name` must equal the CN of the loaded host cert.
- `peers[].name` must be unique; loopback (`host.name` itself) may appear and is treated as a self-check target.
- `udpSharedSecret` and `ui.sessionSecret` must each decode to 32 bytes.
- Every `peers[].checks` entry must be one of `icmp | tcp | udp | https`; the daemon ignores unknown entries with a warning.
- `probe.failureThreshold <= probe.failureWindow`.
- `pki.caKeyPath` is only read by `pki init` and `pki cert <host>`. The daemon must refuse to read it; the file's existence (or absence) does not affect `serve`.

### 6.3 Reload

No hot-reload in 0.1.0. Changes require `systemctl restart mesh-checker`. The CLI helpers write atomically (`os.WriteFile` to a temp file + `os.Rename`) so a concurrent daemon read never sees a partial file, but the running daemon won't pick up the new file until restart.

## 7. Listeners and Endpoints

### 7.1 Inter-host listener (`:8443`)

- HTTPS, `tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: meshCA}`.
- Handler accepts a request only if the client cert's CN matches an entry in `peers[].name` (defence-in-depth on top of `RequireAndVerifyClientCert`).
- Endpoints:
  - `GET /api/peer/status` → JSON: `{"host": "node-a", "samples": { "<peer>": { "<proto>": { "state": "up|degraded|down", "lastSample": {...}, "history": [...] } } } }`.
  - `GET /api/peer/version` → JSON: `{"version": "0.1.0", "schemaVersion": 1}`.
- Read-only in 0.1.0. No mutation endpoints.

### 7.2 UI listener (`:8080`)

- HTTPS using the same host cert (no client-cert requirement).
- Endpoints:
  - `GET /ui/` → embedded `index.html` (vanilla JS, no build step, served via `go:embed`).
  - `GET /ui/assets/*` → embedded static files.
  - `POST /ui/login` → form post `name=…&password=…`; on success sets `mesh-session` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), 256-bit value HMAC-signed with `ui.sessionSecret`, TTL `sessionTTLSeconds`.
  - `POST /ui/logout` → clears cookie.
  - `GET /ui/sse/status` → `text/event-stream`. Server tick every 1 s: aggregator runs (see §8.3), JSON payload pushed as one SSE event named `status`.
  - `GET /probe` → `200 OK`, body `mesh-checker 0.1.0\n`, **no authentication**. This is the target of the HTTPS reachability check (see §9.4). It is the only unauthenticated endpoint on this listener.
- All `/ui/*` endpoints except `/ui/login` require a valid session cookie. Failed bcrypt comparison sleeps 250 ms before responding to slow online brute force.

### 7.3 Probe target listener (`:7080` HTTP, `:7081` UDP)

- HTTP: `GET /probe` → `200 OK`, body `mesh-checker 0.1.0\n`, `Cache-Control: no-store`. No auth, no state.
- UDP: see §9.3.

## 8. Daemon Internals

### 8.1 Scheduler

- For each `(peer, protocol)` enabled in config, the scheduler enqueues a `Job` every `intervalSeconds ± jitterPercent`.
- Jobs are pulled by a bounded worker pool sized `min(runtime.NumCPU()*4, 2 * |peers|*|protocols|)`.
- Each worker invokes the corresponding `Prober.Probe(ctx, target) (Result, error)` with `context.WithTimeout(ctx, timeoutSeconds)`.
- The result is appended to the ringbuffer for that `(peer, protocol)`.

### 8.2 Classifier

Sliding window of the last `failureWindow` samples per `(peer, protocol)`:

- `down` if `>= failureThreshold` of the last `failureWindow` samples failed.
- `up` if all `failureWindow` samples succeeded.
- `degraded` otherwise.

States are derived on read, not stored separately — the ringbuffer is the only source of truth.

### 8.3 Aggregator (used by UI SSE)

On each SSE tick:

1. Build local view from the store.
2. Concurrently `GET /api/peer/status` to every peer via the inter-host mTLS client (built from our own host cert+key, trusting Mesh CA).
3. Merge: for each `(observerHost, peer, protocol)` keep the responding observer's state. Peers that don't respond within 2 s contribute a `state: "unknown", reason: "peer unreachable"` entry rather than dropping.
4. Emit the merged JSON.

The local-only `status` CLI subcommand uses the same aggregator path against loopback + peers.

## 9. Probers

All probers implement:

```go
type Prober interface {
    Probe(ctx context.Context, target Target) (Result, error)
}

type Target struct {
    Name, Addr string
    TCPPort, UDPPort int
    HTTPSURL string
}

type Result struct {
    Timestamp time.Time
    Latency   time.Duration
    OK        bool
    Err       string // empty on success
}
```

### 9.1 ICMP

- Uses `golang.org/x/net/icmp` with a raw socket (`ip4:icmp`). Requires `cap_net_raw`.
- Identifier = `os.Getpid() & 0xffff`, sequence increments per probe.
- A single goroutine owns the raw socket and demultiplexes replies to probe requests via a `map[seq]chan Result`.
- Timeout from `probe.timeoutSeconds`.

### 9.2 TCP

- `net.DialTimeout("tcp", target.Addr+":"+target.TCPPort, timeout)`.
- On success: `conn.Close()` immediately, `OK=true`, `Latency = time.Since(start)`.
- No protocol-level handshake. Connects against the inter-host or UI port — both are real listeners.

### 9.3 UDP

- Client builds payload: `nonce (16B) || timestamp (8B, big-endian unix-nano) || hostName (variable) || HMAC-SHA256(udpSharedSecret, nonce||timestamp||hostName)` (HMAC tag last, 32 B).
- Sends UDP packet to `target.Addr:target.UDPPort`. Waits for echoed packet with the same nonce.
- UDP echo server (in the probe-target listener):
  - Parses payload, verifies HMAC, verifies source IP is in peer list, verifies `|now - timestamp| < 30 s`, verifies nonce not in 60 s replay cache.
  - On success: echoes back `nonce (16B) || HMAC-SHA256(udpSharedSecret, nonce||responseTimestamp) || responseTimestamp (8B)` — strictly **smaller** than the request payload (anti-amplification).
  - On failure: silent drop (no error reply to avoid being a probe oracle).

### 9.4 HTTPS

- Target: the peer's UI-listener `GET /probe` endpoint (see §7.2). `httpsURL` defaults to `https://<peer.addr>:<ui-port>/probe` if omitted.
- `http.Client` with `Transport.TLSClientConfig.RootCAs = meshCAPool` — peer certs are signed by the Mesh CA, not by a public CA, so system roots would reject them.
- Expects `200 OK`, body must contain `mesh-checker` substring.
- No client cert sent (the UI listener doesn't ask for one). This check therefore validates "TLS handshake against mesh CA works and listener answers", which is the intent of an HTTPS-reachability check.
- `httpsInsecureSkipVerify` is **not** a config option — if Mesh-CA trust is broken, the check should fail loudly.

## 10. Security Model

| Surface              | Protection                                                                                   |
| -------------------- | -------------------------------------------------------------------------------------------- |
| Inter-host API       | mTLS, mesh CA only, CN-against-peer-list double-check, read-only.                            |
| UI                   | bcrypt passwords (cost 12), signed cookie, fixed 250 ms delay on failed login.               |
| UDP echo             | HMAC-SHA256, nonce replay cache, 30 s timestamp window, source-IP whitelist, response ≤ request. |
| HTTP probe target    | No auth, immutable response, no state.                                                       |
| Config file          | `0600`, daemon refuses looser permissions.                                                   |
| PKI private keys     | `0600`, daemon refuses looser permissions; CA key only touched by `pki` subcommands.         |
| Logs (`log/slog` JSON on stderr) | Never log secrets, tokens, cookie values, or full HTTP bodies.                   |
| Privileges           | Daemon runs as `mesh-checker`, not root. ICMP via `cap_net_raw`.                             |
| Supply chain         | `go mod tidy` + `govulncheck` in CI. No vendoring in 0.1.0.                                  |

## 11. Error Handling Policy

- Probe failures are normal data, not errors — they go into the ringbuffer as `OK=false`.
- Errors that the daemon cannot recover from (bad config, missing cert, unwritable port) cause `serve` to exit non-zero with one structured log line; systemd restarts it.
- Errors per request in the inter-host API return appropriate HTTP status with no detail in the body (status only); detail goes to logs.
- Panics: every goroutine entry-point (`scheduler` workers, HTTP handlers, UDP listener loop) is wrapped in `defer recover()` that logs and continues, never crashes the process.

## 12. Test Strategy

- Unit tests per package, run via `go test ./...`. CI gate: coverage ≥ 80 % on `internal/pkg/...`.
- `internal/pkg/probe`: Prober-interface fakes for scheduler tests. HTTPS prober tested against `httptest.NewTLSServer`. TCP/UDP probers tested against ephemeral `127.0.0.1:0` listeners with the real prober code.
- `internal/pkg/probe/icmp`: pure tests for packet build/parse; live ICMP under `//go:build integration` tag, executed only in a privileged CI stage.
- `internal/pkg/server`: every listener tested with `httptest.NewUnstartedServer` plus a configured `tls.Config`; mTLS handshake exercised end-to-end with throw-away in-memory CA.
- `internal/pkg/pki`: pure tests (no filesystem) for cert generation; round-trip parse back.
- `internal/pkg/cli`: each subcommand tested via `cli.Run(ctx, args, stdout, stderr)` with a temp `--config` file.
- Optional E2E: `make e2e` brings up three Docker containers via `docker-compose.test.yml`, runs a smoke that asserts every peer eventually sees every other peer as `up`. Not part of `go test ./...`.

## 13. Open Items and Risks

- **CA key handling**: `pki init` writes the CA private key to `pki.caKeyPath` (mode `0600`). The daemon never reads it. If the admin loses it, new hosts can't be enrolled — accepted limitation for 0.1.0 (regenerate the mesh).
- **Clock skew**: UDP HMAC has a 30 s timestamp window; this requires NTP on all hosts. Not enforced, documented in README only.
- **Uniform inter-host port**: the daemon and the `status` CLI build peer URLs as `https://<peer.addr>:<own inter-host port>`. Every peer in the mesh must therefore listen on the same `listeners.interhost.addr` port. No per-peer port field in 0.1.0; deferred to 0.2.0 (`peers[].interHostPort`). Documented in README "Caveats".
- **IPv6**: out of scope, but `listeners.*.addr` accepts IPv6 syntax syntactically; behaviour with IPv6 peers is undefined in 0.1.0.
- **`govulncheck` cadence**: not yet decided where it runs (pre-commit hook vs. CI only). Picked up by the implementation plan.
- **Documentation**: README, install instructions, and `man mesh-checker` are part of the implementation plan, not this design.

## 14. Out of Scope for 0.1.0

- Remote installation of the binary on peers
- Remote administration of a daemon over the network (all admin is local-host CLI)
- Hot-reload of the configuration
- Persistent storage of probe history
- Certificate rotation, CRL, OCSP
- Prometheus or other metrics endpoints
- Non-Linux platforms
- IPv6 first-class support
- Mesh-wide consensus on observed state (each observer's view stands on its own; UI just displays the matrix)
