# mesh-checker

Check ICMP, TCP, UDP, and HTTPS reachability between hosts in a mesh.

Each instance probes every other configured peer on all four protocols and
serves a browser UI that aggregates every peer's view via an authenticated
mTLS inter-host API.

## Build

```sh
go build -ldflags "-X github.com/bsmr/mesh-checker/internal/pkg/version.version=$(cat VERSION)" \
  -o bin/mesh-checker ./cmd/mesh-checker
```

## Install (Linux)

```sh
# 1. System user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mesh-checker

# 2. Binary in place + cap_net_raw for ICMP
sudo install -o root -g root -m 0755 bin/mesh-checker /usr/bin/mesh-checker
sudo setcap cap_net_raw=ep /usr/bin/mesh-checker

# 3. Directories
sudo install -d -o mesh-checker -g mesh-checker -m 0750 /etc/mesh-checker /etc/mesh-checker/pki /var/lib/mesh-checker

# 4. Bootstrap PKI (one host generates the CA, distributes ca.crt to all peers)
sudo -u mesh-checker mesh-checker pki init \
  --ca-cert /etc/mesh-checker/pki/ca.crt \
  --ca-key  /etc/mesh-checker/pki/ca.key

sudo -u mesh-checker mesh-checker pki cert "$(hostname)" \
  --ca-cert /etc/mesh-checker/pki/ca.crt --ca-key /etc/mesh-checker/pki/ca.key \
  --out-cert /etc/mesh-checker/pki/host.crt --out-key /etc/mesh-checker/pki/host.key \
  --san "$(hostname -I | awk '{print $1}')"

# 5. Create /etc/mesh-checker/config.json (see Configuration), then chmod 0600.

# 6. systemd
sudo install -m 0644 contrib/systemd/mesh-checker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mesh-checker
```

## Listeners (defaults)

| Port | Proto | Purpose                                                  |
| ---- | ----- | -------------------------------------------------------- |
| 8443 | HTTPS | Inter-host API (mTLS required, peers only)               |
| 8080 | HTTPS | Browser UI (session cookie); also serves `/probe` unauth |
| 7080 | HTTP  | Probe target (`GET /probe` -> 200, no auth)              |
| 7081 | UDP   | UDP echo (HMAC-authenticated, peer-IP allowlist)         |

## Configuration

Single file at `/etc/mesh-checker/config.json`, mode `0600`, owner
`mesh-checker:mesh-checker`. The daemon refuses to start with looser
permissions.

Edit via the CLI subcommands rather than by hand:

```sh
mesh-checker host add node-b 10.0.0.2
mesh-checker user add admin
mesh-checker config validate
```

See `docs/superpowers/specs/2026-05-24-mesh-checker-0.1.0-design.md` for the
full schema and security model.

## Subcommands

| Command                         | Purpose                                        |
| ------------------------------- | ---------------------------------------------- |
| `serve`                         | Run daemon + all three listeners               |
| `pki init`                      | Generate Mesh CA                               |
| `pki cert <host>`               | Sign a host certificate under the CA           |
| `host add <name> <addr>`        | Add a peer to the configuration                |
| `host remove <name>`            | Remove a peer                                  |
| `host list`                     | Print configured peers                         |
| `user add <name>`               | Prompt for password, store bcrypt hash         |
| `user remove <name>`            | Remove a UI user                               |
| `config validate`               | Parse + schema-check the config                |
| `status`                        | Pull every peer and print the mesh matrix      |

## Trust Model

- Peer-to-peer is mTLS only. Each host has a certificate signed by the
  shared Mesh CA; both server and client validate against that CA, and the
  server additionally checks the certificate CN against the configured
  peer list.
- The UI is HTTPS with bcrypt-hashed user passwords and signed session
  cookies. The default listen address is your routable interface — bind to
  `127.0.0.1` if SSH-tunnel access is preferred.
- The UDP echo authenticates requests with HMAC-SHA256 over the shared
  secret from the config; replies are strictly smaller than requests
  (anti-amplification).

## Caveats

- IPv4 only in 0.1.0.
- No hot reload — config changes require `systemctl restart mesh-checker`.
- Probe history is in-memory; lost on restart.
- ICMP requires `cap_net_raw` on the binary (set by step 2 above) or the
  daemon falls back silently (ICMP checks become permanent failures).
- All hosts must share a reasonably accurate clock (NTP) — the UDP HMAC
  rejects timestamps more than 30 s skewed.

## License

MIT — see [LICENSE](LICENSE).
