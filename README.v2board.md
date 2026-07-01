# v2board WireGuard backend

This repository now ships `v2board-wireguard`, a Linux-only backend daemon for v2board WireGuard nodes.

## Runtime contract

The daemon talks to v2board UniProxy endpoints:

- `GET /api/v1/server/UniProxy/config`
- `GET /api/v1/server/UniProxy/user`
- `POST /api/v1/server/UniProxy/traffic-cumulative`
- `POST /api/v1/server/UniProxy/status`

Every request uses the standard query parameters:

- `token`
- `node_type=wireguard`
- `node_id`

The daemon stores the last good panel snapshot in SQLite and reuses it when the panel is temporarily unreachable.

## Host requirements

- Linux with WireGuard kernel support.
- `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- `nft` for NAT/filtering.
- `tc` from `iproute2` for per-peer ingress/egress policing.
- `net.ipv4.ip_forward=1`.
- `net.ipv6.conf.all.forwarding=1` when the v2board node uses IPv6 routed or NAT mode.
- Rust 1.87+ when building from source.

## v2board requirements

- Run the WireGuard migrations before starting the daemon.
- Set `WIREGUARD_PRIVATE_KEY_ENCRYPTION_KEY` to a 32-byte `base64:` key before creating WireGuard nodes.
- Do not clear or change `WIREGUARD_PRIVATE_KEY_ENCRYPTION_KEY` after WireGuard nodes or peers exist unless historical keys are configured and `wireguard:reencrypt-keys` has completed.
- Keep Horizon or another worker consuming `traffic_fetch`; `traffic-cumulative` only enqueues positive deltas.
- Use `/api/v1/server/UniProxy/...` as the canonical endpoint path. Lowercase `/uniproxy/...` is compatibility-only.

## Build

```bash
cargo build --release --features v2board-daemon --bin v2board-wireguard
install -m 0755 target/release/v2board-wireguard /usr/local/bin/v2board-wireguard
```

## Configure

Copy `deploy/config/v2board-wireguard.toml` to `/etc/v2board-wireguard/config.toml` and set:

- `panel.base_url`
- `panel.token`
- `panel.node_id`
- `wireguard.interface`
- `wireguard.online_handshake_window_secs` if the default online window is too wide or too narrow
- `firewall.outbound_interface` when NAT must be pinned to one uplink

Use an HTTPS `panel.base_url` in production. UniProxy currently authenticates with a query token, so panel reverse proxies must either avoid access logging on `/api/v1/server/UniProxy/*` or redact query strings before writing logs.

## systemd

```bash
install -d -m 0750 /etc/v2board-wireguard
install -d -m 0700 /var/lib/v2board-wireguard
install -m 0600 deploy/config/v2board-wireguard.toml /etc/v2board-wireguard/config.toml
install -m 0644 deploy/systemd/v2board-wireguard.service /etc/systemd/system/v2board-wireguard.service
systemctl daemon-reload
systemctl enable --now v2board-wireguard
```

## Docker host network

```bash
cd deploy/docker
docker compose up -d --build
```

The container must use host networking. WireGuard interfaces, nftables rules, and tc filters are host network state, so bridge networking is not a valid production mode.

## v2board Docker self-test

When using the sibling `v2board-docker` test environment, run:

```bash
cd ../v2board-docker
scripts/selftest_wireguard.sh
```

The default self-test validates v2board schema, encryption-key configuration, UniProxy `config/user/status/traffic-cumulative`, queue-backed traffic accounting, ETag/MessagePack-sensitive response paths, and cleanup. It does not create a host WireGuard interface unless explicitly requested:

```bash
RUN_WG_DAEMON=1 ALLOW_HOST_WG_TEST=1 scripts/selftest_wireguard.sh
```

## Traffic accounting

WireGuard kernel counters are cumulative. The daemon reports cumulative peer counters to v2board with a unique `report_id`. v2board records the last counter per peer and only sends positive deltas into the existing traffic/stat jobs. Repeating the same report is idempotent.

Do not use the legacy UniProxy `push` endpoint for this daemon. `push` is incremental and not idempotent, so retrying it can double count traffic.

Direction mapping:

- WireGuard `rx_bytes` -> v2board upload
- WireGuard `tx_bytes` -> v2board download

## Reconcile behavior

The daemon applies full interface configuration when `config_version` changes and then reconciles peers one by one. Stale peers that no longer appear in v2board are removed. Panel outages do not remove peers; the daemon uses the cached snapshot and logs a degraded refresh.
