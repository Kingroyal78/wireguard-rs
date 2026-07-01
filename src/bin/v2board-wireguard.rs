#[cfg(not(target_os = "linux"))]
compile_error!("v2board-wireguard daemon only supports Linux");

use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, key::Key, net::IpAddrMask,
    peer::Peer,
};
use reqwest::blocking::Client;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "v2board-wireguard")]
#[command(about = "Linux WireGuard backend daemon for v2board UniProxy")]
struct Args {
    #[arg(short, long, env = "V2BOARD_WIREGUARD_CONFIG")]
    config: PathBuf,

    #[arg(long, env = "V2BOARD_WIREGUARD_ONCE")]
    once: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct DaemonConfig {
    panel: PanelConfig,
    wireguard: LocalWireguardConfig,
    state: StateConfig,
    #[serde(default)]
    firewall: FirewallConfig,
    #[serde(default)]
    rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct PanelConfig {
    base_url: String,
    token: String,
    node_id: u64,
    #[serde(default = "default_node_type")]
    node_type: String,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalWireguardConfig {
    interface: String,
    #[serde(default)]
    fwmark: Option<u32>,
    #[serde(default)]
    online_handshake_window_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct StateConfig {
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct FirewallConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_firewall_backend")]
    backend: String,
    #[serde(default)]
    outbound_interface: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: default_firewall_backend(),
            outbound_interface: None,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RateLimitConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    dry_run: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BaseConfig {
    #[serde(default = "default_interval")]
    pull_interval: u64,
    #[serde(default = "default_interval")]
    push_interval: u64,
    #[serde(default)]
    node_report_min_traffic: u64,
}

impl Default for BaseConfig {
    fn default() -> Self {
        Self {
            pull_interval: default_interval(),
            push_interval: default_interval(),
            node_report_min_traffic: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ServerConfig {
    #[serde(default = "default_config_version")]
    config_version: u64,
    server_port: u16,
    private_key: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    interface_ip: Option<String>,
    #[serde(default)]
    interface_ipv4: Option<String>,
    #[serde(default)]
    address_pool: Option<String>,
    #[serde(default)]
    address_pool_ipv4: Option<String>,
    #[serde(default)]
    interface_ipv6: Option<String>,
    #[serde(default)]
    address_pool_ipv6: Option<String>,
    #[serde(default = "default_ipv6_mode")]
    ipv6_mode: String,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    #[serde(default)]
    base_config: BaseConfig,
}

impl ServerConfig {
    fn interface_ipv4(&self) -> Result<&str> {
        self.interface_ipv4
            .as_deref()
            .or(self.interface_ip.as_deref())
            .context("v2board config is missing interface_ip/interface_ipv4")
    }

    fn address_pool_ipv4(&self) -> Result<&str> {
        self.address_pool_ipv4
            .as_deref()
            .or(self.address_pool.as_deref())
            .context("v2board config is missing address_pool/address_pool_ipv4")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct UsersResponse {
    users: Vec<UserPayload>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct UserPayload {
    id: u64,
    #[serde(default)]
    speed_limit: Option<u64>,
    #[serde(default)]
    device_limit: Option<u64>,
    #[serde(default)]
    wireguard: Option<PeerPayload>,
    #[serde(default)]
    wireguard_peers: Vec<PeerPayload>,
}

impl UserPayload {
    fn peers(&self) -> Vec<PeerPayload> {
        if !self.wireguard_peers.is_empty() {
            return self.wireguard_peers.clone();
        }

        self.wireguard.clone().into_iter().collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PeerPayload {
    #[serde(default)]
    peer_id: Option<u64>,
    #[serde(default)]
    user_id: Option<u64>,
    #[serde(default)]
    device_id: Option<String>,
    public_key: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Option<String>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    speed_limit: Option<u64>,
    #[serde(default)]
    device_limit: Option<u64>,
    #[serde(default)]
    enabled: Option<i64>,
    #[serde(default)]
    revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    config: ServerConfig,
    users: Vec<UserPayload>,
}

#[derive(Debug, Clone)]
struct DesiredPeer {
    peer_id: Option<u64>,
    user_id: u64,
    device_id: String,
    public_key: Key,
    public_key_string: String,
    allowed_ips: Vec<IpAddrMask>,
    speed_limit_mbps: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TrafficReport {
    report_id: String,
    reported_at: u64,
    peers: Vec<TrafficPeerReport>,
}

#[derive(Debug, Serialize)]
struct TrafficPeerReport {
    peer_id: Option<u64>,
    user_id: u64,
    device_id: String,
    public_key: String,
    upload: u64,
    download: u64,
    last_handshake_at: Option<u64>,
    last_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusReport {
    reported_at: u64,
    online: usize,
    peers: Vec<StatusPeerReport>,
}

#[derive(Debug, Serialize)]
struct StatusPeerReport {
    peer_id: Option<u64>,
    user_id: u64,
    device_id: String,
    public_key: String,
    last_handshake_at: Option<u64>,
    last_endpoint: Option<String>,
}

fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();
    let config = load_config(&args.config)?;
    Runtime::new(config)?.run(args.once)
}

fn load_config(path: &PathBuf) -> Result<DaemonConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse config {}", path.display()))
}

struct Runtime {
    config: DaemonConfig,
    panel: PanelClient,
    state: StateStore,
    wg: WireguardManager,
    net: NetManager,
    desired: HashMap<Key, DesiredPeer>,
    last_config_version: Option<u64>,
    report_sequence: u64,
    ipv6_forwarding_warning_emitted: bool,
}

impl Runtime {
    fn new(config: DaemonConfig) -> Result<Self> {
        let panel = PanelClient::new(config.panel.clone())?;
        let state = StateStore::open(config.state.path.clone())?;
        let wg = WireguardManager::new(config.wireguard.clone())?;
        let net = NetManager::new(
            config.wireguard.interface.clone(),
            config.firewall.clone(),
            config.rate_limit.clone(),
        );

        Ok(Self {
            config,
            panel,
            state,
            wg,
            net,
            desired: HashMap::new(),
            last_config_version: None,
            report_sequence: 0,
            ipv6_forwarding_warning_emitted: false,
        })
    }

    fn run(mut self, once: bool) -> Result<()> {
        let mut next_pull = Instant::now();
        let mut next_report = Instant::now();
        let mut base = BaseConfig::default();

        loop {
            if Instant::now() >= next_pull {
                base = match self.refresh_snapshot() {
                    Ok(snapshot) => match self.apply_snapshot(&snapshot) {
                        Ok(()) => {
                            self.state.save_snapshot(&snapshot)?;
                            snapshot.config.base_config.clone()
                        }
                        Err(error) => self.apply_cached_snapshot(error)?,
                    },
                    Err(error) => self.apply_cached_snapshot(error)?,
                };

                next_pull = Instant::now() + Duration::from_secs(base.pull_interval.max(5));
            }

            if Instant::now() >= next_report {
                if let Err(error) = self.report_runtime(
                    base.node_report_min_traffic,
                    self.online_handshake_window_secs(&base),
                    true,
                ) {
                    error!(%error, "runtime report failed");
                }
                next_report = Instant::now() + Duration::from_secs(base.push_interval.max(5));
            }

            if once {
                break;
            }

            thread::sleep(Duration::from_secs(1));
        }

        Ok(())
    }

    fn refresh_snapshot(&self) -> Result<Snapshot> {
        let config = self.panel.config()?;
        let users = self.panel.users()?.users;
        Ok(Snapshot { config, users })
    }

    fn apply_cached_snapshot(&mut self, reason: anyhow::Error) -> Result<BaseConfig> {
        warn!(error = %reason, "trying cached last-good snapshot");
        if let Some(snapshot) = self.state.load_snapshot()? {
            self.apply_snapshot(&snapshot)?;
            return Ok(snapshot.config.base_config.clone());
        }

        Err(reason).context("no cached v2board snapshot is available")
    }

    fn apply_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        let desired = desired_peers(snapshot)?;
        self.warn_if_ipv6_forwarding_disabled(&snapshot.config);
        self.flush_traffic_before_peer_changes()?;
        let interface_needs_base = self.wg.ensure_interface()?;
        let reconfigure_base = interface_needs_base
            || self.last_config_version != Some(snapshot.config.config_version);

        if reconfigure_base {
            self.wg.configure_base(&snapshot.config, desired.values())?;
        }
        self.wg.reconcile_peers(&desired)?;
        self.net.apply(&snapshot.config, desired.values())?;

        info!(
            config_version = snapshot.config.config_version,
            peers = desired.len(),
            "snapshot applied"
        );
        self.desired = desired;
        self.last_config_version = Some(snapshot.config.config_version);
        Ok(())
    }

    fn warn_if_ipv6_forwarding_disabled(&mut self, server: &ServerConfig) {
        if self.ipv6_forwarding_warning_emitted || server.ipv6_mode == "disabled" {
            return;
        }
        if server.address_pool_ipv6.is_none() && server.interface_ipv6.is_none() {
            return;
        }

        if matches!(ipv6_forwarding_enabled(), Some(false)) {
            warn!(
                "IPv6 forwarding is disabled; WireGuard IPv6 routed/NAT traffic will not forward until net.ipv6.conf.all.forwarding=1"
            );
            self.ipv6_forwarding_warning_emitted = true;
        }
    }

    fn report_runtime(
        &mut self,
        min_traffic: u64,
        online_handshake_window_secs: u64,
        include_status: bool,
    ) -> Result<()> {
        let host = self.wg.read()?;
        let now = epoch_secs();
        let mut traffic_peers = Vec::new();
        let mut status_peers = Vec::new();
        let mut online = 0usize;

        for (key, desired) in &self.desired {
            let Some(peer) = host.peers.get(key) else {
                continue;
            };

            let last_handshake_at = peer
                .last_handshake
                .and_then(system_time_to_epoch)
                .filter(|value| *value > 0);
            let last_endpoint = peer.endpoint.map(|endpoint| endpoint.to_string());
            if is_recent_handshake(last_handshake_at, now, online_handshake_window_secs) {
                online += 1;
            }

            let upload = peer.rx_bytes;
            let download = peer.tx_bytes;
            if upload.saturating_add(download) >= min_traffic {
                traffic_peers.push(TrafficPeerReport {
                    peer_id: desired.peer_id,
                    user_id: desired.user_id,
                    device_id: desired.device_id.clone(),
                    public_key: desired.public_key_string.clone(),
                    upload,
                    download,
                    last_handshake_at,
                    last_endpoint: last_endpoint.clone(),
                });
            }

            status_peers.push(StatusPeerReport {
                peer_id: desired.peer_id,
                user_id: desired.user_id,
                device_id: desired.device_id.clone(),
                public_key: desired.public_key_string.clone(),
                last_handshake_at,
                last_endpoint,
            });
        }

        if !traffic_peers.is_empty() {
            let report = TrafficReport {
                report_id: self.next_report_id(),
                reported_at: now,
                peers: traffic_peers,
            };
            self.panel.traffic_cumulative(&report)?;
        }

        if include_status {
            let status = StatusReport {
                reported_at: now,
                online,
                peers: status_peers,
            };
            self.panel.status(&status)?;
        }
        Ok(())
    }

    fn flush_traffic_before_peer_changes(&mut self) -> Result<()> {
        if self.desired.is_empty() {
            return Ok(());
        }

        match self.report_runtime(0, 30, false) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.wg.read().is_err() {
                    warn!(
                        %error,
                        "skipping final traffic flush because the WireGuard interface is not readable"
                    );
                    return Ok(());
                }

                Err(error).context("failed to flush final traffic counters before peer changes")
            }
        }
    }

    fn next_report_id(&mut self) -> String {
        self.report_sequence = self.report_sequence.wrapping_add(1);
        format!(
            "{}-{}-{}",
            self.config.panel.node_id,
            epoch_millis(),
            self.report_sequence
        )
    }

    fn online_handshake_window_secs(&self, base: &BaseConfig) -> u64 {
        self.config
            .wireguard
            .online_handshake_window_secs
            .unwrap_or_else(|| base.push_interval.saturating_mul(3).max(180))
            .max(30)
    }
}

struct PanelClient {
    config: PanelConfig,
    client: Client,
}

impl PanelClient {
    fn new(config: PanelConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs.max(1)))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { config, client })
    }

    fn config(&self) -> Result<ServerConfig> {
        self.get("config")
    }

    fn users(&self) -> Result<UsersResponse> {
        self.get("user")
    }

    fn traffic_cumulative(&self, report: &TrafficReport) -> Result<()> {
        self.post("traffic-cumulative", report)
    }

    fn status(&self, report: &StatusReport) -> Result<()> {
        self.post("status", report)
    }

    fn get<T>(&self, action: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self
            .client
            .get(self.url(action))
            .query(&self.query())
            .send()
            .map_err(|error| panel_request_error(action, error))?;
        let response = panel_response(action, response)?;
        response
            .json::<T>()
            .map_err(|_| anyhow!("failed to decode v2board action {action}"))
    }

    fn post<T>(&self, action: &str, payload: &T) -> Result<()>
    where
        T: Serialize,
    {
        self.client
            .post(self.url(action))
            .query(&self.query())
            .json(payload)
            .send()
            .map_err(|error| panel_request_error(action, error))
            .and_then(|response| panel_response(action, response).map(|_| ()))?;
        Ok(())
    }

    fn url(&self, action: &str) -> String {
        format!(
            "{}/api/v1/server/UniProxy/{}",
            self.config.base_url.trim_end_matches('/'),
            action
        )
    }

    fn query(&self) -> Vec<(&str, String)> {
        vec![
            ("token", self.config.token.clone()),
            ("node_type", self.config.node_type.clone()),
            ("node_id", self.config.node_id.to_string()),
        ]
    }
}

fn panel_request_error(action: &str, error: reqwest::Error) -> anyhow::Error {
    let reason = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() {
        "request body failed"
    } else {
        "request failed"
    };

    anyhow!("failed to call v2board action {action}: {reason}")
}

fn panel_response(
    action: &str,
    response: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().unwrap_or_default();
    let body = redact_sensitive(body.trim());
    let body = truncate_for_log(&body, 2048);
    if body.is_empty() {
        bail!("v2board action {action} returned HTTP {}", status.as_u16());
    }

    bail!(
        "v2board action {action} returned HTTP {}: {}",
        status.as_u16(),
        body
    )
}

fn redact_sensitive(input: &str) -> String {
    let query_token = regex::Regex::new(r#"(?i)(\b(?:token|server_token)=)[^&\s"'<>]+"#)
        .expect("valid token redaction regex");
    let json_token =
        regex::Regex::new(r#"(?i)(["'](?:token|server_token)["']\s*:\s*["'])[^"']*(["'])"#)
            .expect("valid JSON token redaction regex");

    let redacted = query_token.replace_all(input, "${1}[REDACTED]");
    json_token
        .replace_all(&redacted, "${1}[REDACTED]${2}")
        .into_owned()
}

struct StateStore {
    conn: Connection,
}

impl StateStore {
    fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create state dir {}", parent.display()))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(|| {
                format!(
                    "failed to restrict state dir permissions {}",
                    parent.display()
                )
            })?;
        }
        if !path.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("failed to create state database {}", path.display()))?;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict state database {}", path.display()))?;
        let conn = Connection::open(&path)
            .with_context(|| format!("failed to open state database {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .context("failed to initialize state database")?;
        Ok(Self { conn })
    }

    fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let value = serde_json::to_string(snapshot).context("failed to encode snapshot")?;
        self.conn
            .execute(
                "INSERT INTO kv (key, value, updated_at) VALUES ('snapshot', ?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![value, epoch_secs() as i64],
            )
            .context("failed to save snapshot")?;
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Option<Snapshot>> {
        let result =
            self.conn
                .query_row("SELECT value FROM kv WHERE key = 'snapshot'", [], |row| {
                    row.get::<_, String>(0)
                });

        match result {
            Ok(value) => serde_json::from_str(&value)
                .map(Some)
                .context("failed to decode cached snapshot"),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("failed to load cached snapshot"),
        }
    }
}

struct WireguardManager {
    config: LocalWireguardConfig,
    api: WGApi<Kernel>,
}

impl WireguardManager {
    fn new(config: LocalWireguardConfig) -> Result<Self> {
        let api = WGApi::<Kernel>::new(config.interface.clone())
            .context("failed to create WireGuard kernel API")?;
        Ok(Self { config, api })
    }

    fn ensure_interface(&mut self) -> Result<bool> {
        let needs_base_config = match self.api.read_interface_data() {
            Ok(host) => host.private_key.is_none() || host.listen_port == 0,
            Err(error) => {
                debug!(%error, "WireGuard interface is missing or unreadable before ensure");
                true
            }
        };

        self.api
            .create_interface()
            .with_context(|| format!("failed to create {}", self.config.interface))?;

        Ok(needs_base_config)
    }

    fn configure_base<'a>(
        &self,
        server: &ServerConfig,
        desired: impl Iterator<Item = &'a DesiredPeer>,
    ) -> Result<()> {
        let addresses = interface_addresses(server)?;
        let peers = desired
            .map(peer_from_desired)
            .collect::<Result<Vec<_>>>()
            .context("failed to build peer snapshot")?;
        let config = InterfaceConfiguration {
            name: self.config.interface.clone(),
            prvkey: server.private_key.clone(),
            addresses,
            port: server.server_port,
            peers,
            mtu: server.mtu,
            fwmark: self.config.fwmark,
        };

        self.api
            .configure_interface(&config)
            .with_context(|| format!("failed to configure {}", self.config.interface))
    }

    fn reconcile_peers(&self, desired: &HashMap<Key, DesiredPeer>) -> Result<()> {
        let host = self.read()?;
        let current: HashSet<Key> = host.peers.keys().cloned().collect();

        let desired_keys: HashSet<Key> = desired.keys().cloned().collect();
        for stale in current.difference(&desired_keys) {
            warn!(public_key = %stale, "removing stale WireGuard peer");
            self.api
                .remove_peer(stale)
                .with_context(|| format!("failed to remove peer {stale}"))?;
        }

        for peer in desired.values() {
            let wg_peer = peer_from_desired(peer)?;
            self.api
                .configure_peer(&wg_peer)
                .with_context(|| format!("failed to configure peer {}", peer.public_key_string))?;
        }

        Ok(())
    }

    fn read(&self) -> Result<defguard_wireguard_rs::host::Host> {
        self.api
            .read_interface_data()
            .with_context(|| format!("failed to read {}", self.config.interface))
    }
}

struct NetManager {
    ifname: String,
    firewall: FirewallConfig,
    rate_limit: RateLimitConfig,
}

impl NetManager {
    fn new(ifname: String, firewall: FirewallConfig, rate_limit: RateLimitConfig) -> Self {
        Self {
            ifname,
            firewall,
            rate_limit,
        }
    }

    fn apply<'a>(
        &self,
        server: &ServerConfig,
        desired: impl Iterator<Item = &'a DesiredPeer>,
    ) -> Result<()> {
        if self.firewall.enabled {
            self.apply_nft(server)?;
        }
        if self.rate_limit.enabled {
            self.apply_tc(desired)?;
        }
        Ok(())
    }

    fn apply_nft(&self, server: &ServerConfig) -> Result<()> {
        if self.firewall.backend != "nftables" {
            bail!("unsupported firewall backend {}", self.firewall.backend);
        }

        let script = self.nft_script(server)?;
        let check_table = format!("{}_check", nft_table_name(&self.ifname));
        let check_script = self.nft_script_with_table(server, &check_table)?;
        self.run_with_stdin(
            "nft",
            &["-c", "-f", "-"],
            &check_script,
            self.firewall.dry_run,
        )?;

        let table = nft_table_name(&self.ifname);
        self.run_ignore_error(
            "nft",
            &["delete", "table", "inet", table.as_str()],
            self.firewall.dry_run,
        );

        self.run_with_stdin("nft", &["-f", "-"], &script, self.firewall.dry_run)
    }

    fn nft_script(&self, server: &ServerConfig) -> Result<String> {
        let table = nft_table_name(&self.ifname);
        self.nft_script_with_table(server, &table)
    }

    fn nft_script_with_table(&self, server: &ServerConfig, table: &str) -> Result<String> {
        let mut script = String::new();
        script.push_str(&format!("table inet {} {{\n", table));
        script.push_str("  chain forward {\n");
        script.push_str("    type filter hook forward priority 0; policy accept;\n");
        script.push_str(&format!(
            "    iifname \"{}\" accept\n    oifname \"{}\" accept\n",
            shell_escape(&self.ifname),
            shell_escape(&self.ifname)
        ));
        script.push_str("  }\n");
        script.push_str("  chain postrouting {\n");
        script.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        if let Some(outbound) = &self.firewall.outbound_interface {
            script.push_str(&format!(
                "    ip saddr {} oifname \"{}\" masquerade\n",
                server.address_pool_ipv4()?,
                shell_escape(outbound)
            ));
            if server.ipv6_mode == "nat" {
                if let Some(pool) = &server.address_pool_ipv6 {
                    script.push_str(&format!(
                        "    ip6 saddr {} oifname \"{}\" masquerade\n",
                        pool,
                        shell_escape(outbound)
                    ));
                }
            }
        } else {
            script.push_str(&format!(
                "    ip saddr {} oifname != \"{}\" masquerade\n",
                server.address_pool_ipv4()?,
                shell_escape(&self.ifname)
            ));
            if server.ipv6_mode == "nat" {
                if let Some(pool) = &server.address_pool_ipv6 {
                    script.push_str(&format!(
                        "    ip6 saddr {} oifname != \"{}\" masquerade\n",
                        pool,
                        shell_escape(&self.ifname)
                    ));
                }
            }
        }
        script.push_str("  }\n");
        script.push_str("}\n");

        Ok(script)
    }

    fn apply_tc<'a>(&self, desired: impl Iterator<Item = &'a DesiredPeer>) -> Result<()> {
        let ifname = self.ifname.clone();
        self.run_ignore_error(
            "tc",
            &["qdisc", "del", "dev", ifname.as_str(), "clsact"],
            self.rate_limit.dry_run,
        );
        self.run(
            "tc",
            &["qdisc", "replace", "dev", ifname.as_str(), "clsact"],
            self.rate_limit.dry_run,
        )?;

        let mut pref = 10u32;
        for peer in desired {
            let Some(limit) = peer.speed_limit_mbps.filter(|limit| *limit > 0) else {
                continue;
            };
            for allowed_ip in &peer.allowed_ips {
                let ip = allowed_ip.address.to_string();
                let protocol = if allowed_ip.address.is_ipv4() {
                    "ip"
                } else {
                    "ipv6"
                };
                let rate = format!("{limit}mbit");
                let pref_string = pref.to_string();
                self.run(
                    "tc",
                    &[
                        "filter",
                        "replace",
                        "dev",
                        ifname.as_str(),
                        "egress",
                        "protocol",
                        protocol,
                        "pref",
                        pref_string.as_str(),
                        "flower",
                        "dst_ip",
                        ip.as_str(),
                        "action",
                        "police",
                        "rate",
                        rate.as_str(),
                        "burst",
                        "256k",
                        "conform-exceed",
                        "drop",
                    ],
                    self.rate_limit.dry_run,
                )?;
                pref += 1;
                let pref_string = pref.to_string();
                self.run(
                    "tc",
                    &[
                        "filter",
                        "replace",
                        "dev",
                        ifname.as_str(),
                        "ingress",
                        "protocol",
                        protocol,
                        "pref",
                        pref_string.as_str(),
                        "flower",
                        "src_ip",
                        ip.as_str(),
                        "action",
                        "police",
                        "rate",
                        rate.as_str(),
                        "burst",
                        "256k",
                        "conform-exceed",
                        "drop",
                    ],
                    self.rate_limit.dry_run,
                )?;
                pref += 1;
            }
        }

        Ok(())
    }

    fn run(&self, program: &str, args: &[&str], dry_run: bool) -> Result<()> {
        if dry_run {
            debug!(program, ?args, "dry-run command");
            return Ok(());
        }

        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {program}"))?;
        if !output.status.success() {
            bail!(
                "{} {:?} failed: {}",
                program,
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn run_ignore_error(&self, program: &str, args: &[&str], dry_run: bool) {
        if dry_run {
            debug!(program, ?args, "dry-run command");
            return;
        }

        match Command::new(program).args(args).output() {
            Ok(output) if !output.status.success() => debug!(
                program,
                ?args,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "ignored command failure"
            ),
            Err(error) => debug!(program, ?args, %error, "ignored command execution failure"),
            _ => {}
        }
    }

    fn run_with_stdin(
        &self,
        program: &str,
        args: &[&str],
        stdin: &str,
        dry_run: bool,
    ) -> Result<()> {
        if dry_run {
            debug!(program, ?args, stdin, "dry-run command with stdin");
            return Ok(());
        }

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to execute {program}"))?;
        child
            .stdin
            .as_mut()
            .context("failed to open command stdin")?
            .write_all(stdin.as_bytes())
            .context("failed to write command stdin")?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {program}"))?;
        if !output.status.success() {
            bail!(
                "{} {:?} failed: {}",
                program,
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

fn desired_peers(snapshot: &Snapshot) -> Result<HashMap<Key, DesiredPeer>> {
    let mut peers: HashMap<Key, DesiredPeer> = HashMap::new();
    for user in &snapshot.users {
        for peer in user.peers() {
            if peer.enabled == Some(0) || peer.revoked_at.is_some() {
                continue;
            }

            let public_key: Key = peer
                .public_key
                .as_str()
                .try_into()
                .with_context(|| format!("invalid peer public key for user {}", user.id))?;
            let allowed_ips = peer_allowed_ips(&peer)?;
            if allowed_ips.is_empty() {
                warn!(
                    user_id = user.id,
                    public_key = peer.public_key,
                    "skipping peer without allowed IPs"
                );
                continue;
            }

            let speed_limit_mbps = peer.speed_limit.or(user.speed_limit);
            if let Some(existing) = peers.get(&public_key) {
                bail!(
                    "duplicate WireGuard public key {} for user {} conflicts with user {}",
                    peer.public_key,
                    user.id,
                    existing.user_id
                );
            }
            peers.insert(
                public_key.clone(),
                DesiredPeer {
                    peer_id: peer.peer_id,
                    user_id: peer.user_id.unwrap_or(user.id),
                    device_id: peer.device_id.unwrap_or_else(|| "default".to_string()),
                    public_key,
                    public_key_string: peer.public_key,
                    allowed_ips,
                    speed_limit_mbps,
                },
            );
        }
    }

    Ok(peers)
}

fn peer_allowed_ips(peer: &PeerPayload) -> Result<Vec<IpAddrMask>> {
    let mut values = peer.allowed_ips.clone();
    if values.is_empty() {
        if let Some(ipv4) = peer.ipv4.as_ref().or(peer.ip.as_ref()) {
            values.push(ipv4.clone());
        }
        if let Some(ipv6) = &peer.ipv6 {
            values.push(ipv6.clone());
        }
    }

    values
        .into_iter()
        .map(|value| {
            value
                .parse::<IpAddrMask>()
                .with_context(|| format!("invalid peer allowed IP {value}"))
        })
        .collect()
}

fn peer_from_desired(peer: &DesiredPeer) -> Result<Peer> {
    let mut wg_peer = Peer::new(peer.public_key.clone());
    wg_peer.set_allowed_ips(peer.allowed_ips.clone());
    Ok(wg_peer)
}

fn interface_addresses(server: &ServerConfig) -> Result<Vec<IpAddrMask>> {
    let interface_ipv4 = server.interface_ipv4()?;
    let mut addresses = vec![
        interface_ipv4
            .parse::<IpAddrMask>()
            .with_context(|| format!("invalid interface address {interface_ipv4}"))?,
    ];
    if server.ipv6_mode != "disabled" {
        if let Some(ipv6) = &server.interface_ipv6 {
            addresses.push(
                ipv6.parse::<IpAddrMask>()
                    .with_context(|| format!("invalid interface IPv6 address {ipv6}"))?,
            );
        }
    }
    Ok(addresses)
}

fn system_time_to_epoch(value: SystemTime) -> Option<u64> {
    value.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn is_recent_handshake(last_handshake_at: Option<u64>, now: u64, window_secs: u64) -> bool {
    last_handshake_at
        .map(|handshake_at| {
            handshake_at <= now.saturating_add(60)
                && now.saturating_sub(handshake_at) <= window_secs
        })
        .unwrap_or(false)
}

fn ipv6_forwarding_enabled() -> Option<bool> {
    fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .ok()
        .map(|value| value.trim() == "1")
}

fn truncate_for_log(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }

    let mut end = max_len;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn shell_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}

fn nft_table_name(ifname: &str) -> String {
    let sanitized: String = ifname
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('_');
    let sanitized = if sanitized.is_empty() {
        "if"
    } else {
        sanitized
    };
    let sanitized: String = sanitized.chars().take(32).collect();

    let mut hasher = DefaultHasher::new();
    ifname.hash(&mut hasher);
    let hash = format!("{:016x}", hasher.finish());
    let hash = &hash[..8];

    format!("v2board_wg_{sanitized}_{hash}")
}

fn default_node_type() -> String {
    "wireguard".to_string()
}

fn default_firewall_backend() -> String {
    "nftables".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_interval() -> u64 {
    60
}

fn default_config_version() -> u64 {
    1
}

fn default_ipv6_mode() -> String {
    "routed".to_string()
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_http_errors_do_not_leak_token() {
        use std::io::Read;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 18\r\n\r\npanel unavailable\n",
                )
                .unwrap();
        });

        let client = PanelClient::new(PanelConfig {
            base_url: format!("http://{address}"),
            token: "super-secret-token".to_string(),
            node_id: 42,
            node_type: "wireguard".to_string(),
            timeout_secs: 5,
        })
        .unwrap();

        let error = client.config().unwrap_err().to_string();
        handle.join().unwrap();

        assert!(error.contains("v2board action config returned HTTP 500"));
        assert!(error.contains("panel unavailable"));
        assert!(!error.contains("super-secret-token"));
        assert!(!error.contains("token="));
    }

    #[test]
    fn panel_error_body_redacts_reflected_tokens() {
        let redacted = redact_sensitive(
            r#"GET /api/v1/server/UniProxy/config?token=secret-token&node_id=1 {"server_token":"another-secret"}"#,
        );

        assert!(redacted.contains("token=[REDACTED]"));
        assert!(redacted.contains(r#""server_token":"[REDACTED]""#));
        assert!(!redacted.contains("secret-token"));
        assert!(!redacted.contains("another-secret"));
    }

    #[test]
    fn state_store_restricts_file_permissions() {
        let dir = std::env::temp_dir().join(format!("v2board-wg-state-{}", epoch_millis()));
        let path = dir.join("state.sqlite3");

        let _store = StateStore::open(path.clone()).unwrap();

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn users_response_requires_top_level_users_field() {
        let error = serde_json::from_str::<UsersResponse>("{}").unwrap_err();
        assert!(error.to_string().contains("missing field `users`"));

        let response = serde_json::from_str::<UsersResponse>(r#"{"users":[]}"#).unwrap();
        assert!(response.users.is_empty());
    }

    #[test]
    fn online_handshake_requires_recent_handshake() {
        assert!(is_recent_handshake(Some(1_000), 1_100, 180));
        assert!(!is_recent_handshake(Some(1_000), 1_300, 180));
        assert!(!is_recent_handshake(None, 1_100, 180));
        assert!(!is_recent_handshake(Some(1_300), 1_100, 180));
    }

    #[test]
    fn nft_table_name_is_namespaced_by_interface() {
        assert!(nft_table_name("wg0").starts_with("v2board_wg_wg0_"));
        assert!(nft_table_name("***").starts_with("v2board_wg_if_"));
        assert_ne!(nft_table_name("wg-prod.1"), nft_table_name("wg_prod_1"));
    }

    #[test]
    fn nft_script_excludes_wireguard_egress_and_does_not_nat_routed_ipv6() {
        let manager = NetManager::new(
            "wg0".to_string(),
            FirewallConfig::default(),
            RateLimitConfig::default(),
        );
        let script = manager.nft_script(&test_server_config()).unwrap();

        assert!(script.contains("table inet v2board_wg_wg0_"));
        assert!(script.contains("ip saddr 10.10.0.0/24 oifname != \"wg0\" masquerade"));
        assert!(!script.contains("ip6 saddr fd10:10::/64"));
    }

    #[test]
    fn nft_script_masquerades_ipv6_only_in_nat_mode() {
        let manager = NetManager::new(
            "wg0".to_string(),
            FirewallConfig::default(),
            RateLimitConfig::default(),
        );
        let mut server = test_server_config();
        server.ipv6_mode = "nat".to_string();

        let script = manager.nft_script(&server).unwrap();

        assert!(script.contains("ip6 saddr fd10:10::/64 oifname != \"wg0\" masquerade"));
    }

    #[test]
    fn desired_peers_reject_duplicate_public_keys() {
        let duplicate_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        let snapshot = Snapshot {
            config: test_server_config(),
            users: vec![
                UserPayload {
                    id: 1,
                    speed_limit: None,
                    device_limit: None,
                    wireguard: Some(PeerPayload {
                        peer_id: Some(1),
                        user_id: Some(1),
                        device_id: Some("default".to_string()),
                        public_key: duplicate_key.clone(),
                        ip: Some("10.10.0.2/32".to_string()),
                        ipv4: None,
                        ipv6: None,
                        allowed_ips: vec![],
                        speed_limit: None,
                        device_limit: None,
                        enabled: Some(1),
                        revoked_at: None,
                    }),
                    wireguard_peers: vec![],
                },
                UserPayload {
                    id: 2,
                    speed_limit: None,
                    device_limit: None,
                    wireguard: Some(PeerPayload {
                        peer_id: Some(2),
                        user_id: Some(2),
                        device_id: Some("default".to_string()),
                        public_key: duplicate_key,
                        ip: Some("10.10.0.3/32".to_string()),
                        ipv4: None,
                        ipv6: None,
                        allowed_ips: vec![],
                        speed_limit: None,
                        device_limit: None,
                        enabled: Some(1),
                        revoked_at: None,
                    }),
                    wireguard_peers: vec![],
                },
            ],
        };

        let error = desired_peers(&snapshot).unwrap_err().to_string();
        assert!(error.contains("duplicate WireGuard public key"));
    }

    fn test_server_config() -> ServerConfig {
        ServerConfig {
            config_version: 1,
            server_port: 51820,
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            public_key: String::new(),
            interface_ip: Some("10.10.0.1/24".to_string()),
            interface_ipv4: None,
            address_pool: Some("10.10.0.0/24".to_string()),
            address_pool_ipv4: None,
            interface_ipv6: Some("fd10:10::1/64".to_string()),
            address_pool_ipv6: Some("fd10:10::/64".to_string()),
            ipv6_mode: "routed".to_string(),
            mtu: None,
            persistent_keepalive: None,
            base_config: BaseConfig::default(),
        }
    }
}
