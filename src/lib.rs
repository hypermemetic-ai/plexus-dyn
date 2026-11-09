//! # plexus-dyn — a service grows peers at runtime
//!
//! `dyn` is an activation a Plexus service registers to connect to other
//! services **at runtime** and to grow TypeScript **dendrites**, each served
//! as a peer in one untyped slot:
//!
//! ```text
//! dyn.connect   { name, url, replace? }      a service on a WebSocket, as a peer        (admin)
//! dyn.grow      { name, source, targets }    a dendrite: index.ts, served on stdio      (admin)
//! dyn.disconnect { name }                                                                (admin)
//! dyn.peers                                  each peer: kind, up, interface, counters    (viewer)
//! dyn.names                                  each peer's name: the slot's list            (viewer)
//! dyn.peer.<name>.<path>.<method>            a call into a peer, gated by `dyn.{peer}`
//! ```
//!
//! Every peer is a plexus-core [`RemoteChild`]: a WebSocket peer dialed with
//! [`ChildSpec::Ws`], a dendrite spawned as `plexus-dendrite serve DIR
//! --via-host …` on stdio. A dendrite's targets are other peers: its client is
//! grown from the host's view of `dyn.peer.<target>` (asked over the pipe),
//! and its calls go back **through the host** — the service's own routing and
//! gate — as the caller of the call the dendrite is serving (NEST-11).
//!
//! **Transport** (DYNAUTH-8, TM-3): a WebSocket peer beyond loopback is
//! reached by `wss://` only, its certificate validated (the webpki roots,
//! plus [`ChildOptions::tls_roots`]); `ws://` is for `127.0.0.0/8`, `::1`
//! and `localhost`, unless [`DynOptions::insecure_ws`] (a test network's),
//! which `dyn.peers` says on each such peer. A peer's identity — its
//! `_info` backend, and on `wss://` its certificate's key — is pinned when
//! it is connected; a redial or remount that proves another is refused
//! (`identity_changed`) until it is connected again with `replace`.
//!
//! The slot is untyped: a call is admitted on the slot grant `dyn.{peer}` (or
//! a literal path a role lists, `dyn.peer.digest.rainy`), held by `admin`
//! unless a role lists it, and the peer decides again inside it.
//!
//! **Liveness.** Every `liveness` (5 s) a task looks at each peer: one down is
//! brought up (redialed, restarted) within its backoff; a WebSocket peer is
//! pinged at that period and marked down when silent for two. **Remount.** A
//! peer whose restart published another schema is refused by its mount for
//! good (plexus-core: "schema changed; restart the service"); `dyn` connects
//! a fresh one and swaps it in — at the next look, or at once on a call.
//!
//! **`--peers FILE`** ([`DynOptions::peers_file`]): a TOML of peers connected
//! at [`DynActivation::start`]; one that fails is listed down, never dropped,
//! and tried again at every look.
//!
//! ```toml
//! weather = "ws://127.0.0.1:4801"
//!
//! [digest]
//! dendrite = "dendrites/digest"
//! via = ["weather.weather"]
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::Stream;
use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{ChildOptions, ChildSpec, DynamicHub, RemoteChild, WeakService};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How `dyn` runs.
#[derive(Debug, Clone)]
pub struct DynOptions {
    /// Where grown dendrites' sources are written (`<dir>/<name>/index.ts`).
    pub data_dir: PathBuf,
    /// The `plexus-dendrite` executable a dendrite is served by.
    pub dendrite: PathBuf,
    /// The mounts' options (timeouts, backoff, the hop's principal).
    pub child: ChildOptions,
    /// How long a dendrite may take to start (it grows its clients first).
    pub dendrite_timeout: Duration,
    /// How often each peer is looked at (and a WebSocket peer pinged).
    pub liveness: Duration,
    /// Peers connected at [`DynActivation::start`].
    pub peers_file: Option<PathBuf>,
    /// DYNAUTH-8: allow plain `ws://` to a host beyond loopback — a test
    /// network's, never a real one's: the hop (who calls, under what
    /// ceiling) crosses it in clear. Each such peer says `insecure` in
    /// `dyn.peers`.
    pub insecure_ws: bool,
}

impl Default for DynOptions {
    fn default() -> Self {
        Self {
            data_dir: std::env::temp_dir().join("plexus-dyn"),
            dendrite: PathBuf::from("plexus-dendrite"),
            child: ChildOptions::for_service("dyn"),
            dendrite_timeout: Duration::from_secs(60),
            liveness: Duration::from_secs(5),
            peers_file: None,
            insecure_ws: false,
        }
    }
}

/// What a peer is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerKind {
    /// A service on a WebSocket.
    Ws { url: String },
    /// A dendrite: `index.ts` in `dir`, its clients grown toward `via`.
    Dendrite { dir: String, via: Vec<String> },
}

/// One peer, as `dyn.peers` lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    pub name: String,
    #[serde(flatten)]
    pub peer: PeerKind,
    /// A live connection is up now.
    pub up: bool,
    /// Why it is down, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// Its interface's hash (its whole schema tree's shape), once mounted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Restarts (redials) of the current mount.
    pub restarts: u64,
    /// Calls open into it now.
    pub open: usize,
    /// Calls forwarded to it, in all (the current mount).
    pub calls: u64,
    /// Calls it made back through the service (a dendrite).
    pub calls_back: u64,
    /// Times a fresh mount replaced one whose schema changed.
    pub remounts: u64,
    /// DYNAUTH-8: who it proved it was when it was connected, pinned: a
    /// redial or remount that proves another is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PeerIdentity>,
    /// DYNAUTH-8: reached by plain `ws://` beyond loopback, as
    /// [`DynOptions::insecure_ws`] allows.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure: bool,
}

/// DYNAUTH-8: who a peer proved it was — its `_info` backend and, on
/// `wss://`, the sha256 of its certificate's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerIdentity {
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
}

impl From<&plexus_core::plexus::PeerIdentity> for PeerIdentity {
    fn from(p: &plexus_core::plexus::PeerIdentity) -> Self {
        Self { backend: p.backend.clone(), tls_key: p.tls_key.clone() }
    }
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend `{}`", self.backend)?;
        match &self.tls_key {
            Some(k) => write!(f, ", TLS key {}", &k[..k.len().min(16)]),
            None => write!(f, ", no TLS key"),
        }
    }
}

/// Why `dyn` refused a peer (DYNAUTH-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Plain `ws://` to a host beyond loopback.
    InsecureTransport,
    /// It proved another identity than the one pinned when it was connected.
    IdentityChanged,
}

/// What `connect`, `grow` and `disconnect` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DynEvent {
    /// A peer is mounted under `name`: `dyn.peer.<name>.…`.
    Connected { name: String, interface: String, methods: Vec<String>, replaced: bool },
    /// A peer let go.
    Disconnected { name: String },
    /// Refused, and why in a word (DYNAUTH-8).
    Refused { reason: Refusal, message: String },
    /// Why not.
    Error { message: String },
}

impl plexus_client::FromClientError for DynEvent {
    fn from_client_error(e: plexus_client::ClientError) -> Self {
        DynEvent::Error { message: e.to_string() }
    }
}

struct Entry {
    kind: PeerKind,
    child: Option<RemoteChild>,
    why: Option<String>,
    remounts: u64,
    /// DYNAUTH-8: who it proved it was at its first mount.
    pin: Option<PeerIdentity>,
}

struct Inner {
    opts: DynOptions,
    peers: Mutex<BTreeMap<String, Entry>>,
    /// Serializes connects and remounts (a dendrite's start is slow).
    dialing: tokio::sync::Mutex<()>,
    host: Mutex<Option<WeakService>>,
    started: std::sync::atomic::AtomicBool,
}

/// The `dyn` activation. Cheap to clone.
#[derive(Clone)]
pub struct DynActivation {
    inner: Arc<Inner>,
}

impl Default for DynActivation {
    fn default() -> Self {
        Self::new(DynOptions::default())
    }
}

/// A peer's name: one segment of `[A-Za-z0-9_-]`.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(format!("`{name}` is not a peer name: one segment of letters, digits, `_` and `-`"));
    }
    Ok(())
}

impl DynActivation {
    /// `dyn` with `opts`.
    pub fn new(opts: DynOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                opts,
                peers: Mutex::default(),
                dialing: tokio::sync::Mutex::new(()),
                host: Mutex::default(),
                started: Default::default(),
            }),
        }
    }

    /// The options it runs with.
    pub fn options(&self) -> &DynOptions {
        &self.inner.opts
    }

    /// Start it in `service` (the service it is registered in): the service
    /// a dendrite calls back through, the peers of [`DynOptions::peers_file`]
    /// connected (one that fails listed down), and the liveness task. Call
    /// once the service is built; safe to call again (it does nothing).
    pub async fn start(&self, service: &DynamicHub) -> Result<(), String> {
        *self.inner.host.lock().unwrap() = Some(service.downgrade());
        if self.inner.started.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(file) = &self.inner.opts.peers_file {
            for (name, kind) in read_peers_file(file)? {
                self.inner.peers.lock().unwrap().insert(name, Entry { kind, child: None, why: Some("not connected yet".into()), remounts: 0, pin: None });
            }
            let names: Vec<String> = self.inner.peers.lock().unwrap().keys().cloned().collect();
            for name in names {
                if let Err(why) = self.mount(&name, false).await {
                    tracing::warn!(target: "plexus::dyn", peer = %name, "{why}");
                }
            }
        }
        let weak = Arc::downgrade(&self.inner);
        let every = self.inner.opts.liveness;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                DynActivation { inner }.look().await;
            }
        });
        Ok(())
    }

    /// One look at every peer, each in its own time: a down one brought up
    /// (or remounted).
    pub async fn look(&self) {
        let names: Vec<String> = self.inner.peers.lock().unwrap().keys().cloned().collect();
        let looks = names.into_iter().map(|name| {
            let this = self.clone();
            async move { this.look_at(name).await }
        });
        futures::future::join_all(looks).await;
    }

    async fn look_at(&self, name: String) {
        {
            let child = self.inner.peers.lock().unwrap().get(&name).map(|e| e.child.clone());
            match child {
                Some(Some(c)) if c.is_up() => {}
                Some(Some(c)) => {
                    let up = c.up().await;
                    if c.dead().is_some() {
                        if let Err(why) = self.mount(&name, true).await {
                            tracing::warn!(target: "plexus::dyn", peer = %name, "remount: {why}");
                        }
                    } else if let Err(why) = up {
                        self.set_why(&name, &c, Some(why));
                    } else {
                        self.set_why(&name, &c, None);
                    }
                }
                Some(None) => {
                    if let Err(why) = self.mount(&name, false).await {
                        tracing::debug!(target: "plexus::dyn", peer = %name, "still down: {why}");
                    }
                }
                None => {}
            }
        }
    }

    fn set_why(&self, name: &str, child: &RemoteChild, why: Option<String>) {
        if let Some(e) = self.inner.peers.lock().unwrap().get_mut(name) {
            if e.child.as_ref().is_some_and(|c| std::ptr::eq(c.spec(), child.spec())) {
                e.why = why;
            }
        }
    }

    /// The options a mount of `kind` takes.
    fn child_options(&self, kind: &PeerKind) -> ChildOptions {
        let mut o = self.inner.opts.child.clone();
        if o.host.is_none() {
            o.host = self.inner.host.lock().unwrap().clone();
        }
        match kind {
            PeerKind::Ws { .. } => o.ping = o.ping.or(Some(self.inner.opts.liveness)),
            PeerKind::Dendrite { .. } => o.timeout = o.timeout.max(self.inner.opts.dendrite_timeout),
        }
        o
    }

    /// The spec a peer of `kind` is mounted from.
    fn spec(&self, name: &str, kind: &PeerKind) -> Result<ChildSpec, String> {
        match kind {
            PeerKind::Ws { url } => {
                check_url(url, self.inner.opts.insecure_ws).map_err(|(_, why)| why)?;
                Ok(ChildSpec::Ws { name: name.into(), url: url.clone() })
            }
            PeerKind::Dendrite { dir, via } => {
                let mut argv = vec![self.inner.opts.dendrite.display().to_string(), "serve".into(), dir.clone(), "--name".into(), name.into()];
                if !via.is_empty() {
                    let paths: Vec<String> = via.iter().map(|t| format!("{}=dyn.peer.{t}", t.rsplit('.').next().unwrap_or(t))).collect();
                    argv.extend(["--via-host".into(), paths.join(",")]);
                }
                Ok(ChildSpec::Stdio { name: name.into(), argv })
            }
        }
    }

    /// Mount the peer listed under `name` (again: `remount`), keeping it
    /// listed whatever happens.
    async fn mount(&self, name: &str, remount: bool) -> Result<RemoteChild, String> {
        let _g = self.inner.dialing.lock().await;
        let kind = match self.inner.peers.lock().unwrap().get(name) {
            Some(e) => {
                // Mounted (or remounted) meanwhile by another look or call.
                if let Some(c) = e.child.as_ref().filter(|c| c.dead().is_none()) {
                    return Ok(c.clone());
                }
                e.kind.clone()
            }
            None => return Err(format!("no peer `{name}`")),
        };
        let spec = match self.spec(name, &kind) {
            Ok(s) => s,
            Err(why) => {
                if let Some(e) = self.inner.peers.lock().unwrap().get_mut(name) {
                    e.why = Some(why.clone());
                }
                return Err(why);
            }
        };
        let mounted = RemoteChild::connect(spec, self.child_options(&kind)).await.map_err(|e| e.to_string());
        let mut peers = self.inner.peers.lock().unwrap();
        let Some(e) = peers.get_mut(name) else { return Err(format!("`{name}` was disconnected while it was mounted")) };
        match mounted {
            Ok(child) => {
                let proved = child.identity().map(PeerIdentity::from);
                match (&e.pin, &proved) {
                    (Some(pinned), Some(p)) if pinned != p => {
                        let why = identity_changed(name, pinned, p);
                        tracing::error!(target: "plexus::dyn", peer = %name, %pinned, proved = %p, "refused: another identity");
                        e.why = Some(why.clone());
                        return Err(why);
                    }
                    (None, _) => e.pin = proved,
                    _ => {}
                }
                if remount {
                    e.remounts += 1;
                    tracing::info!(target: "plexus::dyn", peer = %name, hash = %child.mounted_hash(), "remounted: its schema changed");
                }
                e.child = Some(child.clone());
                e.why = None;
                Ok(child)
            }
            Err(why) => {
                if !remount {
                    e.child = None;
                }
                e.why = Some(why.clone());
                Err(why)
            }
        }
    }

    /// Add (or replace) a peer and mount it; on failure nothing is kept.
    async fn add(&self, name: String, kind: PeerKind, replace: bool) -> DynEvent {
        if let Err(message) = check_name(&name) {
            return DynEvent::Error { message };
        }
        let replaced = self.inner.peers.lock().unwrap().contains_key(&name);
        if replaced && !replace {
            return DynEvent::Error { message: format!("a peer is connected as `{name}`: disconnect it, or connect with `replace`") };
        }
        // Mounted beside the old one, swapped in only once it is up.
        let spec = match self.spec(&name, &kind) {
            Ok(s) => s,
            Err(message) => return DynEvent::Error { message },
        };
        // Not under `dialing`: a dendrite asks, at its start, for the
        // schemas of the peers it targets — which may need mounting.
        match RemoteChild::connect(spec, self.child_options(&kind)).await {
            Ok(child) => {
                let schema = plexus_core::plexus::Activation::plugin_schema(&child);
                let interface = interface_of(&child);
                let methods = schema.methods.iter().map(|m| m.name.clone()).collect();
                let pin = child.identity().map(PeerIdentity::from);
                self.inner.peers.lock().unwrap().insert(name.clone(), Entry { kind, child: Some(child), why: None, remounts: 0, pin });
                DynEvent::Connected { name, interface, methods, replaced }
            }
            Err(e) => DynEvent::Error { message: e.to_string() },
        }
    }

    /// The peers, listed.
    pub fn list(&self) -> Vec<PeerInfo> {
        self.inner
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(name, e)| {
                let st = e.child.as_ref().map(RemoteChild::stats).unwrap_or_default();
                let up = e.child.as_ref().is_some_and(RemoteChild::is_up);
                let why = match (&e.child, up) {
                    (_, true) => None,
                    // A dead mount's last word is dyn's remount (refused, or failing).
                    (Some(c), false) if c.dead().is_some() => e.why.clone().or_else(|| c.why_down()),
                    (Some(c), false) => c.why_down().or_else(|| e.why.clone()),
                    (None, false) => e.why.clone(),
                };
                PeerInfo {
                    name: name.clone(),
                    peer: e.kind.clone(),
                    up,
                    why,
                    interface: e.child.as_ref().map(interface_of),
                    restarts: st.restarts,
                    open: st.open,
                    calls: st.calls,
                    calls_back: st.calls_back,
                    remounts: e.remounts,
                    identity: e.pin.clone(),
                    insecure: matches!(&e.kind, PeerKind::Ws { url } if check_url(url, false).is_err()),
                }
            })
            .collect()
    }

    /// The peer `name`, mounted: a fresh mount when its schema changed, a
    /// first one when it never came up.
    pub async fn get(&self, name: &str) -> Result<RemoteChild, PeerError> {
        let child = match self.inner.peers.lock().unwrap().get(name) {
            None => return Err(PeerError::NotFound { name: name.into() }),
            Some(e) => e.child.clone(),
        };
        match child {
            Some(c) if c.dead().is_none() => Ok(c),
            Some(_) => self.mount(name, true).await.map_err(|reason| PeerError::Unavailable { reason }),
            None => self.mount(name, false).await.map_err(|reason| PeerError::Unavailable { reason }),
        }
    }

    fn data_dir_for(&self, name: &str) -> PathBuf {
        self.inner.opts.data_dir.join(name)
    }
}

/// DYNAUTH-8 (TM-3): whether `url` may be dialed — `wss://` anywhere,
/// `ws://` only to loopback (`127.0.0.0/8`, `::1`, `localhost`) unless
/// `insecure` allows it. `Err`: the refusal, said.
pub fn check_url(url: &str, insecure: bool) -> Result<(), (Refusal, String)> {
    let rest = if let Some(r) = url.strip_prefix("wss://") {
        return match host_of(r) {
            Some(_) => Ok(()),
            None => Err((Refusal::InsecureTransport, format!("`{url}` names no host"))),
        };
    } else if let Some(r) = url.strip_prefix("ws://") {
        r
    } else {
        return Err((Refusal::InsecureTransport, format!("`{url}`: a peer is reached by ws:// or wss://")));
    };
    let Some(host) = host_of(rest) else { return Err((Refusal::InsecureTransport, format!("`{url}` names no host"))) };
    if is_loopback(&host) || insecure {
        return Ok(());
    }
    Err((
        Refusal::InsecureTransport,
        format!("`{url}`: plain ws:// only to loopback (127.0.0.0/8, ::1, localhost); a peer beyond it is reached by wss://, its hop (who calls, under what ceiling) never in clear"),
    ))
}

/// The host of `authority[/path]`: no user info, no port, an IPv6
/// literal without its brackets, lower case.
fn host_of(rest: &str) -> Option<String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once(']')?.0
    } else {
        authority.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host == "localhost" {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_loopback(),
        Ok(std::net::IpAddr::V6(a)) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => false,
    }
}

fn identity_changed(name: &str, pinned: &PeerIdentity, proved: &PeerIdentity) -> String {
    format!("`{name}` proved another identity ({proved}) than the one pinned when it was connected ({pinned}): connect it again with `replace` to trust it")
}

/// A mounted peer's interface hash: its whole tree's (the schema hash its
/// mount compares across restarts, NEST-4), as 16 hex digits.
fn interface_of(child: &RemoteChild) -> String {
    plexus_core::plexus::content_hash::hash16(child.mounted_hash().as_bytes())
}

/// `--peers FILE`: `name = "ws://…"`, or `[name] dendrite = "DIR", via = […]`
/// (a relative `DIR` is the file's own directory's).
pub fn read_peers_file(file: &Path) -> Result<Vec<(String, PeerKind)>, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("--peers {}: {e}", file.display()))?;
    let table: toml::Table = text.parse().map_err(|e| format!("--peers {}: {e}", file.display()))?;
    let base = file.parent().unwrap_or(Path::new("."));
    let mut out = Vec::new();
    for (name, v) in table {
        check_name(&name).map_err(|e| format!("--peers {}: {e}", file.display()))?;
        let kind = match v {
            toml::Value::String(url) if url.starts_with("ws://") || url.starts_with("wss://") => PeerKind::Ws { url },
            toml::Value::Table(t) => {
                let dir = t.get("dendrite").and_then(toml::Value::as_str).ok_or_else(|| format!("--peers {}: `[{name}]` names no `dendrite = \"DIR\"`", file.display()))?;
                let dir = if Path::new(dir).is_absolute() { PathBuf::from(dir) } else { base.join(dir) };
                let via = t.get("via").and_then(toml::Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
                PeerKind::Dendrite { dir: dir.display().to_string(), via }
            }
            other => return Err(format!("--peers {}: `{name}` is {other}: a peer is `name = \"ws://…\"` or `[name] dendrite = \"DIR\"`", file.display())),
        };
        out.push((name, kind));
    }
    Ok(out)
}

/// Runtime peers: connect services, grow dendrites, call them as
/// `dyn.peer.<name>.<path>.<method>`.
#[plexus_macros::activation(roles(viewer = ["peers", "names"]))]
impl DynActivation {
    /// Connect the service at `url` (a WebSocket) as the peer `name`; a taken
    /// name is refused unless `replace`. `wss://` anywhere, `ws://` only to
    /// loopback (`refused`, `insecure_transport`); its identity is pinned.
    #[plexus_macros::method]
    pub async fn connect(&self, name: String, url: String, replace: Option<bool>) -> DynEvent {
        if let Err((reason, message)) = check_url(&url, self.inner.opts.insecure_ws) {
            return DynEvent::Refused { reason, message };
        }
        self.add(name, PeerKind::Ws { url }, replace.unwrap_or(false)).await
    }

    /// Grow a dendrite: `source` (its `index.ts`) served as the peer `name`,
    /// its clients grown toward `targets` (other peers, `weather` or
    /// `weather.forecasts`, each called back through this service).
    #[plexus_macros::method]
    pub async fn grow(&self, name: String, source: String, targets: Vec<String>, replace: Option<bool>) -> DynEvent {
        if let Err(message) = check_name(&name) {
            return DynEvent::Error { message };
        }
        if let Some(bad) = targets.iter().find(|t| t.is_empty() || !t.split('.').all(|s| check_name(s).is_ok())) {
            return DynEvent::Error { message: format!("target `{bad}` is not a peer's path (`weather`, `weather.forecasts`)") };
        }
        let dir = self.data_dir_for(&name);
        if let Err(e) = tokio::fs::create_dir_all(&dir).await {
            return DynEvent::Error { message: format!("{}: {e}", dir.display()) };
        }
        if let Err(e) = tokio::fs::write(dir.join("index.ts"), source).await {
            return DynEvent::Error { message: format!("{}: {e}", dir.display()) };
        }
        self.add(name, PeerKind::Dendrite { dir: dir.display().to_string(), via: targets }, replace.unwrap_or(false)).await
    }

    /// Let go of the peer `name` (a dendrite's process ends with its last call).
    #[plexus_macros::method]
    pub async fn disconnect(&self, name: String) -> DynEvent {
        match self.inner.peers.lock().unwrap().remove(&name) {
            Some(_) => DynEvent::Disconnected { name },
            None => DynEvent::Error { message: format!("no peer `{name}`") },
        }
    }

    /// Every peer: its kind, whether it is up, its interface's hash, its
    /// restarts, open calls and calls.
    #[plexus_macros::method]
    pub async fn peers(&self) -> impl Stream<Item = PeerInfo> + Send + 'static {
        futures::stream::iter(self.list())
    }

    /// Every peer's name (the slot's list: a slot lists names).
    #[plexus_macros::method]
    pub async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::iter(self.list().into_iter().map(|p| p.name))
    }

    /// A peer by name: `dyn.peer.<name>.<path>.<method>`.
    #[plexus_macros::peer(list = "names")]
    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.get(name).await.map(|c| Box::new(c) as Box<dyn Peer>)
    }
}
