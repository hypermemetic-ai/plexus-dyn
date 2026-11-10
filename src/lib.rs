//! # plexus-dyn — a service grows peers at runtime
//!
//! `dyn` is an activation a Plexus service registers to connect to other
//! services **at runtime** and to grow TypeScript **dendrites**, each served
//! as a peer in one untyped slot:
//!
//! ```text
//! dyn.connect   { name, url, replace?, expecting? }   a service on a WebSocket, as a peer (admin)
//! dyn.grow      { name, source, targets, expecting? } a dendrite: index.ts, on stdio      (admin)
//! dyn.disconnect { name }                                                                (admin)
//! dyn.peers                                  each peer: kind, up, interface, counters    (viewer)
//! dyn.names                                  each peer's name: the slot's list            (viewer)
//! dyn.consent   { peer, needs?, callers? }   what a peer may call up; who may call it    (admin)
//! dyn.consents                               each peer's key, declared needs, consent     (viewer)
//! dyn.pins                                   each peer's pin, and what it presented       (viewer)
//! dyn.repin     { name, fingerprint }        pin the presented identity, by its print     (admin)
//! dyn.peer.<name>.<path>.<method>            a call into a peer, gated by `dyn.{peer}`
//!                                            or a role its consent names
//! ```
//!
//! **Registration and consent** (DYNAUTH-5, [`consent`]): a peer's key
//! (proved at `_info`) and its declared `needs` are registered at connect
//! and grow, the key pinned. Its needs are a request: an admin answers with
//! `dyn.consent`, and a declared need not consented is refused upward. A
//! consent's `callers` are roles whose holders may call into the peer,
//! through [`DynActivation::consent_roles`] — the roles a service hands its
//! gate.
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
//! **Settings** (NEST-21, [`settings`]): `dyn` reads the service's
//! configuration (`plexus_core::plexus::config`) at every connect, mount
//! and spawn — `transport.insecure_ws`, `transport.tls_roots`, `child.*`,
//! `dyn.repin_on_valid_cert`, `dyn.containment.deny` / `require`,
//! `dyn.require_consent` — so a set through the `config` activation takes
//! effect at the next one. What [`DynOptions`] says is their flag layer.
//! **Re-pinning**: a peer refused for another identity keeps what it
//! presented (`dyn.pins`); `dyn.repin { name, fingerprint }` pins it only
//! when `fingerprint` is exactly that identity's, so nobody accepts blind.
//! With `dyn.repin_on_valid_cert` (off, NEST-18 D33) a certificate whose key
//! moved under a valid chain, the backend and the peer's own key the same,
//! is re-pinned by itself.
//!
//! **Containment** (DYNAUTH-9, TM-5): a dendrite is spawned through
//! `plexus-dyn-contain` ([`contain`]): a cleared environment (its own
//! `HOME` and `TMPDIR`), its own directory, and on Linux a Landlock ruleset
//! that denies it `dyn`'s data directory, every secret store of the user's
//! that is there ([`contain::SECRET_STORES`], [`contain::RUNTIME_SECRETS`]:
//! `~/.plexus`, `~/.ssh`, `~/.gnupg`, `~/.password-store`, hyperforge's,
//! gh's, menger's, cargo's credentials, docker's, kube's, the cloud CLIs',
//! `~/.netrc`, `~/.npmrc`, `~/.pypirc`, synapse's holder socket), the dial
//! key and [`Containment::deny`]. Where
//! Landlock is not there it runs with the cleared environment and a
//! warning, unless [`Containment::require`]. `dyn.grow` stays the admin's:
//! until microVMs a dendrite is host-equivalent trust.
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
//! **The top level** ([`DynOptions::top_level`], NEST-15): each peer is also
//! served at the service's own top level — `<name>.<path>.<method>`, as a
//! `--child` mount is (`svc w weather forecast`, not `svc dyn peer w weather
//! forecast`) — through plexus-core's service root, added and removed as the
//! peer is; `dyn.peer.<name>` keeps working beside it. A name the service
//! already serves at its top level is refused. At the top level a peer is
//! gated as a mounted child is: each method on its own grant
//! (`w.weather.forecast`), admin's unless a role lists it — not the slot's
//! `dyn.{peer}`.
//!
//! **Grafts** (NEST-16). Every connect, grow and remount is checked before
//! the peer is served: a peer whose schema declares `needs` (what it calls
//! of this service — a graft that knows its parent, or a dendrite calling
//! back through `--via-host`) is refused unless this service serves each, by
//! its shape hash, naming every one missing or changed. **`expecting`** is a
//! contract's stamp (the interface hash: `ForgeClient::stamp().hash`, or
//! `Interface::named(…).hash`): the peer — its root or one of its
//! activations — must serve exactly that interface, at connect and at every
//! remount; otherwise it is refused (a remount keeps the mount it had).
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

pub mod contain;
// DYNAUTH-5: a peer's registration and an admin's consent.
pub mod consent;
// NEST-21: dyn's settings, on the service's configuration.
pub mod settings;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::Stream;
use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::peer_token::{Jwks, PeerKey, TokenIssuer};
use plexus_core::plexus::config::{settings as core_settings, Config, Source};
use plexus_core::plexus::{ChildOptions, ChildSpec, DynamicHub, RemoteChild, ServiceRoot, WeakService};
use schemars::JsonSchema;

pub use consent::{Consent, ConsentInfo, ConsentRoles};
pub use contain::Containment;
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
    /// NEST-15: serve each peer at the service's top level too
    /// (`<name>.<path>.<method>`), beside `dyn.peer.<name>`. Off by default.
    pub top_level: bool,
    /// DYNAUTH-8: allow plain `ws://` to a host beyond loopback — a test
    /// network's, never a real one's: the hop (who calls, under what
    /// ceiling) crosses it in clear. Each such peer says `insecure` in
    /// `dyn.peers`.
    pub insecure_ws: bool,
    /// DYNAUTH-9: how a dendrite is contained.
    pub contain: Containment,
    /// DYNAUTH-5: a peer's declared needs are called back only once an
    /// admin consents (`dyn.consent`); on by default. Off: every declared
    /// need may be called, as NEST-16 has it.
    pub require_consent: bool,
    /// DYNAUTH-12: mint a peer token for every call forwarded to a peer that
    /// proved a key (and to a dendrite on its pipe); on by default.
    pub tokens: bool,
    /// DYNAUTH-12: the signing key's file (0600, made when missing); `None`:
    /// `<data_dir>/dyn.key`. Denied to every contained dendrite.
    pub key_file: Option<PathBuf>,
    /// DYNAUTH-7: where each mint and exchange is recorded, beside the
    /// `plexus::audit` tracing event (PRIVACY-1's sink, when there is one).
    pub audit: Option<Audit>,
    /// NEST-21: the configuration `dyn` reads its settings from
    /// (`transport.insecure_ws`, `transport.tls_roots`, `child.*`,
    /// `dyn.*`). `None`: the service's own ([`DynamicHub::config`]), taken
    /// at [`DynActivation::start`]. The fields above that a setting
    /// governs (`insecure_ws`, `require_consent`, `contain.require`,
    /// `child`'s timeout, max_calls, backoff, legacy_upcalls, tls_roots)
    /// are its flag layer: what the host was started with, which a runtime
    /// set goes over and a reset comes back to.
    pub config: Option<Config>,
}

/// DYNAUTH-7: an audit sink for [`DynOptions::audit`].
#[derive(Clone)]
pub struct Audit(pub Arc<dyn plexus_core::plexus::peer_token::TokenAudit>);

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Audit(..)")
    }
}

/// KEEL-19 (P5, KEEL-25): the user's own data directory —
/// `$XDG_DATA_HOME/plexus-dyn`, else `~/.local/share/plexus-dyn`; with
/// neither, `<tmp>/plexus-dyn-<uid>`. Made 0700; refused at start when it is
/// not the user's or is open to others (`DynActivation::start`).
fn default_data_dir() -> PathBuf {
    let from = |k: &str| std::env::var_os(k).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(x) = from("XDG_DATA_HOME") {
        return x.join("plexus-dyn");
    }
    if let Some(h) = from("HOME") {
        return h.join(".local/share/plexus-dyn");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[cfg(unix)]
    let me = format!("plexus-dyn-{}", unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let me = "plexus-dyn".to_string();
    std::env::temp_dir().join(me)
}

impl Default for DynOptions {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            dendrite: PathBuf::from("plexus-dendrite"),
            child: ChildOptions::for_service("dyn"),
            dendrite_timeout: Duration::from_secs(60),
            liveness: Duration::from_secs(5),
            peers_file: None,
            top_level: false,
            insecure_ws: false,
            contain: Containment::default(),
            require_consent: true,
            tokens: true,
            key_file: None,
            audit: None,
            config: None,
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
    /// DYNAUTH-7: revoked (`dyn.revoke`), and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
    /// NEST-21: the identity it presented and was refused for
    /// (`identity_changed`), kept for `dyn.repin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<PeerIdentity>,
}

/// NEST-21: one peer's pin, as `dyn.pins` lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PinInfo {
    pub name: String,
    /// The identity pinned (none until its first mount).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<PeerIdentity>,
    /// [`PeerIdentity::fingerprint`] of `pinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The identity it last presented and was refused for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<PeerIdentity>,
    /// [`PeerIdentity::fingerprint`] of `presented`: what `dyn.repin` takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_fingerprint: Option<String>,
}

/// DYNAUTH-8: who a peer proved it was — its `_info` backend and, on
/// `wss://`, the sha256 of its certificate's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerIdentity {
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// DYNAUTH-5: the Ed25519 key it proved at `_info` (`key:<hex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl PeerIdentity {
    /// NEST-21: the whole identity as one string to compare —
    /// `sha256:<hex>` over its backend, its certificate's key and its own
    /// key, each on a line (an absent one empty).
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let text = format!("{}\n{}\n{}", self.backend, self.tls_key.as_deref().unwrap_or(""), self.key.as_deref().unwrap_or(""));
        let d = sha2::Sha256::digest(text.as_bytes());
        format!("sha256:{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    /// NEST-21: the same peer under a renewed certificate: the same backend
    /// and own key, only the certificate's key moved.
    fn only_tls_moved(&self, other: &PeerIdentity) -> bool {
        self.backend == other.backend && self.key == other.key && self.tls_key.is_some() && other.tls_key.is_some() && self.tls_key != other.tls_key
    }
}

impl From<&plexus_core::plexus::PeerIdentity> for PeerIdentity {
    fn from(p: &plexus_core::plexus::PeerIdentity) -> Self {
        Self { backend: p.backend.clone(), tls_key: p.tls_key.clone(), key: p.key.clone() }
    }
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend `{}`", self.backend)?;
        match &self.tls_key {
            Some(k) => write!(f, ", TLS key {}", &k[..k.len().min(16)]),
            None => write!(f, ", no TLS key"),
        }?;
        match &self.key {
            Some(k) => write!(f, ", key {}", &k[..k.len().min(20)]),
            None => Ok(()),
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
    /// NEST-21: `dyn.repin`'s fingerprint is not the one the peer presented.
    FingerprintMismatch,
    /// NEST-21: `dyn.repin` on a peer that presented nothing refused.
    NotPresented,
}

/// KEEL-19: the peer other than `name` that holds `key` — mounted under it,
/// or pinned to it — if one does. One key is one mount: a token addressed to
/// a key, and an exchange's presenter found by its key, name one peer.
fn key_held_by(peers: &BTreeMap<String, Entry>, name: &str, key: Option<&str>) -> Option<String> {
    let key = key?;
    peers
        .iter()
        .find(|(n, e)| n.as_str() != name && (e.child.as_ref().and_then(|c| c.peer_key()) == Some(key) || e.pin.as_ref().and_then(|p| p.key.as_deref()) == Some(key)))
        .map(|(n, _)| n.clone())
}

/// KEEL-19: the refusal of a key another peer holds. Said as
/// `Refusal::IdentityChanged` (the identity it proved is another peer's),
/// its message starting `key_in_use:`, `old` the holder's pin.
fn key_in_use(name: &str, key: &str, other: &str) -> String {
    format!("key_in_use: `{name}` proved the key {key}, which `{other}` holds here: one key is one peer (disconnect `{other}` first)")
}

/// DYNAUTH-6: what `dyn.exchange` answers (RFC 8693 §2.2's response, as
/// a stream item).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExchangeEvent {
    /// The token for the audience.
    Exchanged {
        access_token: String,
        /// `urn:ietf:params:oauth:token-type:jwt`.
        issued_token_type: String,
        /// `N_A`: not a bearer token — bound to the audience's key.
        token_type: String,
        /// What it holds (never more than the subject token held).
        scope: Vec<String>,
        /// Seconds it lives.
        expires_in: u64,
    },
    /// Refused, and why (never the token).
    Error { message: String },
}

impl plexus_client::FromClientError for ExchangeEvent {
    fn from_client_error(e: plexus_client::ClientError) -> Self {
        ExchangeEvent::Error { message: e.to_string() }
    }
}

/// What `connect`, `grow` and `disconnect` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DynEvent {
    /// A peer is mounted under `name`: `dyn.peer.<name>.…`.
    Connected { name: String, interface: String, methods: Vec<String>, replaced: bool },
    /// A peer let go.
    Disconnected { name: String },
    /// Refused, and why in a word (DYNAUTH-8). NEST-21: for an identity,
    /// the one pinned (`old`) and the one presented.
    Refused {
        reason: Refusal,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<PeerIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presented: Option<PeerIdentity>,
    },
    /// NEST-21: `name` is pinned to what it presented (`dyn.repin`).
    Repinned { name: String, old: Option<PeerIdentity>, pinned: PeerIdentity, fingerprint: String, up: bool },
    /// DYNAUTH-5: what `peer` may now do: the needs it may call back up,
    /// and the roles that may call into it.
    Consented { peer: String, needs: Vec<String>, callers: Vec<String> },
    /// DYNAUTH-7: `peer` is revoked.
    Revoked { peer: String, why: String },
    /// DYNAUTH-7: the signing key rotated: `kid` signs from now, `previous`
    /// verifies for one more token lifetime.
    Rotated { kid: String, previous: String },
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
    /// NEST-16: the interface hash the peer must serve.
    expecting: Option<String>,
    /// DYNAUTH-8: who it proved it was at its first mount.
    pin: Option<PeerIdentity>,
    /// NEST-21: the identity a remount presented and was refused for.
    presented: Option<PeerIdentity>,
}

struct Inner {
    opts: DynOptions,
    peers: Mutex<BTreeMap<String, Entry>>,
    /// Serializes connects and remounts (a dendrite's start is slow).
    dialing: tokio::sync::Mutex<()>,
    host: Mutex<Option<WeakService>>,
    started: std::sync::atomic::AtomicBool,
    /// NEST-15: the names this `dyn` serves at the service's top level.
    top: Mutex<std::collections::BTreeSet<String>>,
    /// DYNAUTH-5: consent (and DYNAUTH-7's revocations), kept in
    /// `<data_dir>/consent.json`.
    store: Mutex<consent::Store>,
    /// DYNAUTH-12: the peer-token issuer (its key in `key_file`).
    issuer: Arc<TokenIssuer>,
    /// DYNAUTH-6: the exchange proofs seen, each once.
    proofs: plexus_core::plexus::peer_token::ProofCache,
    /// KEEL-19: the key `dyn` dials its peers with when `opts.child.key`
    /// names none — `<data_dir>/dial.key` (0600, made when missing), its
    /// own, not the token-signing key: a peer trusts it as the service
    /// acting for others, and rotating either changes only its own role.
    /// `None` when it could not be read or made: then no keyed peer mounts.
    dial_key: Option<PathBuf>,
    /// KEEL-19 (P5): why the data directory is refused, if it is.
    refused: Option<String>,
    /// NEST-21: where the settings are read: `DynOptions::config`, or the
    /// service's once started.
    config: Mutex<Config>,
}

impl consent::ConsentSource for Inner {
    fn consented_grants(&self, role: &str) -> Vec<String> {
        let store = self.store.lock().unwrap();
        let peers = self.peers.lock().unwrap();
        let top = self.top.lock().unwrap();
        let mut out = Vec::new();
        for (name, c) in &store.consents {
            if store.revoked.contains_key(name) || !c.callers.iter().any(|r| r == role) {
                continue;
            }
            let Some(child) = peers.get(name).and_then(|e| e.child.as_ref()) else { continue };
            // KEEL-19: a consent given for another key is another client's.
            if c.key.as_deref() != child.peer_key() {
                continue;
            }
            for m in consent::method_paths(child) {
                out.push(format!("dyn.peer.{name}.{m}"));
                if top.contains(name) {
                    out.push(format!("{name}.{m}"));
                }
            }
        }
        out
    }
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
        let config = opts.config.clone().unwrap_or_default();
        // KEEL-19 (P5, KEEL-25): the data directory is the user's own and
        // closed to others, or nothing is read from or kept in it — and
        // `start` refuses, naming it.
        let refused = plexus_core::plexus::peer_token::ensure_private_dir(&opts.data_dir).err().map(|why| format!("the data directory: {why}"));
        // KEEL-31: the backstop that does not depend on the macro, at the one
        // constructor — a build whose whole-service methods lost their mark
        // reads no key or consent, connects and grows nothing, and `start`
        // refuses, whether or not it is ever called.
        let refused = refused.or_else(|| {
            let schema = <Self as plexus_core::plexus::Activation>::slot_schema()?;
            plexus_core::plexus::require_everywhere(&schema, EVERYWHERE).err()
        });
        if let Some(why) = &refused {
            tracing::error!(target: "plexus::dyn", "{why}; no key or consent is read, no peer is connected or grown, and `start` refuses");
        }
        let signing = match &refused {
            None => Self::signing_key(&opts),
            Some(_) => PeerKey::generate(),
        };
        let mut issuer = TokenIssuer::new(signing);
        if let Some(Audit(sink)) = &opts.audit {
            issuer = issuer.with_audit(Arc::clone(sink));
        }
        let issuer = Arc::new(issuer);
        let dial_key = if refused.is_none() { Self::dial_key(&opts) } else { None };
        let load = refused.is_none();
        let this = Self {
            inner: Arc::new(Inner {
                opts,
                peers: Mutex::default(),
                dialing: tokio::sync::Mutex::new(()),
                host: Mutex::default(),
                started: Default::default(),
                top: Mutex::default(),
                store: Mutex::new(consent::Store::default()),
                issuer,
                proofs: Default::default(),
                dial_key,
                refused,
                config: Mutex::new(config.clone()),
            }),
        };
        let this = if load { this.loaded() } else { this };
        this.adopted(config)
    }

    /// NEST-21: the configuration read now.
    pub fn config(&self) -> Config {
        self.inner.config.lock().unwrap().clone()
    }

    /// NEST-21: read the settings from `config`: dyn's declared there, what
    /// the options say above the defaults put in as its flag layer, and the
    /// mounted peers held again when `dyn.require_consent` moves.
    fn adopted(self, config: Config) -> Self {
        *self.inner.config.lock().unwrap() = config.clone();
        settings::declare(&config);
        let o = &self.inner.opts;
        if o.insecure_ws {
            config.seed(&core_settings::TRANSPORT_INSECURE_WS, Source::Flag, Some(true));
        }
        if !o.require_consent {
            config.seed(&settings::DYN_REQUIRE_CONSENT, Source::Flag, Some(false));
        }
        if o.contain.require {
            config.seed(&settings::DYN_CONTAINMENT_REQUIRE, Source::Flag, Some(true));
        }
        o.child.seed(&config);
        let weak = Arc::downgrade(&self.inner);
        config.on_change(&settings::DYN_REQUIRE_CONSENT, move |_| {
            if let Some(inner) = weak.upgrade() {
                let this = DynActivation { inner };
                let mounted: Vec<(String, RemoteChild)> = this.inner.peers.lock().unwrap().iter().filter_map(|(n, e)| e.child.clone().map(|c| (n.clone(), c))).collect();
                for (name, child) in mounted {
                    this.hold(&name, &child);
                }
            }
        });
        self
    }

    /// NEST-21: `transport.insecure_ws`, now.
    fn insecure_ws(&self) -> bool {
        self.config().get(&core_settings::TRANSPORT_INSECURE_WS)
    }

    /// DYNAUTH-12: the signing key, from its file (made there when
    /// missing). A file that cannot be read or made: an in-memory key, said
    /// loudly (tokens still verify against `dyn.jwks`, until a restart).
    fn key_path(opts: &DynOptions) -> PathBuf {
        opts.key_file.clone().unwrap_or_else(|| opts.data_dir.join("dyn.key"))
    }

    /// KEEL-19: the dial key's file — `opts.child.key` when it names one,
    /// else `<data_dir>/dial.key`, made (0600) when missing.
    fn dial_key(opts: &DynOptions) -> Option<PathBuf> {
        if let Some(k) = &opts.child.key {
            return Some(k.clone());
        }
        let path = opts.data_dir.join("dial.key");
        match PeerKey::load_or_create(&path) {
            Ok(_) => Some(path),
            Err(why) => {
                tracing::error!(target: "plexus::dyn", "the dial key: {why}; dialing with none, so no keyed peer is mounted");
                None
            }
        }
    }

    /// KEEL-19: the principal `dyn`'s dial proves to its peers (`key:<hex>`),
    /// what a keyed peer trusts to act for others; `None` without a dial key.
    pub fn dial_principal(&self) -> Option<String> {
        self.inner.dial_key.as_deref().and_then(|p| plexus_core::plexus::remote_child::key_principal(p).ok())
    }

    fn signing_key(opts: &DynOptions) -> PeerKey {
        let path = Self::key_path(opts);
        PeerKey::load_or_create(&path).unwrap_or_else(|why| {
            tracing::error!(target: "plexus::dyn", "the signing key: {why}; signing with a key kept in memory only");
            PeerKey::generate()
        })
    }

    /// DYNAUTH-12: the keys a peer verifies this `dyn`'s tokens with.
    pub fn jwk_set(&self) -> Jwks {
        self.inner.issuer.jwks()
    }

    /// DYNAUTH-12: the issuer (the signing key's id, its rotation, DYNAUTH-7).
    pub fn issuer(&self) -> &Arc<TokenIssuer> {
        &self.inner.issuer
    }

    /// DYNAUTH-7: revoke `peer` — no call is forwarded to it (no token is
    /// minted for it), every call it is making back ends, its consent is
    /// dropped and it stays listed as revoked until an admin connects or
    /// grows it again with `replace`. A token already in its hand lives out
    /// its `exp` (≤ 60 s) at a peer that verifies without asking.
    pub fn revoke_peer(&self, peer: &str, why: &str) -> Result<(), String> {
        let child = match self.inner.peers.lock().unwrap().get(peer) {
            None => return Err(format!("no peer `{peer}`")),
            Some(e) => e.child.clone(),
        };
        {
            let mut store = self.inner.store.lock().unwrap();
            store.revoked.insert(peer.to_string(), why.to_string());
            store.consents.remove(peer);
        }
        self.save_store()?;
        if let Some(c) = &child {
            c.set_consent(Some(Vec::new()));
            c.revoke(why);
        }
        self.moved();
        tracing::warn!(target: "plexus::audit", peer = %peer, %why, "dyn revoke");
        Ok(())
    }

    /// DYNAUTH-7: sign with a new key from now; the old one stays in
    /// `dyn.jwks` for one token lifetime and the skew. The key file is
    /// replaced. Answers the new key's id and the old one's.
    pub fn rotate_signing_key(&self) -> Result<(String, String), String> {
        if let Some(why) = &self.inner.refused {
            return Err(why.clone());
        }
        let old = self.inner.issuer.kid();
        let new = PeerKey::generate();
        new.save(&Self::key_path(&self.inner.opts))?;
        let kid = self.inner.issuer.rotate(new);
        tracing::warn!(target: "plexus::audit", %kid, previous = %old, "dyn signing key rotated");
        Ok((kid, old))
    }

    /// DYNAUTH-6: [`DynActivation::exchange`]'s work.
    ///
    /// KEEL-19: decided where a call back is decided. The presenter — the
    /// subject token's audience, proven by its proof — must be a peer
    /// mounted here, not revoked, holding a consented need that covers the
    /// audience and the method asked (`dyn.peer.<audience>.<m>` for the
    /// audience's `<backend>.<m>`, or `<audience>.<m>` when it is served at
    /// the top level), held by the subject token: `RemoteChild::may_exchange`,
    /// which asks the one function the presenter's calls back are asked by.
    /// The token is bound to the presenter's key, so the audience takes it
    /// only with the presenter's proof; a subject token is exchanged once
    /// per audience and method. A refusal says its reason in brackets
    /// (`[not_consented]`) and is audited.
    pub fn exchange_for(&self, subject: &str, proof: &str, audience: &str, scope: Option<&[String]>, method: &str) -> Result<(String, plexus_core::plexus::peer_token::PeerClaims), String> {
        use plexus_core::plexus::peer_token::{narrow, ExchangeRefusal as R, Onward, PeerClaims, TokenError};
        let reason = std::cell::Cell::new(None::<R>);
        let decide = |presented: &PeerClaims| -> Result<Onward, (R, String)> {
            let refuse = |r: R, why: String| {
                reason.set(Some(r));
                (r, why)
            };
            let (target, presenter) = {
                let peers = self.inner.peers.lock().unwrap();
                let target = peers.get(audience).and_then(|e| e.child.clone());
                let presenter = peers.iter().find_map(|(n, e)| e.child.clone().filter(|c| c.peer_key() == Some(presented.aud.as_str())).map(|c| (n.clone(), c)));
                (target, presenter)
            };
            let Some((target, key)) = target.and_then(|c| c.peer_key().map(str::to_string).map(|k| (c, k))) else {
                return Err(refuse(R::Audience, format!("no connected peer `{audience}` that proved a key: a token is only exchanged for one")));
            };
            let Some((name, presenter)) = presenter else {
                return Err(refuse(R::Presenter, "the token's holder is not a peer mounted in this service: only a mounted peer's token is exchanged".into()));
            };
            {
                let store = self.inner.store.lock().unwrap();
                for (who, n) in [("the presenter", name.as_str()), ("the audience", audience)] {
                    if let Some(why) = store.revoked.get(n) {
                        return Err(refuse(R::Revoked, format!("{who} `{n}` is revoked ({why})")));
                    }
                }
            }
            let backend = target.identity().map(|i| i.backend.clone()).unwrap_or_else(|| audience.to_string());
            let Some(m) = method.strip_prefix(&format!("{backend}.")).filter(|m| !m.is_empty()) else {
                return Err(refuse(R::NotConsented, format!("`{method}` is not a method of `{audience}`, whose methods are `{backend}.…`: an exchange names the method it is for")));
            };
            let mut needs = vec![format!("dyn.peer.{audience}.{m}")];
            if self.inner.top.lock().unwrap().contains(audience) {
                needs.push(format!("{audience}.{m}"));
            }
            let mut why = String::new();
            for need in &needs {
                match presenter.may_exchange(need, method, presented) {
                    Ok(held) => {
                        let scope = match scope {
                            Some(asked) => narrow(Some(asked), &held),
                            None => held,
                        };
                        if scope.is_empty() {
                            return Err(refuse(R::NotConsented, format!("the scope asked is not within what `{name}` may reach of `{audience}`")));
                        }
                        return Ok(Onward { name: audience.to_string(), peer_key: Some(key), scope });
                    }
                    Err(w) => why = w,
                }
            }
            let r = if presenter.revoked().is_some() { R::Revoked } else { R::NotConsented };
            Err(refuse(r, format!("`{name}` may not reach `{}`: {why}", needs[0])))
        };
        let call = uuid::Uuid::new_v4().to_string();
        self.inner.issuer.exchange_decided(subject, Some(proof), audience, &call, method, &self.inner.proofs, decide).map_err(|e| {
            let r = reason.get().unwrap_or(match &e {
                TokenError::Proof(_) => R::Proof,
                TokenError::Refused(_) => R::Again,
                _ => R::Subject,
            });
            format!("the exchange is refused [{r}]: {e}")
        })
    }

    /// DYNAUTH-5: the consent kept in the data directory, read at start.
    fn loaded(self) -> Self {
        match consent::Store::load(&self.store_path()) {
            Ok(s) => *self.inner.store.lock().unwrap() = s,
            Err(why) => tracing::error!(target: "plexus::dyn", "consent not read, none kept: {why}"),
        }
        self
    }

    fn store_path(&self) -> PathBuf {
        self.inner.opts.data_dir.join("consent.json")
    }

    fn save_store(&self) -> Result<(), String> {
        if let Some(why) = &self.inner.refused {
            return Err(why.clone());
        }
        let s = self.inner.store.lock().unwrap().clone();
        s.save(&self.store_path())
    }

    /// DYNAUTH-5: the service's `roles`, plus the grants consent gives
    /// (`dyn.consent … callers`): hand the result to the gate in their
    /// place.
    pub fn consent_roles(&self, roles: Arc<dyn plexus_auth_core::grants::Roles>) -> Arc<dyn plexus_auth_core::grants::Roles> {
        let weak = Arc::downgrade(&self.inner);
        Arc::new(ConsentRoles { base: roles, source: weak })
    }

    /// DYNAUTH-5: a peer's declared needs, by method.
    fn declared(child: &RemoteChild) -> Option<Vec<String>> {
        child.needs().map(|n| n.iter().map(|n| n.method.clone()).collect())
    }

    /// DYNAUTH-5: hold `child`'s calls back to what is consented for
    /// `name` (everything declared when consent is not required).
    fn hold(&self, name: &str, child: &RemoteChild) {
        if !self.config().get(&settings::DYN_REQUIRE_CONSENT) {
            child.set_consent(None);
            return;
        }
        let declared = Self::declared(child);
        let store = self.inner.store.lock().unwrap();
        // KEEL-19: a consent given for another key is another client's.
        let given = store.consents.get(name).filter(|c| c.key.as_deref() == child.peer_key());
        child.set_consent(Some(consent::consented(given, declared.as_deref())));
    }

    /// DYNAUTH-5: a new registration of `name` under `key` — the consent
    /// kept for another key is dropped (another client).
    fn register(&self, name: &str, key: Option<&str>) {
        let dropped = {
            let mut store = self.inner.store.lock().unwrap();
            match store.consents.get(name) {
                Some(c) if c.key.as_deref() != key => store.consents.remove(name).is_some(),
                _ => false,
            }
        };
        if dropped {
            tracing::warn!(target: "plexus::dyn", peer = %name, "registered under another key: its consent is dropped");
            if let Err(why) = self.save_store() {
                tracing::error!(target: "plexus::dyn", "{why}");
            }
            self.moved();
        }
    }

    /// The gate's grants generation moves (consent changed what a role holds).
    fn moved(&self) {
        let service = self.inner.host.lock().unwrap().as_ref().and_then(WeakService::upgrade);
        if let Some(gate) = service.as_ref().and_then(|s| s.gate()) {
            gate.moved(plexus_auth_core::grants::GrantsMove::RoleEdit);
        }
    }

    /// DYNAUTH-5: what is registered and consented, per peer.
    pub fn consent_list(&self) -> Vec<ConsentInfo> {
        let store = self.inner.store.lock().unwrap().clone();
        let peers = self.inner.peers.lock().unwrap();
        let mut names: std::collections::BTreeSet<String> = peers.keys().cloned().collect();
        names.extend(store.consents.keys().cloned());
        names
            .into_iter()
            .map(|name| {
                let child = peers.get(&name).and_then(|e| e.child.as_ref());
                let declared = child.and_then(Self::declared);
                let c = store.consents.get(&name).cloned().unwrap_or_default();
                let held: Vec<String> = c.needs.iter().map(|n| consent::split_need(n).0.to_string()).collect();
                let pending = declared.iter().flatten().filter(|d| !held.contains(d)).cloned().collect();
                ConsentInfo {
                    key: child.and_then(|c| c.peer_key().map(str::to_string)).or(c.key.clone()),
                    declared,
                    needs: c.needs,
                    pending,
                    callers: c.callers,
                    revoked: store.revoked.get(&name).cloned(),
                    peer: name,
                }
            })
            .collect()
    }

    /// DYNAUTH-5: set what `peer` may do (replacing what it could).
    pub fn set_consent(&self, peer: &str, needs: Vec<String>, callers: Vec<String>) -> Result<Consent, String> {
        let child = self.inner.peers.lock().unwrap().get(peer).map(|e| e.child.clone());
        let child = match child {
            None => return Err(format!("no peer `{peer}`: connect or grow it first, so its needs are known")),
            Some(None) => return Err(format!("`{peer}` is not mounted now: its needs are not known")),
            Some(Some(c)) => c,
        };
        let c = Consent { needs, callers, key: child.peer_key().map(str::to_string) };
        consent::check(peer, &c, Self::declared(&child).as_deref())?;
        self.inner.store.lock().unwrap().consents.insert(peer.to_string(), c.clone());
        self.save_store()?;
        self.hold(peer, &child);
        self.moved();
        tracing::info!(target: "plexus::audit", peer = %peer, needs = ?c.needs, callers = ?c.callers, "dyn consent");
        Ok(c)
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
        if let Some(why) = &self.inner.refused {
            return Err(why.clone());
        }
        // KEEL-31: the backstop, again on the instance's own schema (`new`
        // checked the one the build declares).
        plexus_core::plexus::require_everywhere(&plexus_core::plexus::Activation::plugin_schema(self), EVERYWHERE)?;
        *self.inner.host.lock().unwrap() = Some(service.downgrade());
        if self.inner.started.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        // NEST-21: no configuration given: the service's.
        if self.inner.opts.config.is_none() && !self.config().same(&service.config()) {
            let _ = self.clone().adopted(service.config());
        }
        // NEST-15: peers connected before the service was known.
        let mounted: Vec<(String, RemoteChild)> = self.inner.peers.lock().unwrap().iter().filter_map(|(n, e)| e.child.clone().map(|c| (n.clone(), c))).collect();
        for (name, child) in mounted {
            if let Err(why) = self.surface(&name, &child) {
                tracing::warn!(target: "plexus::dyn", peer = %name, "{why}");
            }
        }
        if let Some(file) = &self.inner.opts.peers_file {
            for (name, kind) in read_peers_file(file)? {
                self.inner.peers.lock().unwrap().insert(name, Entry { kind, child: None, why: Some("not connected yet".into()), remounts: 0, expecting: None, pin: None, presented: None });
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

    /// NEST-15: the service's root, while the service lives.
    fn root(&self) -> Option<ServiceRoot> {
        self.inner.host.lock().unwrap().as_ref().and_then(WeakService::upgrade).map(|s| s.root())
    }

    /// NEST-15: whether `name` may go on the service's top level — free, or
    /// this `dyn`'s already.
    fn top_free(&self, name: &str) -> Result<(), String> {
        if !self.inner.opts.top_level || self.inner.top.lock().unwrap().contains(name) {
            return Ok(());
        }
        match self.root() {
            Some(root) if root.contains(name) => Err(format!("the service serves `{name}` at its top level already")),
            _ => Ok(()),
        }
    }

    /// NEST-15: with [`DynOptions::top_level`], serve `child` as `name` at
    /// the service's top level (replacing this `dyn`'s earlier mount of it).
    fn surface(&self, name: &str, child: &RemoteChild) -> Result<(), String> {
        if !self.inner.opts.top_level {
            return Ok(());
        }
        let Some(root) = self.root() else { return Ok(()) };
        self.top_free(name)?;
        root.replace(child.clone()).map_err(|e| e.to_string())?;
        self.inner.top.lock().unwrap().insert(name.to_string());
        Ok(())
    }

    /// NEST-15: `name` off the service's top level, if this `dyn` put it there.
    fn unsurface(&self, name: &str) {
        if self.inner.top.lock().unwrap().remove(name) {
            if let Some(root) = self.root() {
                root.remove(name);
            }
        }
    }

    /// The options a mount of `kind` takes.
    fn child_options(&self, kind: &PeerKind) -> ChildOptions {
        // NEST-21: the child.* and transport.tls_roots settings, read at each mount.
        let mut o = self.inner.opts.child.clone().configured(&self.config());
        // KEEL-19: dial with a key by default, so a keyed peer's proof is
        // made for a principal its transport proved.
        if o.key.is_none() {
            o.key = self.inner.dial_key.clone();
        }
        if self.inner.opts.tokens {
            o.tokens = Some(Arc::clone(&self.inner.issuer));
        }
        if o.host.is_none() {
            o.host = self.inner.host.lock().unwrap().clone();
        }
        // KEEL-32 (R3-1): dyn keeps a consent — nothing declared counts until
        // `hold` applies it, from the handshake on.
        o.consent_required = true;
        match kind {
            PeerKind::Ws { .. } => o.ping = o.ping.or(Some(self.inner.opts.liveness)),
            PeerKind::Dendrite { via, .. } => {
                o.timeout = o.timeout.max(self.inner.opts.dendrite_timeout);
                // KEEL-32: the schemas it grows its clients from at its start
                // (`--via-host`), before its needs are known — and no other.
                o.schemas = via.iter().map(|t| format!("dyn.peer.{t}")).collect();
            }
        }
        o
    }

    /// The spec a peer of `kind` is mounted from.
    fn spec(&self, name: &str, kind: &PeerKind) -> Result<ChildSpec, String> {
        match kind {
            PeerKind::Ws { url } => {
                check_url(url, self.insecure_ws()).map_err(|(_, why)| why)?;
                Ok(ChildSpec::Ws { name: name.into(), url: url.clone() })
            }
            PeerKind::Dendrite { dir, via } => {
                let mut argv = vec![self.inner.opts.dendrite.display().to_string(), "serve".into(), dir.clone(), "--name".into(), name.into()];
                if !via.is_empty() {
                    let paths: Vec<String> = via.iter().map(|t| format!("{}=dyn.peer.{t}", t.rsplit('.').next().unwrap_or(t))).collect();
                    argv.extend(["--via-host".into(), paths.join(",")]);
                }
                let argv = self.containment().wrap(Path::new(dir), &self.denied(), argv)?;
                Ok(ChildSpec::Stdio { name: name.into(), argv })
            }
        }
    }

    /// Mount the peer listed under `name` (again: `remount`), keeping it
    /// listed whatever happens.
    async fn mount(&self, name: &str, remount: bool) -> Result<RemoteChild, String> {
        let _g = self.inner.dialing.lock().await;
        let (kind, expecting) = match self.inner.peers.lock().unwrap().get(name) {
            Some(e) => {
                // Mounted (or remounted) meanwhile by another look or call.
                if let Some(c) = e.child.as_ref().filter(|c| c.dead().is_none()) {
                    return Ok(c.clone());
                }
                (e.kind.clone(), e.expecting.clone())
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
        // NEST-16: the remount is the same graft: checked again.
        // KEEL-32 (R3-1): a revoked peer is remounted revoked from its first
        // byte (a fresh connect or grow with `replace` is what lifts it).
        let revoked = self.inner.store.lock().unwrap().revoked.get(name).cloned();
        let mounted = match RemoteChild::connect(spec, self.child_options(&kind).with_revoked(revoked)).await {
            Ok(child) => self.vet(name, &child, expecting.as_deref()).map(|_| child),
            Err(e) => Err(e.to_string()),
        };
        let repin_on_valid_cert = self.config().get(&settings::DYN_REPIN_ON_VALID_CERT);
        let mut peers = self.inner.peers.lock().unwrap();
        // KEEL-19: one key, one mount.
        let mounted = mounted.and_then(|child| match key_held_by(&peers, name, child.peer_key()) {
            Some(other) => {
                let why = key_in_use(name, child.peer_key().unwrap_or_default(), &other);
                tracing::warn!(target: "plexus::audit", peer = %name, holder = %other, key = %child.peer_key().unwrap_or_default(), "dyn refused a mount: its key is another peer's");
                Err(why)
            }
            None => Ok(child),
        });
        let Some(e) = peers.get_mut(name) else { return Err(format!("`{name}` was disconnected while it was mounted")) };
        match mounted {
            Ok(child) => {
                let proved = child.identity().map(PeerIdentity::from);
                match (&e.pin, &proved) {
                    // NEST-21: a renewed certificate (its key moved, the
                    // peer's backend and own key the same, the chain
                    // validated as every dial's is) re-pinned by the setting.
                    (Some(pinned), Some(p)) if pinned != p && repin_on_valid_cert && pinned.only_tls_moved(p) => {
                        tracing::warn!(target: "plexus::audit", peer = %name, old = %pinned.fingerprint(), new = %p.fingerprint(), "dyn re-pinned on a valid certificate (dyn.repin_on_valid_cert)");
                        e.pin = proved.clone();
                        e.presented = None;
                    }
                    (Some(pinned), Some(p)) if pinned != p => {
                        let why = identity_changed(name, pinned, p);
                        tracing::error!(target: "plexus::dyn", peer = %name, %pinned, proved = %p, "refused: another identity");
                        e.why = Some(why.clone());
                        // NEST-21: kept for `dyn.repin`.
                        e.presented = Some(p.clone());
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
                drop(peers);
                self.hold(name, &child);
                // DYNAUTH-7: a revoked peer stays revoked across a remount.
                if let Some(why) = self.inner.store.lock().unwrap().revoked.get(name).cloned() {
                    child.revoke(&why);
                }
                if let Err(why) = self.surface(name, &child) {
                    tracing::warn!(target: "plexus::dyn", peer = %name, "{why}");
                }
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

    /// NEST-16: may `child` be served as `name` here — its `needs` all
    /// served by this service (by shape), and, when `expecting` names an
    /// interface hash, that interface served by the peer's root or one of
    /// its activations.
    fn vet(&self, name: &str, child: &RemoteChild, expecting: Option<&str>) -> Result<(), String> {
        if let Some(want) = expecting {
            let served = served_interfaces(child);
            if !served.iter().any(|(_, h)| h == want) {
                let got: Vec<String> = served.iter().map(|(at, h)| format!("{at} {h}")).collect();
                return Err(format!("`{name}` does not serve the interface it is expected to ({want}): it serves {}", got.join(", ")));
            }
        }
        if let Some(needs) = child.needs() {
            let service = self.inner.host.lock().unwrap().as_ref().and_then(WeakService::upgrade);
            match service {
                Some(service) => service.check_needs(name, needs).map_err(|m| m.to_string())?,
                None => return Err(format!("`{name}` needs {} of its service, which is not known yet: start `dyn` in its service first", needs.iter().map(|n| n.method.as_str()).collect::<Vec<_>>().join(", "))),
            }
        }
        Ok(())
    }

    /// Add (or replace) a peer and mount it; on failure nothing is kept.
    async fn add(&self, name: String, kind: PeerKind, replace: bool, expecting: Option<String>) -> DynEvent {
        // KEEL-31 / KEEL-19: refused at construction — nothing connected or grown.
        if let Some(message) = &self.inner.refused {
            return DynEvent::Error { message: message.clone() };
        }
        if let Err(message) = check_name(&name) {
            return DynEvent::Error { message };
        }
        let replaced = self.inner.peers.lock().unwrap().contains_key(&name);
        if replaced && !replace {
            return DynEvent::Error { message: format!("a peer is connected as `{name}`: disconnect it, or connect with `replace`") };
        }
        if let Err(message) = self.top_free(&name) {
            return DynEvent::Error { message };
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
                if let Err(message) = self.vet(&name, &child, expecting.as_deref()) {
                    return DynEvent::Error { message };
                }
                // KEEL-19: one key, one mount — refused, typed and audited:
                // checked where the entry is reserved, under one hold of the
                // lock (two connects racing on one key mount one).
                let refuse = |peers: &BTreeMap<String, Entry>| {
                    let other = key_held_by(peers, &name, child.peer_key())?;
                    let key = child.peer_key().unwrap_or_default().to_string();
                    tracing::warn!(target: "plexus::audit", peer = %name, holder = %other, %key, "dyn refused a mount: its key is another peer's");
                    let old = peers.get(&other).and_then(|e| e.pin.clone());
                    Some(DynEvent::Refused { reason: Refusal::IdentityChanged, message: key_in_use(&name, &key, &other), old, presented: child.identity().map(PeerIdentity::from) })
                };
                let schema = plexus_core::plexus::Activation::plugin_schema(&child);
                let interface = interface_of(&child);
                let methods = schema.methods.iter().map(|m| m.name.clone()).collect();
                let pin = child.identity().map(PeerIdentity::from);
                // Nothing upward until it is held to its consent below
                // (fail closed while it is reserved).
                child.set_consent(Some(Vec::new()));
                {
                    let mut peers = self.inner.peers.lock().unwrap();
                    if let Some(refused) = refuse(&peers) {
                        return refused;
                    }
                    peers.insert(name.clone(), Entry { kind, child: Some(child.clone()), why: None, remounts: 0, expecting, pin, presented: None });
                }
                // DYNAUTH-5: registered — its key and needs — and held to
                // what is consented for it; only once it holds its name, so
                // a connect refused above dropped nobody's consent.
                self.register(&name, child.peer_key());
                self.hold(&name, &child);
                // DYNAUTH-7: an admin connecting or growing it again is a
                // new registration: a revocation ends here.
                if self.inner.store.lock().unwrap().revoked.remove(&name).is_some() {
                    if let Err(why) = self.save_store() {
                        tracing::error!(target: "plexus::dyn", "{why}");
                    }
                }
                if let Err(message) = self.surface(&name, &child) {
                    self.inner.peers.lock().unwrap().remove(&name);
                    return DynEvent::Error { message };
                }
                DynEvent::Connected { name, interface, methods, replaced }
            }
            Err(e) => DynEvent::Error { message: e.to_string() },
        }
    }

    /// NEST-21: every peer's pin and the identity it presented and was
    /// refused for, if any.
    pub fn pin_list(&self) -> Vec<PinInfo> {
        self.inner
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(name, e)| PinInfo {
                name: name.clone(),
                fingerprint: e.pin.as_ref().map(PeerIdentity::fingerprint),
                pinned: e.pin.clone(),
                presented_fingerprint: e.presented.as_ref().map(PeerIdentity::fingerprint),
                presented: e.presented.clone(),
            })
            .collect()
    }

    /// NEST-21: pin `name` to the identity it presented — only when
    /// `fingerprint` is that identity's ([`PeerIdentity::fingerprint`]), so
    /// nobody accepts blind — and mount it now.
    pub async fn repin_peer(&self, name: &str, fingerprint: &str) -> DynEvent {
        let (old, pinned) = {
            let mut peers = self.inner.peers.lock().unwrap();
            let Some(e) = peers.get_mut(name) else { return DynEvent::Error { message: format!("no peer `{name}`") } };
            let Some(presented) = e.presented.clone() else {
                return DynEvent::Refused { reason: Refusal::NotPresented, message: format!("`{name}` presented no other identity: nothing to re-pin"), old: e.pin.clone(), presented: None };
            };
            if presented.fingerprint() != fingerprint.trim() {
                return DynEvent::Refused {
                    reason: Refusal::FingerprintMismatch,
                    message: format!("`{fingerprint}` is not what `{name}` presented: compare `dyn.pins`' presented_fingerprint with the peer's own"),
                    old: e.pin.clone(),
                    presented: Some(presented),
                };
            }
            let old = e.pin.replace(presented.clone());
            e.presented = None;
            e.why = Some("re-pinned; mounting".into());
            (old, presented)
        };
        // DYNAUTH-5: another key is another client — its consent goes.
        self.register(name, pinned.key.as_deref());
        tracing::warn!(target: "plexus::audit", peer = %name, actor = %plexus_core::plexus::config::current_actor().join(" < "), old = %old.as_ref().map(PeerIdentity::fingerprint).unwrap_or_default(), new = %pinned.fingerprint(), "dyn repin");
        let up = match self.mount(name, true).await {
            Ok(_) => true,
            Err(why) => {
                tracing::warn!(target: "plexus::dyn", peer = %name, "re-pinned, not mounted yet: {why}");
                false
            }
        };
        DynEvent::Repinned { name: name.to_string(), old, fingerprint: pinned.fingerprint(), pinned, up }
    }

    /// The peers, listed.
    pub fn list(&self) -> Vec<PeerInfo> {
        let revoked = self.inner.store.lock().unwrap().revoked.clone();
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
                    // A dead mount (a remount refused: NEST-16, DYNAUTH-8)'s last word is dyn's remount (refused, or failing).
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
                    revoked: revoked.get(name).cloned(),
                    presented: e.presented.clone(),
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

    /// DYNAUTH-9: what no dendrite may read.
    fn denied(&self) -> Vec<PathBuf> {
        let o = &self.inner.opts;
        let mut out = Containment::default_deny(&o.data_dir);
        out.extend(o.child.key.iter().cloned());
        // KEEL-19: the dial key, wherever it is kept.
        out.extend(self.inner.dial_key.iter().cloned());
        // DYNAUTH-12: the signing key, wherever it is kept.
        out.extend(o.key_file.iter().cloned());
        out.extend(o.contain.deny.iter().cloned());
        // NEST-21: `dyn.containment.deny` adds, never takes away.
        out.extend(self.config().get(&settings::DYN_CONTAINMENT_DENY).into_iter().map(PathBuf::from));
        out
    }

    /// NEST-21: the options' containment, `dyn.containment.require` read now.
    fn containment(&self) -> Containment {
        Containment { require: self.config().get(&settings::DYN_CONTAINMENT_REQUIRE), ..self.inner.opts.contain.clone() }
    }

    fn data_dir_for(&self, name: &str) -> PathBuf {
        self.inner.opts.data_dir.join(name)
    }
}

/// DYNAUTH-8 (TM-3): whether `url` may be dialed — `wss://` anywhere,
/// `ws://` only to loopback (`127.0.0.0/8`, `::1`, `localhost`) unless
/// `insecure` allows it. `Err`: the refusal, said. KEEL-7: plexus-core's
/// [`check_ws_url`](plexus_core::plexus::check_ws_url) decides, the one
/// every dial of the service asks; this names its reason.
pub fn check_url(url: &str, insecure: bool) -> Result<(), (Refusal, String)> {
    plexus_core::plexus::check_ws_url(url, insecure).map_err(|why| (Refusal::InsecureTransport, why))
}

fn identity_changed(name: &str, pinned: &PeerIdentity, proved: &PeerIdentity) -> String {
    format!("`{name}` proved another identity ({proved}) than the one pinned when it was connected ({pinned}): connect it again with `replace` to trust it")
}

/// A mounted peer's interface hash: its whole tree's (the schema hash its
/// mount compares across restarts, NEST-4), as 16 hex digits.
fn interface_of(child: &RemoteChild) -> String {
    plexus_core::plexus::content_hash::hash16(child.mounted_hash().as_bytes())
}

/// NEST-16: the interfaces a mounted peer serves — its root's and each of
/// its activations' (its static children's), by path, each `Interface`'s
/// hash (of its methods' shapes, whatever it is mounted as).
fn served_interfaces(child: &RemoteChild) -> Vec<(String, String)> {
    use plexus_core::plexus::peer::Interface;
    use plexus_core::plexus::Activation;
    let mut out = vec![("(root)".to_string(), Interface::named(child.name(), &child.plugin_schema()).hash)];
    for (path, schema) in child.static_child_schemas() {
        out.push((path.clone(), Interface::named(&path, &schema).hash));
    }
    out
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

/// KEEL-31: dyn's methods that act on the whole service — its admin writes,
/// and its reads of every peer, consent and pin — each marked `everywhere`,
/// which [`DynActivation::start`] checks.
pub const EVERYWHERE: &[&str] =
    &["connect", "grow", "disconnect", "consent", "consents", "revoke", "rotate_key", "pins", "repin", "peers", "names"];

/// Runtime peers: connect services, grow dendrites, call them as
/// `dyn.peer.<name>.<path>.<method>`.
#[plexus_macros::activation(roles(viewer = ["peers", "names", "consents", "pins"]))]
impl DynActivation {
    /// Connect the service at `url` (a WebSocket) as the peer `name`; a taken
    /// name is refused unless `replace`. `wss://` anywhere, `ws://` only to
    /// loopback (`refused`, `insecure_transport`); its identity is pinned.
    #[plexus_macros::method(everywhere)]
    ///
    /// `expecting` (NEST-16): an interface hash, a contract's stamp — the
    /// peer must serve exactly that interface, now and at every remount.
    pub async fn connect(&self, name: String, url: String, replace: Option<bool>, expecting: Option<String>) -> DynEvent {
        if let Err((reason, message)) = check_url(&url, self.insecure_ws()) {
            return DynEvent::Refused { reason, message, old: None, presented: None };
        }
        self.add(name, PeerKind::Ws { url }, replace.unwrap_or(false), expecting).await
    }

    /// Grow a dendrite: `source` (its `index.ts`) served as the peer `name`,
    /// its clients grown toward `targets` (other peers, `weather` or
    /// `weather.forecasts`, each called back through this service).
    #[plexus_macros::method(everywhere)]
    ///
    /// `expecting` (NEST-16): as `connect`'s.
    pub async fn grow(&self, name: String, source: String, targets: Vec<String>, replace: Option<bool>, expecting: Option<String>) -> DynEvent {
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
        self.add(name, PeerKind::Dendrite { dir: dir.display().to_string(), via: targets }, replace.unwrap_or(false), expecting).await
    }

    /// Let go of the peer `name` (a dendrite's process ends with its last call).
    #[plexus_macros::method(everywhere)]
    pub async fn disconnect(&self, name: String) -> DynEvent {
        let gone = self.inner.peers.lock().unwrap().remove(&name);
        match gone {
            Some(_) => {
                self.unsurface(&name);
                DynEvent::Disconnected { name }
            }
            None => DynEvent::Error { message: format!("no peer `{name}`") },
        }

    }

    /// DYNAUTH-5: consent to what `peer` asks for. `needs`: the subset of
    /// its declared needs it may call back up through this service, each
    /// `method` or `method@scope`; `callers`: the roles whose holders may
    /// call into it. Replaces what it held; empty lists withdraw it.
    #[plexus_macros::method(everywhere)]
    pub async fn consent(&self, peer: String, needs: Option<Vec<String>>, callers: Option<Vec<String>>) -> DynEvent {
        match self.set_consent(&peer, needs.unwrap_or_default(), callers.unwrap_or_default()) {
            Ok(c) => DynEvent::Consented { peer, needs: c.needs, callers: c.callers },
            Err(message) => DynEvent::Error { message },
        }
    }

    /// DYNAUTH-5: each peer's registration — its key, what it declares it
    /// needs — and what is consented, what is still pending.
    #[plexus_macros::method(everywhere)]
    pub async fn consents(&self) -> impl Stream<Item = ConsentInfo> + Send + 'static {
        futures::stream::iter(self.consent_list())
    }

    /// DYNAUTH-7: revoke `peer`: nothing is forwarded to it from now (no
    /// token minted), every call it is making back ends, its consent goes;
    /// listed as revoked until it is connected or grown again with
    /// `replace`. Tokens already issued expire within 60 s.
    #[plexus_macros::method(everywhere)]
    pub async fn revoke(&self, peer: String, why: Option<String>) -> DynEvent {
        let why = why.unwrap_or_else(|| "revoked by an admin".into());
        match self.revoke_peer(&peer, &why) {
            Ok(()) => DynEvent::Revoked { peer, why },
            Err(message) => DynEvent::Error { message },
        }
    }

    /// DYNAUTH-7: rotate the signing key: a new one signs from now, the old
    /// one stays in `dyn.jwks` for one token lifetime, then goes.
    #[plexus_macros::method(everywhere)]
    pub async fn rotate_key(&self) -> DynEvent {
        match self.rotate_signing_key() {
            Ok((kid, previous)) => DynEvent::Rotated { kid, previous },
            Err(message) => DynEvent::Error { message },
        }
    }

    /// DYNAUTH-6: RFC 8693 token exchange. `subject_token`, a token this
    /// service minted for a peer, presented by that peer with `proof` (its
    /// proof of possession for method `exchange` under the token's `call`),
    /// becomes a token for the connected peer `audience` (one that proved a
    /// key) and `method` (the audience's, `<backend>.<m>`): the same `sub`,
    /// the presenter added to `act`. KEEL-19: only for a presenter mounted
    /// here, not revoked, consented to reach `dyn.peer.<audience>.<m>`; its
    /// scope `method` where the subject holds that need and consent allows,
    /// narrowed to `scope` when asked; bound to the presenter's key (the
    /// audience takes it only with the presenter's proof); once per subject,
    /// audience and method. A token bound to no key (a pipe's) is not
    /// exchanged.
    #[plexus_macros::method(public)]
    pub async fn exchange(&self, subject_token: String, proof: String, audience: String, scope: Option<Vec<String>>, method: Option<String>) -> ExchangeEvent {
        match self.exchange_for(&subject_token, &proof, &audience, scope.as_deref(), method.as_deref().unwrap_or_default()) {
            Ok((access_token, claims)) => ExchangeEvent::Exchanged {
                access_token,
                issued_token_type: plexus_core::plexus::peer_token::JWT_TOKEN_TYPE.into(),
                token_type: "N_A".into(),
                scope: claims.scope,
                expires_in: claims.exp.saturating_sub(claims.iat),
            },
            Err(message) => ExchangeEvent::Error { message },
        }
    }

    /// DYNAUTH-12: the keys this service signs its peers' tokens with (a
    /// JWK Set: Ed25519, `kid` the key's id) — public, as a JWKS is.
    #[plexus_macros::method(public)]
    pub async fn jwks(&self) -> Jwks {
        self.inner.issuer.jwks()
    }

    /// NEST-21: every peer's pin — the identity pinned and its fingerprint,
    /// and the identity it last presented and was refused for, with the
    /// fingerprint `dyn.repin` takes.
    #[plexus_macros::method(everywhere)]
    pub async fn pins(&self) -> impl Stream<Item = PinInfo> + Send + 'static {
        futures::stream::iter(self.pin_list())
    }

    /// NEST-21: pin `name` to the identity it presented and was refused for
    /// (`identity_changed`) — only when `fingerprint` is exactly that
    /// identity's (`dyn.pins`' `presented_fingerprint`, checked against the
    /// peer's own word), so nobody re-pins blind — and mount it again.
    #[plexus_macros::method(everywhere)]
    pub async fn repin(&self, name: String, fingerprint: String) -> DynEvent {
        self.repin_peer(&name, &fingerprint).await
    }

    /// Every peer: its kind, whether it is up, its interface's hash, its
    /// restarts, open calls and calls.
    #[plexus_macros::method(everywhere)]
    pub async fn peers(&self) -> impl Stream<Item = PeerInfo> + Send + 'static {
        futures::stream::iter(self.list())
    }

    /// Every peer's name (the slot's list: a slot lists names).
    #[plexus_macros::method(everywhere)]
    pub async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::iter(self.list().into_iter().map(|p| p.name))
    }

    /// A peer by name: `dyn.peer.<name>.<path>.<method>`.
    #[plexus_macros::peer(list = names)]
    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        self.get(name).await.map(|c| Box::new(c) as Box<dyn Peer>)
    }
}

#[cfg(test)]
mod r3_1 {
    use super::*;

    /// KEEL-32 (R3-1): every mount dyn makes keeps a consent from its
    /// handshake on — nothing a peer declares counts until `hold`.
    #[test]
    fn every_mount_holds_its_consent_from_the_handshake() {
        let data = tempfile::tempdir().unwrap();
        let dyn_ = DynActivation::new(DynOptions { data_dir: data.path().join("dyn"), dendrite: data.path().join("no-dendrite"), ..DynOptions::default() });
        for kind in [PeerKind::Ws { url: "ws://127.0.0.1:1".into() }, PeerKind::Dendrite { dir: "d".into(), via: vec!["w".into()] }] {
            assert!(dyn_.child_options(&kind).consent_required, "{kind:?}");
        }
    }
}
