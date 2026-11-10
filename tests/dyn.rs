//! NEST-12's gate: `dyn` in a gated service, two services on loopback.
//!
//! The far service (`far`, a `DynamicHub` with `weather`) is served on a
//! WebSocket in 4800–4899; the host (`host`, a gated `DynamicHub` with `dyn`)
//! is called in memory. Each test is one row of the ticket:
//!
//! - connect, call through `dyn.peer.<name>`, disconnect;
//! - a caller without the slot grant is refused;
//! - the far side restarts: the peer is redialed;
//! - the far side restarts with another schema: `dyn` remounts it;
//! - a dendrite grown against a connected peer calls it through the host —
//!   as the caller: one holding the dendrite's method alone is refused the
//!   peer it calls;
//! - a peer that goes silent is marked down by the ping;
//! - `--peers FILE`: a failing peer listed down, then up once it is;
//! - NEST-15, `top_level`: a peer served at the host's own top level too,
//!   gated by its own grants, gone with it; `dyn.peer.<name>` unchanged.
//! - NEST-16: `connect --expecting <stamp>` refuses a peer whose interface
//!   differs, at connect and at a remount; a dendrite declaring needs this
//!   service does not serve is refused at `grow`, naming them;
//! - NEST-14: `DynClient` reaches a peer through the slot — untyped, by
//!   method name, and typed, as the far activation's own client once the
//!   peer's schema says it serves it (`ShapeMismatch` else);
//! - DYNAUTH-8: `ws://` beyond loopback refused (`insecure_transport`), or
//!   allowed and said (`insecure`); a `wss://` peer's certificate validated
//!   and its key pinned — a restart with another key refused
//!   (`identity_changed`) until it is connected again with `replace`.
//! - NEST-21: a setting flipped through `config` takes effect at the next
//!   connect, shows in `config.list`, reverts unconfirmed, is refused for a
//!   viewer and audited; `dyn.repin` takes only the presented fingerprint;
//!   `dyn.repin_on_valid_cert` follows a renewed certificate.
//! - DYNAUTH-9: a grown dendrite is contained — it cannot read a key file,
//!   another dendrite's directory or `~/.plexus`, nor see the host's
//!   environment; it reads and writes its own directory. Without its
//!   launcher it is refused when containment is required, else run with a
//!   cleared environment.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, Stream, StreamExt};
use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_core::plexus::{AuthContext, PlexusStream, PlexusStreamItem};
use plexus_core::DynamicHub;
use plexus_core::plexus::HubTransport;
use plexus_dyn::{Containment, DynActivation, DynClient, DynOptions, PeerInfo};
use serde_json::{json, Value};

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const USER: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VIEWER: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_ONLY: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const TOP: &str = "key:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// ------------------------------------------------------------------ the far service

#[derive(Clone)]
pub struct WeatherActivation;

/// Rain, by day: deterministic per city.
#[plexus_macros::activation]
impl WeatherActivation {
    /// Each day's rain in `city`, in millimetres.
    #[plexus_macros::method]
    pub async fn forecast(&self, city: String) -> impl Stream<Item = Value> + Send + 'static {
        let seed = city.bytes().map(u64::from).sum::<u64>();
        futures::stream::iter((0..7u64).map(move |d| json!({ "day": d, "rain": ((seed + d * 7) % 10) as f64 / 10.0 })))
    }
}

#[derive(Clone)]
pub struct ExtraActivation;

/// Only in the far service's second shape.
#[plexus_macros::activation]
impl ExtraActivation {
    /// Something new.
    #[plexus_macros::method]
    pub async fn new_thing(&self) -> Value {
        json!("new")
    }
}

fn rainy_days(city: &str) -> usize {
    let seed = city.bytes().map(u64::from).sum::<u64>();
    (0..7u64).filter(|d| ((seed + d * 7) % 10) as f64 / 10.0 > 0.5).count()
}

/// A free port in 4800–4899.
fn free_port() -> u16 {
    static NEXT: Mutex<u16> = Mutex::new(0);
    let mut n = NEXT.lock().unwrap();
    if *n == 0 {
        *n = 4800 + (std::process::id() % 50) as u16;
    }
    for _ in 0..100 {
        let p = *n;
        *n = if *n >= 4899 { 4800 } else { *n + 1 };
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    panic!("no free port in 4800–4899");
}

/// The far service on `port`; `extra` adds an activation (another schema).
async fn far(port: u16, extra: bool) -> jsonrpsee::server::ServerHandle {
    let mut svc = DynamicHub::new("far").register(WeatherActivation);
    if extra {
        svc = svc.register(ExtraActivation);
    }
    let module = DynamicHub::arc_into_rpc_module(Arc::new(svc)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match jsonrpsee::server::Server::builder().build(format!("127.0.0.1:{port}")).await {
            Ok(server) => return server.start(module),
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("port {port}: {e}"),
        }
    }
}

async fn stop(h: jsonrpsee::server::ServerHandle) {
    let _ = h.stop();
    h.stopped().await;
}

// ------------------------------------------------------------------ the host

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}
struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _t: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], Value::Null)
}

fn dendrite_bin() -> PathBuf {
    std::env::var_os("PLEXUS_DENDRITE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-dendrite/bin/plexus-dendrite"))
}

struct Rig {
    host: Arc<DynamicHub>,
    dyn_: DynActivation,
    _data: tempfile::TempDir,
}

/// ADMIN: admin; USER: `dyn.{peer}` and `dyn.peers`; VIEWER: viewer
/// (`dyn.peers`, `dyn.names`); DIGEST_ONLY: the literal
/// `dyn.peer.digest.rainy` and nothing else; TOP: `w.weather.forecast` (a
/// peer at the top level, NEST-15) and nothing else.
async fn rig_with(peers_file: Option<PathBuf>) -> Rig {
    rig_opts(peers_file, |_| {}).await
}

async fn rig_opts(peers_file: Option<PathBuf>, tweak: impl FnOnce(&mut DynOptions)) -> Rig {
    let data = tempfile::tempdir().unwrap();
    let mut opts = DynOptions {
        // KEEL-19 (KEEL-25): a directory `dyn` makes itself, 0700 (a temp
        // directory may be 0755, which it refuses).
        data_dir: data.path().join("dyn"),
        dendrite: dendrite_bin(),
        liveness: Duration::from_millis(300),
        peers_file,
        ..DynOptions::default()
    };
    // DYNAUTH-9: every dendrite here runs contained, by this build's launcher.
    opts.contain.launcher = Some(PathBuf::from(env!("CARGO_BIN_EXE_plexus-dyn-contain")));
    tweak(&mut opts);
    let dyn_ = DynActivation::new(opts);
    let plain = DynamicHub::new("host").register(dyn_.clone());
    let declared = plain.declared_roles();
    let mut lists: Vec<(String, Vec<String>)> = declared.into_iter().collect();
    lists.push(("user".into(), vec!["dyn.{peer}".into(), "dyn.peers".into()]));
    lists.push(("digest_only".into(), vec!["dyn.peer.digest.rainy".into()]));
    lists.push(("top".into(), vec!["w.weather.forecast".into()]));
    let roles = RoleTable::from_lists(lists.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (p, r) in [(ADMIN, "admin"), (USER, "user"), (VIEWER, "viewer"), (DIGEST_ONLY, "digest_only"), (TOP, "top")] {
        members.0.lock().unwrap().push(Membership { principal: p.parse().unwrap(), role: plexus_auth_core::RoleName::new(r), scope: ScopeRef::Everywhere });
    }
    // DYNAUTH-5: the roles, plus what consent gives a role.
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Everywhere)));
    // NEST-21: the service's configuration served, as `config` (admin's).
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).with_config_service().with_gate(gate));
    dyn_.start(&host).await.unwrap();
    Rig { host, dyn_, _data: data }
}

async fn rig() -> Rig {
    rig_with(None).await
}

async fn items(r: Result<PlexusStream, plexus_core::plexus::PlexusError>) -> Vec<Value> {
    match r {
        Err(e) => vec![json!({ "route_error": format!("{e}") })],
        Ok(stream) => stream
            .map(|i| match i {
                PlexusStreamItem::Data { content, .. } => content.into_value(),
                other => serde_json::to_value(other).unwrap(),
            })
            .filter(|v| futures::future::ready(v["type"] != "done"))
            .collect()
            .await,
    }
}

async fn call(r: &Rig, caller: &str, method: &str, params: Value) -> Vec<Value> {
    items(r.host.route(method, params, Some(&who(caller))).await).await
}

fn peer<'a>(r: &Rig, name: &str) -> PeerInfo {
    r.dyn_.list().into_iter().find(|p| p.name == name).unwrap_or_else(|| panic!("no peer {name}"))
}

/// Call until it answers data, or fail at the deadline naming what came.
async fn until_data(r: &Rig, caller: &str, method: &str, params: Value, within: Duration) -> Vec<Value> {
    let deadline = Instant::now() + within;
    loop {
        let got = call(r, caller, method, params.clone()).await;
        if got.first().is_some_and(|v| v.get("type").is_none() && v.get("route_error").is_none()) {
            return got;
        }
        assert!(Instant::now() < deadline, "{method}: never answered: {got:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ------------------------------------------------------------------ the rows

async fn connect_call_disconnect() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    let url = format!("ws://127.0.0.1:{port}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(got[0]["replaced"], false);
    // A taken name is refused unless replace.
    let again = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(again[0]["type"], "error", "{again:?}");
    let replaced = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url, "replace": true })).await;
    assert_eq!(replaced[0]["replaced"], true, "{replaced:?}");
    // Through the slot.
    let days = call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert_eq!(days.len(), 7, "{days:?}");
    assert_eq!(days[0]["day"], 0);
    let s = call(&r, USER, "dyn.peer.w.weather.schema", json!({})).await;
    assert_eq!(s[0]["namespace"], "weather", "{s:?}");
    // peers / names.
    let listed = call(&r, VIEWER, "dyn.peers", json!({})).await;
    assert_eq!(listed[0]["name"], "w", "{listed:?}");
    assert_eq!((listed[0]["kind"].as_str(), listed[0]["up"].as_bool()), (Some("ws"), Some(true)), "{listed:?}");
    assert!(listed[0]["interface"].as_str().is_some_and(|h| !h.is_empty()), "{listed:?}");
    assert_eq!(listed[0]["calls"], 1, "the schema is the mount's, never a call: {listed:?}");
    assert_eq!(call(&r, VIEWER, "dyn.names", json!({})).await, [json!("w")]);
    // Disconnect: gone from the slot.
    let gone = call(&r, ADMIN, "dyn.disconnect", json!({ "name": "w" })).await;
    assert_eq!(gone[0], json!({ "type": "disconnected", "name": "w" }));
    let after = call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert_eq!(after[0]["error_kind"], "not_found", "{after:?}");
    stop(far).await;
}

async fn a_caller_without_the_grant_is_refused() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    let refused = call(&r, VIEWER, "dyn.peer.w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|e| e.contains("dyn.{peer}")), "{refused:?}");
    let refused = call(&r, USER, "dyn.connect", json!({ "name": "x", "url": "ws://127.0.0.1:1" })).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|e| e.contains("dyn.connect")), "connect is the admin's: {refused:?}");
    let refused = call(&r, VIEWER, "dyn.disconnect", json!({ "name": "w" })).await;
    assert!(refused[0]["route_error"].is_string(), "{refused:?}");
    stop(far).await;
}

async fn the_far_side_restarts_and_is_redialed() {
    let port = free_port();
    let far1 = far(port, false).await;
    let r = rig().await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await.len(), 7);
    stop(far1).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while peer(&r, "w").up {
        assert!(Instant::now() < deadline, "never marked down");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let down = peer(&r, "w");
    assert!(!down.up && down.why.is_some(), "{down:?}");
    let far2 = far(port, false).await;
    let days = until_data(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" }), Duration::from_secs(15)).await;
    assert_eq!(days.len(), 7);
    let back = peer(&r, "w");
    assert!(back.up && back.restarts >= 1 && back.remounts == 0, "{back:?}");
    stop(far2).await;
}

async fn a_changed_schema_is_remounted() {
    let port = free_port();
    let far1 = far(port, false).await;
    let r = rig().await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    let before = peer(&r, "w").interface.unwrap();
    let missing = call(&r, USER, "dyn.peer.w.extra.new_thing", json!({})).await;
    assert!(missing[0].get("type").is_some() || missing[0].get("route_error").is_some(), "{missing:?}");
    stop(far1).await;
    let far2 = far(port, true).await;
    let got = until_data(&r, USER, "dyn.peer.w.extra.new_thing", json!({}), Duration::from_secs(15)).await;
    assert_eq!(got[0], "new");
    let now = peer(&r, "w");
    assert_eq!(now.remounts, 1, "{now:?}");
    assert_ne!(now.interface.unwrap(), before, "the new shape's interface");
    assert_eq!(call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "rome" })).await.len(), 7);
    stop(far2).await;
}

const DIGEST: &str = r#"// A dendrite grown by plexus-dyn's test: `weather` is the peer `w`'s, called back through the host.
import { weather } from "./clients/weather";

/** How many of the next seven days rain over half a millimetre in `city`. */
export async function rainy({ city }: { city: string }) {
  let rain_days = 0;
  for await (const day of weather.forecast({ city })) if ((day as { rain: number }).rain > 0.5) rain_days++;
  return { rain_days };
}
"#;

async fn a_dendrite_calls_its_target_through_the_host() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    let grown = call(&r, ADMIN, "dyn.grow", json!({ "name": "digest", "source": DIGEST, "targets": ["w.weather"] })).await;
    assert_eq!(grown[0]["type"], "connected", "{grown:?}");
    assert_eq!(grown[0]["methods"], json!(["rainy"]), "{grown:?}");
    // DYNAUTH-5: what it declares it needs is a request; until an admin
    // consents, its call back is refused, saying so.
    let unconsented = call(&r, USER, "dyn.peer.digest.rainy", json!({ "city": "lisbon" })).await;
    assert!(format!("{unconsented:?}").contains("consented"), "{unconsented:?}");
    let ok = call(&r, ADMIN, "dyn.consent", json!({ "peer": "digest", "needs": ["dyn.peer.w.weather.forecast"] })).await;
    assert_eq!(ok[0]["type"], "consented", "{ok:?}");
    let got = call(&r, USER, "dyn.peer.digest.rainy", json!({ "city": "lisbon" })).await;
    assert_eq!(got[0], json!({ "rain_days": rainy_days("lisbon") }), "{got:?}");
    let d = peer(&r, "digest");
    assert_eq!((d.calls_back, d.up), (2, true), "its target's schema at its start, then one call back taken (a refused one is not made): {d:?}");
    assert!(matches!(d.peer, plexus_dyn::PeerKind::Dendrite { .. }), "{d:?}");
    // As the caller: one holding `dyn.peer.digest.rainy` alone reaches the
    // dendrite, and its call back to `w` is refused by the host's gate.
    let refused = call(&r, DIGEST_ONLY, "dyn.peer.digest.rainy", json!({ "city": "lisbon" })).await;
    assert_eq!(refused[0]["type"], "error", "{refused:?}");
    assert!(refused[0]["message"].as_str().is_some_and(|m| m.contains("dyn.{peer}") || m.contains("Forbidden")), "{refused:?}");
    // And one holding nothing of it is refused at the door.
    let refused = call(&r, VIEWER, "dyn.peer.digest.rainy", json!({ "city": "lisbon" })).await;
    assert!(refused[0]["route_error"].is_string(), "{refused:?}");
    stop(far).await;
}

// ------------------------------------------------------------------ DYNAUTH-5

/// A WebSocket peer serving `WeatherActivation` as plexus-core's far side
/// (`serve_child_with`), proving its key at `_info` when it has one. The
/// task, aborted, closes every connection.
async fn keyed_peer(port: u16, opts: plexus_core::plexus::remote_child::ServeChild) -> tokio::task::JoinHandle<()> {
    served_peer(port, WeatherActivation, opts).await
}

/// [`keyed_peer`] serving any activation.
async fn served_peer<A>(port: u16, activation: A, opts: plexus_core::plexus::remote_child::ServeChild) -> tokio::task::JoinHandle<()>
where
    A: plexus_core::plexus::Activation + Clone + Send + Sync + 'static,
{
    served_peer_after(port, activation, opts, Duration::ZERO).await
}

/// [`served_peer`], each upgrade answered only after `delay` (a peer slow to
/// come back).
async fn served_peer_after<A>(port: u16, activation: A, opts: plexus_core::plexus::remote_child::ServeChild, delay: Duration) -> tokio::task::JoinHandle<()>
where
    A: plexus_core::plexus::Activation + Clone + Send + Sync + 'static,
{
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = loop {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => break l,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("port {port}: {e}"),
        }
    };
    // KEEL-19: each upgrade's key proof verified (plexus-core's
    // `serve_child_ws`), the child served on a connection proven as the key
    // that dialed — `opts.peer` names whom it trusts to act for others.
    let upgrade = Arc::new(plexus_core::plexus::remote_child::KeyedUpgrade::new([format!("ws://127.0.0.1:{port}")]));
    let trusted = match &opts.peer {
        plexus_core::plexus::remote_child::ChildPeer::Connection { acts_for_others, .. } => acts_for_others.clone(),
        plexus_core::plexus::remote_child::ChildPeer::Pipe => Vec::new(),
    };
    tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (activation, upgrade, trusted, key, tokens) = (activation.clone(), Arc::clone(&upgrade), trusted.clone(), opts.key.clone(), opts.tokens.clone());
            conns.spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = plexus_core::plexus::remote_child::serve_child_ws(activation, tcp, &upgrade, trusted, key, tokens).await;
            });
        }
    })
}

/// The name `dyn` acts as when it has no dial key — which no transport
/// proves (KEEL-19: no keyed peer may be served on it).
const DYN: &str = "service:dyn";

/// KEEL-19: whom a keyed peer trusts to act for others — `r`'s `dyn`, by the
/// key it dials with (`<data_dir>/dial.key`). `served_peer` serves each
/// connection proven as the key its upgrade's proof verified
/// (`serve_child_ws`); the `proven` here is replaced by that.
fn trusting(r: &Rig) -> plexus_core::plexus::remote_child::ChildPeer {
    let dial = r.dyn_.dial_principal().expect("dyn dials with a key by default");
    plexus_core::plexus::remote_child::ChildPeer::connection("(proven at the upgrade)", [dial])
}

fn keyed(key: &plexus_core::plexus::peer_token::PeerKey, r: &Rig) -> plexus_core::plexus::remote_child::ServeChild {
    plexus_core::plexus::remote_child::ServeChild { key: Some(key.clone()), peer: trusting(r), tokens: None }
}

/// A viewer reaches a peer once an admin consents to its role calling it;
/// before, and after the consent is withdrawn, it is refused naming the
/// grant. The slot grant stays the admin's.
async fn a_viewer_with_consent_reaches_a_peer() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let refused = call(&r, VIEWER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await;
    let why = refused[0]["route_error"].as_str().unwrap_or_default().to_string();
    assert!(why.contains("dyn.{peer}") || why.contains("dyn.peer.w.weather.forecast"), "forbidden, naming the grant: {refused:?}");
    // Consent: the viewer role may call it.
    let ok = call(&r, ADMIN, "dyn.consent", json!({ "peer": "w", "callers": ["viewer"] })).await;
    assert_eq!(ok[0], json!({ "type": "consented", "peer": "w", "needs": [], "callers": ["viewer"] }), "{ok:?}");
    assert_eq!(call(&r, VIEWER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await.len(), 7);
    // Only an admin consents.
    let refused = call(&r, VIEWER, "dyn.consent", json!({ "peer": "w", "callers": ["viewer"] })).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|e| e.contains("dyn.consent")), "{refused:?}");
    // Listed: no key (a full service proves none), nothing declared.
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    assert_eq!(listed[0]["peer"], "w", "{listed:?}");
    assert_eq!(listed[0]["callers"], json!(["viewer"]), "{listed:?}");
    // Kept in the data directory, 0600.
    let file = r.dyn_.options().data_dir.join("consent.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Withdrawn: refused again.
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "w" })).await;
    let refused = call(&r, VIEWER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await;
    assert!(refused[0]["route_error"].is_string(), "{refused:?}");
    // A consent to a need it does not declare is refused.
    let wider = call(&r, ADMIN, "dyn.consent", json!({ "peer": "w", "needs": ["dyn.grow"] })).await;
    assert!(wider[0]["message"].as_str().is_some_and(|m| m.contains("dyn.grow") && m.contains("does not declare")), "{wider:?}");
    stop(far).await;
}

/// A peer proves its key at `_info`; it is registered and pinned, and a
/// remount proving another key is refused until `connect … replace` — which
/// registers a new client, so its consent is dropped.
async fn a_peer_whose_key_changed_is_refused_at_remount() {
    use plexus_core::plexus::peer_token::PeerKey;
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}");
    let (one, two) = (PeerKey::generate(), PeerKey::generate());
    let r = rig().await;
    let first = keyed_peer(port, keyed(&one, &r)).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "k", "url": url })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let p = peer(&r, "k");
    assert_eq!(p.identity.as_ref().and_then(|i| i.key.as_deref()), Some(one.kid()), "registered: {p:?}");
    assert_eq!(call(&r, USER, "dyn.peer.k.forecast", json!({ "city": "oslo" })).await.len(), 7);
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "k", "callers": ["viewer"] })).await;
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    assert_eq!(listed[0]["key"], one.kid(), "{listed:?}");
    // A peer that names a key it cannot prove is refused at connect.
    // (Another key restarts on the same port.)
    first.abort();
    let _ = first.await;
    let second = keyed_peer(port, keyed(&two, &r)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = call(&r, USER, "dyn.peer.k.forecast", json!({ "city": "oslo" })).await;
        let p = peer(&r, "k");
        if p.why.as_deref().is_some_and(|w| w.contains("identity") || w.contains("another")) {
            assert!(got.len() < 7 && !p.up, "{got:?} {p:?}");
            break;
        }
        assert!(Instant::now() < deadline, "a new key was never refused: {got:?} {p:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    let p = peer(&r, "k");
    assert!(!p.up && p.identity.as_ref().and_then(|i| i.key.as_deref()) == Some(one.kid()), "still pinned to the first key: {p:?}");
    let again = call(&r, ADMIN, "dyn.connect", json!({ "name": "k", "url": url, "replace": true })).await;
    assert_eq!(again[0]["type"], "connected", "{again:?}");
    assert_eq!(peer(&r, "k").identity.and_then(|i| i.key), Some(two.kid().to_string()), "re-registered");
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    assert_eq!(listed[0]["callers"], json!([]), "another key, another client: its consent dropped: {listed:?}");
    second.abort();
}

// ------------------------------------------------------------------ DYNAUTH-12

/// A far side that verifies: its key, and the host's JWKS trusted.
fn verifying(key: &plexus_core::plexus::peer_token::PeerKey, jwks: &plexus_core::plexus::peer_token::Jwks, r: &Rig) -> plexus_core::plexus::remote_child::ServeChild {
    let v = plexus_core::plexus::peer_token::Verifier::new(key.kid(), jwks).unwrap();
    plexus_core::plexus::remote_child::ServeChild { key: Some(key.clone()), tokens: Some(Arc::new(v)), peer: trusting(r) }
}

/// A far side that verifies takes a call by the token `dyn` minted for it;
/// one trusting another issuer, or one `dyn` mints nothing for, refuses.
/// `dyn.jwks` is public: the current key, `kid` its id.
async fn a_verifying_peer_takes_a_call_by_its_token() {
    use plexus_core::plexus::peer_token::{Jwks, PeerKey};
    let r = rig().await;
    let jwks: Vec<Value> = items(r.host.route("dyn.jwks", json!({}), None).await).await;
    assert_eq!(jwks[0]["keys"][0]["kty"], "OKP", "anonymous: {jwks:?}");
    assert_eq!(jwks[0]["keys"][0]["kid"], r.dyn_.issuer().kid(), "{jwks:?}");
    let key = PeerKey::generate();
    let port = free_port();
    let peer_task = keyed_peer(port, verifying(&key, &r.dyn_.jwk_set(), &r)).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "v", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(call(&r, USER, "dyn.peer.v.forecast", json!({ "city": "oslo" })).await.len(), 7, "taken by its token");
    // An anonymous caller is never forwarded (the gate), so no token is
    // minted without a `sub`.
    peer_task.abort();
    // A peer trusting another issuer refuses this one's tokens. (KEEL-19:
    // a key of its own — `v`'s is `v`'s alone here.)
    let port = free_port();
    let stranger = keyed_peer(port, verifying(&PeerKey::generate(), &Jwks { keys: vec![PeerKey::generate().jwk()] }, &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "s", "url": format!("ws://127.0.0.1:{port}") })).await;
    let refused = call(&r, USER, "dyn.peer.s.forecast", json!({ "city": "oslo" })).await;
    assert!(refused[0]["message"].as_str().is_some_and(|m| m.contains("token is refused") && m.contains("not trusted")), "{refused:?}");
    stranger.abort();
    // A peer that verifies, under a `dyn` that mints no tokens: refused.
    let r2 = rig_opts(None, |o| o.tokens = false).await;
    let port = free_port();
    let strict = keyed_peer(port, verifying(&key, &r2.dyn_.jwk_set(), &r2)).await;
    call(&r2, ADMIN, "dyn.connect", json!({ "name": "v", "url": format!("ws://127.0.0.1:{port}") })).await;
    let refused = call(&r2, USER, "dyn.peer.v.forecast", json!({ "city": "oslo" })).await;
    assert!(refused[0]["message"].as_str().is_some_and(|m| m.contains("no token")), "{refused:?}");
    strict.abort();
    // The signing key is kept in the data directory, 0600, and denied to dendrites.
    let file = r.dyn_.options().data_dir.join("dyn.key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[derive(Clone)]
pub struct RelayActivation;

/// A peer that calls its host back: `rain` needs the host's peer `v`'s
/// forecast (a graft on `dyn`, NEST-16); `sneak` reaches for `dyn.grow`,
/// which it does not need.
#[plexus_macros::activation(parent = DynClient)]
impl RelayActivation {
    /// Rainy days in `city`, asked of the host's peer `v` through the host.
    #[plexus_macros::method(uses("dyn.peer.v.forecast"))]
    pub async fn rain(&self, city: String) -> Value {
        up("dyn.peer.v", "forecast", json!({ "city": city })).await
    }
    /// What the host's peer `t` says its token for this call holds.
    #[plexus_macros::method(uses("dyn.peer.t.claims"))]
    pub async fn ask(&self) -> Value {
        up_first("dyn.peer.t", "claims", json!({})).await
    }
    /// Past its needs.
    #[plexus_macros::method]
    pub async fn sneak(&self) -> Value {
        up("dyn", "grow", json!({ "name": "x", "source": "", "targets": [] })).await
    }
    /// KEEL-19 (N2): what the host's peer `t` says, asked after a moment —
    /// while consent may move under the call.
    #[plexus_macros::method(uses("dyn.peer.t.claims"))]
    pub async fn later(&self) -> Value {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        up_first("dyn.peer.t", "claims", json!({})).await
    }
    /// KEEL-19: this call's token and its claims (test only: a peer never
    /// hands its token out) — what relay exchanges with `dyn.exchange`.
    #[plexus_macros::method]
    pub async fn mine(&self) -> Value {
        own_token()
    }
}

/// The token the call being served was forwarded with, and its claims.
fn own_token() -> Value {
    use base64::Engine as _;
    let Ok(hop) = plexus_core::call::hop() else { return json!({ "no_hop": true }) };
    let token = hop.token.clone().unwrap_or_default();
    let claims: Value = token
        .split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    json!({ "token": token, "claims": claims })
}

/// The first item of a call back, or the refusal.
async fn up_first(path: &str, name: &str, params: Value) -> Value {
    use plexus_client::{MethodRef, StreamItem, Transport};
    let t = match plexus_core::plexus::remote_child::host() {
        Ok(t) => t,
        Err(e) => return json!({ "no_host": e.to_string() }),
    };
    let items: Vec<_> = t.call(MethodRef::named(path.to_string(), name.to_string()), params).collect().await;
    match items.into_iter().next() {
        Some(Ok(StreamItem::Data { content, .. })) => content,
        Some(Ok(StreamItem::Error { message, .. })) => json!({ "refused": message }),
        other => json!({ "other": format!("{other:?}") }),
    }
}

#[derive(Clone)]
pub struct TellActivation;

/// A peer that says what its token says.
#[plexus_macros::activation]
impl TellActivation {
    /// This call's token (test only: a peer never echoes it) and its claims.
    #[plexus_macros::method]
    pub async fn claims(&self) -> Value {
        own_token()
    }
}

/// DYNAUTH-6: a peer calling onward through its service gets the next peer
/// a token by exchange (RFC 8693) — the same subject, the presenter in the
/// actor chain, a scope never wider; `dyn.exchange` does the same as a
/// method, with a proof, and refuses without one. KEEL-19: the method only
/// for a presenter consented to reach the audience — here `relay`, whose
/// need `dyn.peer.t.claims` is consented; `t` asking for `relay` is refused.
async fn an_onward_call_is_an_exchange() {
    use plexus_core::plexus::peer_token::{prove, Expect, PeerKey, Verifier, EXCHANGE};
    let r = rig().await;
    let (tk, rk) = (PeerKey::generate(), PeerKey::generate());
    let (tp, rp) = (free_port(), free_port());
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    let relay = served_peer(rp, RelayActivation, verifying(&rk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "relay", "url": format!("ws://127.0.0.1:{rp}") })).await;
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.t.claims"] })).await;
    let host = r.dyn_.issuer().kid();
    // Direct: t's token is a mint, the host the only actor.
    let direct = call(&r, USER, "dyn.peer.t.claims", json!({})).await.remove(0);
    assert_eq!(direct["claims"]["act"], json!({ "sub": host }), "{direct:?}");
    // Onward, through relay: an exchange.
    let got = call(&r, USER, "dyn.peer.relay.ask", json!({})).await.remove(0);
    let c = &got["claims"];
    assert_eq!(c["sub"], USER, "the subject survives the hop: {got:?}");
    assert_eq!(c["aud"], tk.kid());
    assert_eq!(c["act"], json!({ "sub": host, "act": { "sub": rk.kid(), "act": { "sub": host } } }), "act names each hop, nearest first: {got:?}");
    assert_eq!(c["scope"], "tell.claims@*", "only what reaching t needs, held by relay's token: {got:?}");
    // KEEL-19: t's token, presented by t with its proof, for relay: t holds
    // no consented need that reaches relay — refused, saying so.
    let subject = direct["token"].as_str().unwrap().to_string();
    let subject_call = direct["claims"]["call"].as_str().unwrap().to_string();
    let proof = prove(&tk, &subject, EXCHANGE, &subject_call);
    let t_asks: Vec<Value> = items(r.host.route("dyn.exchange", json!({ "subject_token": subject, "proof": proof, "audience": "relay", "method": "relay.ask" }), None).await).await;
    assert!(t_asks[0]["message"].as_str().is_some_and(|m| m.contains("[not_consented]")), "{t_asks:?}");
    // The method: relay's token (relay's own, as `mine` hands it over),
    // presented by relay with its proof, exchanged for one addressed to t —
    // narrowed to what is asked, never wider.
    let mine = call(&r, USER, "dyn.peer.relay.mine", json!({})).await.remove(0);
    let subject = mine["token"].as_str().unwrap().to_string();
    let subject_call = mine["claims"]["call"].as_str().unwrap().to_string();
    let no_proof: Vec<Value> = items(r.host.route("dyn.exchange", json!({ "subject_token": subject, "proof": "", "audience": "t", "method": "tell.claims" }), None).await).await;
    assert_eq!(no_proof[0]["type"], "error", "{no_proof:?}");
    let proof = prove(&rk, &subject, EXCHANGE, &subject_call);
    let asked = json!({ "subject_token": subject, "proof": proof, "audience": "t", "method": "tell.claims", "scope": ["tell.claims@*", "auth.grant@*"] });
    let ex: Vec<Value> = items(r.host.route("dyn.exchange", asked.clone(), None).await).await;
    assert_eq!(ex[0]["type"], "exchanged", "{ex:?}");
    assert_eq!(ex[0]["scope"], json!(["tell.claims@*"]), "never wider than the subject's: {ex:?}");
    assert_eq!(ex[0]["issued_token_type"], "urn:ietf:params:oauth:token-type:jwt");
    let at_t = Verifier::new(tk.kid(), &r.dyn_.jwk_set()).unwrap();
    let claims = at_t.verify(ex[0]["access_token"].as_str().unwrap(), &Expect::default()).unwrap();
    assert_eq!(claims.sub, USER);
    assert_eq!(claims.actors(), [host.clone(), rk.kid().to_string(), host.clone()]);
    assert_eq!(claims.cnf.map(|c| c.jkt), Some(rk.thumbprint()), "bound to its presenter, relay");
    // The same proof again: refused (a proof is used once).
    let again: Vec<Value> = items(r.host.route("dyn.exchange", asked, None).await).await;
    assert_eq!(again[0]["type"], "error", "{again:?}");
    // For a peer that proved no key: refused.
    let port = free_port();
    let far = far(port, false).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    let proof = prove(&rk, &subject, EXCHANGE, &subject_call);
    let keyless: Vec<Value> = items(r.host.route("dyn.exchange", json!({ "subject_token": subject, "proof": proof, "audience": "w", "method": "weather.forecast" }), None).await).await;
    assert!(keyless[0]["message"].as_str().is_some_and(|m| m.contains("proved a key")), "{keyless:?}");
    stop(far).await;
    t.abort();
    relay.abort();
}

// ------------------------------------------------------------------ KEEL-19

/// A peer `t` (TellActivation, `tk`'s key, verifying `dyn`'s tokens) served
/// on one input proven as `proven`, trusting only `service` to act for
/// others: the connection a presenter opens to it itself. One `tell.call`
/// with `hop`; its first item.
async fn direct_to_t(tk: &plexus_core::plexus::peer_token::PeerKey, jwks: &plexus_core::plexus::peer_token::Jwks, by: &plexus_core::plexus::peer_token::PeerKey, service: &str, hop: Value) -> Value {
    use plexus_core::plexus::remote_child::{dial_proof, serve_child_proven, KeyedUpgrade};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let v = plexus_core::plexus::peer_token::Verifier::new(tk.kid(), jwks).unwrap();
    // KEEL-19: the connection proven as `by` by verifying `by`'s dial proof.
    let proven = KeyedUpgrade::new(["ws://t.test"]).verify(&dial_proof(by, "ws://t.test")).unwrap();
    let (mut to_t, t_in) = tokio::io::duplex(1 << 16);
    let (t_out, from_t) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve_child_proven(TellActivation, t_in, t_out, proven, vec![service.to_string()], Some(tk.clone()), Some(Arc::new(v))));
    let frame = json!({ "jsonrpc": "2.0", "id": 1, "method": "tell.call", "params": { "method": "tell.claims", "params": {}, "hop": hop } });
    to_t.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut lines = tokio::io::BufReader::new(from_t).lines();
    loop {
        let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await.expect("t answers").unwrap().unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        if v.get("method").and_then(Value::as_str) == Some("tell.call") {
            return v["params"]["result"].clone();
        }
    }
}

/// The rig for KEEL-19: `t` (verifying) and `relay` (whose need
/// `dyn.peer.t.claims` is consented only when `consent`), both keyed.
struct Pair {
    r: Rig,
    tk: plexus_core::plexus::peer_token::PeerKey,
    rk: plexus_core::plexus::peer_token::PeerKey,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn pair(consent: bool) -> Pair {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let (tk, rk) = (PeerKey::generate(), PeerKey::generate());
    let (tp, rp) = (free_port(), free_port());
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    let relay = served_peer(rp, RelayActivation, verifying(&rk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "relay", "url": format!("ws://127.0.0.1:{rp}") })).await;
    if consent {
        let c = call(&r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.t.claims"] })).await;
        assert_eq!(c[0]["type"], "consented", "{c:?}");
    }
    Pair { r, tk, rk, tasks: vec![t, relay] }
}

impl Pair {
    /// relay's token for a call the user made into it, and a fresh proof
    /// for exchanging it.
    async fn subject(&self) -> (String, String) {
        use plexus_core::plexus::peer_token::{prove, EXCHANGE};
        let mine = call(&self.r, USER, "dyn.peer.relay.mine", json!({})).await.remove(0);
        let token = mine["token"].as_str().unwrap_or_else(|| panic!("{mine:?}")).to_string();
        let proof = prove(&self.rk, &token, EXCHANGE, mine["claims"]["call"].as_str().unwrap());
        (token, proof)
    }

    async fn exchange(&self, token: &str, proof: &str) -> Value {
        let ask = json!({ "subject_token": token, "proof": proof, "audience": "t", "method": "tell.claims" });
        items(self.r.host.route("dyn.exchange", ask, None).await).await.remove(0)
    }

    fn end(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

/// KEEL-19 (1), the reviewer's attack at its first step: relay, handed the
/// user's token, asks `dyn.exchange` for one addressed to t — with a good
/// proof, but no consent to reach t. Refused, typed, audited.
async fn keel19_an_unconsented_peer_is_refused_an_exchange() {
    let p = pair(false).await;
    let (token, proof) = p.subject().await;
    let got = p.exchange(&token, &proof).await;
    assert_eq!(got["type"], "error", "the exchange must be refused: {got:?}");
    assert!(got["message"].as_str().is_some_and(|m| m.contains("[not_consented]") && m.contains("dyn.peer.t.claims")), "{got:?}");
    let log = String::from_utf8_lossy(&AUDIT_LOG.lock().unwrap()).to_string();
    assert!(log.contains("peer token exchange refused") && log.contains("not_consented"), "audited: {log}");
    for part in token.split('.').chain(proof.split('.')).filter(|x| x.len() > 8) {
        assert!(!log.contains(part), "a log line holds a token's or a proof's bytes");
    }
    // Nor is a token of a peer not mounted here exchanged.
    let stranger = plexus_core::plexus::peer_token::PeerKey::generate();
    let theirs = p.r.dyn_.issuer().mint(plexus_core::plexus::peer_token::MintRequest { sub: USER.into(), peer_key: Some(stranger.kid().into()), name: "x".into(), scope: vec!["dyn.{peer}@*".into()], call: "c-x".into(), method: "x.y".into(), presented: None }).unwrap().0;
    let proof = plexus_core::plexus::peer_token::prove(&stranger, &theirs, plexus_core::plexus::peer_token::EXCHANGE, "c-x");
    let got = p.exchange(&theirs, &proof).await;
    assert!(got["message"].as_str().is_some_and(|m| m.contains("[presenter]")), "{got:?}");
    p.end();
}

/// KEEL-19, the legitimate onward hop: relay, consented to reach t,
/// exchanges the user's token and calls t itself, with its proof, over a
/// connection proven as relay: t runs it for the user. The same hop with no
/// proof, or over a connection proven as another, is refused (2).
async fn keel19_a_consented_peer_reaches_another_with_its_proof() {
    use plexus_core::plexus::peer_token::{prove, PeerKey};
    let p = pair(true).await;
    let service = "key:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let jwks = p.r.dyn_.jwk_set();
    let hop = |token: &str, call: &str, proof: Option<String>| {
        let mut h = json!({ "principal": p.rk.kid(), "for": [USER], "limit": { "grant": "tell.claims", "held_on": ["*"] }, "call": call, "token": token });
        if let Some(pr) = proof {
            h["proof"] = json!(pr);
        }
        h
    };
    let exchanged = || async {
        let (token, proof) = p.subject().await;
        let ex = p.exchange(&token, &proof).await;
        assert_eq!(ex["type"], "exchanged", "{ex:?}");
        let t = ex["access_token"].as_str().unwrap().to_string();
        let call = plexus_core::plexus::peer_token::Verifier::new(p.tk.kid(), &jwks).unwrap().verify(&t, &Default::default()).unwrap().call;
        (t, call)
    };
    let (t, c) = exchanged().await;
    let got = direct_to_t(&p.tk, &jwks, &p.rk, service, hop(&t, &c, Some(prove(&p.rk, &t, "tell.claims", &c)))).await;
    assert_eq!(got["content"]["claims"]["sub"], USER, "t ran it for the user: {got:?}");
    assert_eq!(got["content"]["claims"]["scope"], "tell.claims@*", "{got:?}");
    // No proof: refused.
    let (t, c) = exchanged().await;
    let got = direct_to_t(&p.tk, &jwks, &p.rk, service, hop(&t, &c, None)).await;
    assert!(got["message"].as_str().is_some_and(|m| m.contains("no proof of possession")), "{got:?}");
    // relay's proof, carried over another's connection: refused.
    let other = PeerKey::generate();
    let (t, c) = exchanged().await;
    let mut h = hop(&t, &c, Some(prove(&p.rk, &t, "tell.claims", &c)));
    h["principal"] = json!(other.kid());
    let got = direct_to_t(&p.tk, &jwks, &other, service, h).await;
    assert!(got["message"].as_str().is_some_and(|m| m.contains("not as the presenter")), "{got:?}");
    p.end();
}

/// KEEL-19 (3): a subject token is exchanged once per audience and method —
/// a second ask, with a fresh proof, is refused.
async fn keel19_a_subject_is_exchanged_once() {
    use plexus_core::plexus::peer_token::{prove, EXCHANGE};
    let p = pair(true).await;
    let mine = call(&p.r, USER, "dyn.peer.relay.mine", json!({})).await.remove(0);
    let token = mine["token"].as_str().unwrap().to_string();
    let call_id = mine["claims"]["call"].as_str().unwrap().to_string();
    let first = p.exchange(&token, &prove(&p.rk, &token, EXCHANGE, &call_id)).await;
    assert_eq!(first["type"], "exchanged", "{first:?}");
    let second = p.exchange(&token, &prove(&p.rk, &token, EXCHANGE, &call_id)).await;
    assert!(second["message"].as_str().is_some_and(|m| m.contains("[again]") && m.contains("once")), "{second:?}");
    p.end();
}

/// KEEL-19 (4): a revoked presenter's exchange is refused at once — with a
/// subject token it was handed before, still live.
async fn keel19_a_revoked_presenter_is_refused_at_once() {
    let p = pair(true).await;
    let (before, proof_before) = p.subject().await;
    let (held, proof_held) = p.subject().await;
    assert_eq!(p.exchange(&before, &proof_before).await["type"], "exchanged");
    let revoked = call(&p.r, ADMIN, "dyn.revoke", json!({ "peer": "relay", "why": "compromised" })).await;
    assert_eq!(revoked[0]["type"], "revoked", "{revoked:?}");
    let got = p.exchange(&held, &proof_held).await;
    assert!(got["message"].as_str().is_some_and(|m| m.contains("[revoked]") && m.contains("compromised")), "{got:?}");
    p.end();
}

/// KEEL-19 (N2): a consent narrowed while a forwarded call is open narrows
/// the next call back made under it — the token minted before (held `*`)
/// no longer decides alone: the call back is held to what consent allows
/// now, `MENGER` — its ceiling, and so the token minted onward for `t`,
/// holds `MENGER` alone (this rig's gate resolves every target everywhere,
/// so the narrowed call is admitted, and narrowed).
async fn keel19_a_narrowed_consent_holds_an_open_call() {
    let p = pair(true).await;
    let r = Arc::clone(&p.r.host);
    let open = tokio::spawn({
        let r = Arc::clone(&r);
        async move { items(r.route("dyn.peer.relay.later", json!({}), Some(&who(USER))).await).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let c = call(&p.r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.t.claims@MENGER"] })).await;
    assert_eq!(c[0]["type"], "consented", "{c:?}");
    let got = open.await.unwrap();
    assert_eq!(got[0]["claims"]["scope"], "tell.claims@MENGER", "the call back went through on the token's `*`: {got:?}");
    // Consented everywhere again: the next call reaches t.
    call(&p.r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.t.claims"] })).await;
    let got = call(&p.r, USER, "dyn.peer.relay.ask", json!({})).await;
    assert_eq!(got[0]["claims"]["scope"], "tell.claims@*", "{got:?}");
    p.end();
}

/// KEEL-19 (c): a peer proving a key another peer here holds is refused —
/// typed (`key_in_use`) and audited — so a token addressed to a key, and an
/// exchange's presenter found by its key, name one peer.
async fn keel19_a_key_is_mounted_once() {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let k = PeerKey::generate();
    let (p1, p2) = (free_port(), free_port());
    let one = keyed_peer(p1, keyed(&k, &r)).await;
    let two = keyed_peer(p2, keyed(&k, &r)).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "a", "url": format!("ws://127.0.0.1:{p1}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "b", "url": format!("ws://127.0.0.1:{p2}") })).await;
    assert_eq!(got[0]["type"], "refused", "{got:?}");
    assert_eq!(got[0]["reason"], "identity_changed", "{got:?}");
    assert!(got[0]["message"].as_str().is_some_and(|m| m.starts_with("key_in_use:")), "{got:?}");
    let log = String::from_utf8_lossy(&AUDIT_LOG.lock().unwrap()).to_string();
    assert!(log.contains("its key is another peer's"), "audited");
    // Revoked, its key still is not another's way in.
    call(&r, ADMIN, "dyn.revoke", json!({ "peer": "a", "why": "compromised" })).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "b", "url": format!("ws://127.0.0.1:{p2}") })).await;
    assert!(got[0]["message"].as_str().is_some_and(|m| m.starts_with("key_in_use:")), "{got:?}");
    one.abort();
    two.abort();
}

/// KEEL-19 (NN2): connects proving one key, all at once — one mounts, the
/// others are refused `key_in_use`; never two.
async fn keel19_two_connects_racing_on_one_key() {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let k = PeerKey::generate();
    let ports: Vec<u16> = (0..6).map(|_| free_port()).collect();
    let mut tasks = Vec::new();
    for p in &ports {
        tasks.push(keyed_peer(*p, keyed(&k, &r)).await);
    }
    let asks = ports.iter().enumerate().map(|(i, p)| call(&r, ADMIN, "dyn.connect", json!({ "name": format!("k{i}"), "url": format!("ws://127.0.0.1:{p}") })));
    let got = futures::future::join_all(asks).await;
    let connected = got.iter().filter(|g| g[0]["type"] == "connected").count();
    assert_eq!(connected, 1, "exactly one mounts: {got:?}");
    assert!(got.iter().filter(|g| g[0]["type"] != "connected").all(|g| g[0]["message"].as_str().is_some_and(|m| m.starts_with("key_in_use:"))), "{got:?}");
    let holding = r.dyn_.list().into_iter().filter(|p| p.identity.as_ref().and_then(|i| i.key.as_deref()) == Some(k.kid())).count();
    assert_eq!(holding, 1);
    for t in tasks {
        t.abort();
    }
}

/// KEEL-19 (NN1): `dyn` dials with a key by default (`<data_dir>/dial.key`,
/// 0600, not the signing key), so a keyed peer's `_info` proof is made for
/// a principal its transport proved; and a keyed peer is never served on a
/// connection "proven" as `service:dyn`, a name no transport proves.
async fn keel19_dyn_dials_with_a_key_and_no_peer_trusts_a_name() {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let dial = r.dyn_.dial_principal().expect("a dial key by default");
    assert!(dial.starts_with("key:") && dial != r.dyn_.issuer().kid(), "its own key, not the signing key: {dial}");
    let file = r.dyn_.options().data_dir.join("dial.key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let k = PeerKey::generate();
    let port = free_port();
    let v = keyed_peer(port, keyed(&k, &r)).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "v", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(peer(&r, "v").identity.and_then(|i| i.key), Some(k.kid().to_string()));
    v.abort();
    // The old rig's pattern: refused before it serves a line.
    let (_to, v_in) = tokio::io::duplex(1 << 10);
    let (v_out, _from) = tokio::io::duplex(1 << 10);
    let named = plexus_core::plexus::remote_child::ServeChild { key: Some(k.clone()), peer: plexus_core::plexus::remote_child::ChildPeer::connection(DYN, [DYN.to_string()]), tokens: None };
    let served = tokio::time::timeout(Duration::from_secs(2), plexus_core::plexus::remote_child::serve_child_with(WeatherActivation, v_in, v_out, named)).await.expect("refused at once");
    assert_eq!(served.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

/// KEEL-19 (P4, KEEL-22's first row): a revoke while a call is on its way —
/// past `forward`'s first check, waiting for the peer to be dialed again —
/// mints no token and opens no call.
async fn keel19_a_revoke_while_dialing_mints_nothing() {
    use plexus_core::plexus::peer_token::{AuditKind, PeerKey};
    let records = Arc::new(Records::default());
    let sink = records.clone();
    let r = rig_opts(None, move |o| o.audit = Some(plexus_dyn::Audit(sink))).await;
    let k = PeerKey::generate();
    let port = free_port();
    let fast = keyed_peer(port, verifying(&k, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "v", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(call(&r, USER, "dyn.peer.v.forecast", json!({ "city": "oslo" })).await.len(), 7);
    // It goes, and comes back slowly: the next call waits in the dial.
    fast.abort();
    let _ = fast.await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while peer(&r, "v").up {
        assert!(Instant::now() < deadline, "never seen down");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let slow = served_peer_after(port, WeatherActivation, verifying(&k, &r.dyn_.jwk_set(), &r), Duration::from_millis(1500)).await;
    records.0.lock().unwrap().clear();
    let host = Arc::clone(&r.host);
    let on_its_way = tokio::spawn(async move { items(host.route("dyn.peer.v.forecast", json!({ "city": "oslo" }), Some(&who(USER))).await).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let revoked = call(&r, ADMIN, "dyn.revoke", json!({ "peer": "v", "why": "compromised" })).await;
    assert_eq!(revoked[0]["type"], "revoked", "{revoked:?}");
    let got = on_its_way.await.unwrap();
    assert!(got.len() < 7 && got[0]["message"].as_str().is_some_and(|m| m.contains("revoked")), "forwarded after the revoke: {got:?}");
    let minted: Vec<_> = records.0.lock().unwrap().iter().filter(|m| m.kind == AuditKind::Mint && m.aud == k.kid()).cloned().collect();
    assert!(minted.is_empty(), "a token minted for a revoked peer: {minted:?}");
    slow.abort();
}

/// KEEL-19 (P5, KEEL-25): a data directory open to others is refused at
/// start, naming it — and nothing is read from or kept in it; one the user
/// owns, 0700, is taken; the default is the user's own, never `/tmp`'s.
async fn keel19_a_data_directory_open_to_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let default = DynOptions::default().data_dir;
    assert!(default.ends_with("plexus-dyn") && !default.starts_with(std::env::temp_dir()), "{default:?}");
    let tmp = tempfile::tempdir().unwrap();
    let open = tmp.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let d = DynActivation::new(DynOptions { data_dir: open.clone(), ..DynOptions::default() });
    let service = DynamicHub::new("host");
    let why = d.start(&service).await.unwrap_err();
    assert!(why.contains(&open.display().to_string()) && why.contains("open to others"), "{why}");
    assert!(!open.join("dyn.key").exists() && !open.join("dial.key").exists(), "a key kept in a refused directory");
    assert_eq!(d.dial_principal(), None);
    // A private one is made 0700 and taken.
    let private = tmp.path().join("private");
    let d = DynActivation::new(DynOptions { data_dir: private.clone(), ..DynOptions::default() });
    assert_eq!(std::fs::metadata(&private).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(d.dial_principal().is_some());
    // A dial key planted as a link (to a key the user owns, 0600): refused.
    let other = tmp.path().join("planted");
    std::fs::create_dir(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real = tmp.path().join("someone.key");
    plexus_core::plexus::peer_token::PeerKey::load_or_create(&real).unwrap();
    std::os::unix::fs::symlink(&real, other.join("dial.key")).unwrap();
    let d = DynActivation::new(DynOptions { data_dir: other, ..DynOptions::default() });
    assert_eq!(d.dial_principal(), None, "dialed as a planted key");
}

/// KEEL-19 (NN2's side effect): a connect refused for a key another holds
/// drops nobody's consent — not that of the entry it named.
async fn keel19_a_refused_connect_keeps_the_named_consent() {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let (k1, k2) = (PeerKey::generate(), PeerKey::generate());
    let (px, py, pz) = (free_port(), free_port(), free_port());
    let x = keyed_peer(px, keyed(&k1, &r)).await;
    let y = keyed_peer(py, keyed(&k2, &r)).await;
    let z = keyed_peer(pz, keyed(&k2, &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "x", "url": format!("ws://127.0.0.1:{px}") })).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "y", "url": format!("ws://127.0.0.1:{py}") })).await;
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "x", "callers": ["viewer"] })).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "x", "url": format!("ws://127.0.0.1:{pz}"), "replace": true })).await;
    assert!(got[0]["message"].as_str().is_some_and(|m| m.starts_with("key_in_use:")), "{got:?}");
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    let xs = listed.iter().find(|c| c["peer"] == "x").unwrap();
    assert_eq!((xs["callers"].clone(), xs["key"].clone()), (json!(["viewer"]), json!(k1.kid())), "x's consent went with the refused connect: {listed:?}");
    assert_eq!(call(&r, VIEWER, "dyn.peer.x.forecast", json!({ "city": "oslo" })).await.len(), 7);
    for t in [x, y, z] {
        t.abort();
    }
}

// ------------------------------------------------------------------ DYNAUTH-7

/// Every `plexus::audit` tracing line this test process wrote.
static AUDIT_LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct AuditWriter;
impl std::io::Write for AuditWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        AUDIT_LOG.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Records(Mutex<Vec<plexus_core::plexus::peer_token::AuditRecord>>);
impl plexus_core::plexus::peer_token::TokenAudit for Records {
    fn record(&self, r: &plexus_core::plexus::peer_token::AuditRecord) {
        self.0.lock().unwrap().push(r.clone());
    }
}

/// A revoked peer's next call is refused at the host at once; a token it
/// was already given verifies until its `exp` (≤ 60 s) and not after.
/// Connecting it again with `replace` ends the revocation.
async fn a_revoked_peer_is_refused_and_its_tokens_expire() {
    use plexus_core::plexus::peer_token::{Expect, PeerKey, TokenError, Verifier, SKEW};
    let r = rig().await;
    let tk = PeerKey::generate();
    let tp = free_port();
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    let url = format!("ws://127.0.0.1:{tp}");
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": url })).await;
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "t", "callers": ["viewer"] })).await;
    let before = call(&r, VIEWER, "dyn.peer.t.claims", json!({})).await.remove(0);
    let issued = before["token"].as_str().unwrap().to_string();
    let revoked = call(&r, ADMIN, "dyn.revoke", json!({ "peer": "t", "why": "its key leaked" })).await;
    assert_eq!(revoked[0], json!({ "type": "revoked", "peer": "t", "why": "its key leaked" }), "{revoked:?}");
    // At once, at the host: refused (its consent gone too, so the viewer
    // is refused at the door; the admin is refused by the revocation).
    let next = call(&r, ADMIN, "dyn.peer.t.claims", json!({})).await;
    assert!(next[0]["message"].as_str().is_some_and(|m| m.contains("revoked")), "{next:?}");
    let viewer = call(&r, VIEWER, "dyn.peer.t.claims", json!({})).await;
    assert!(viewer[0]["route_error"].is_string(), "{viewer:?}");
    assert_eq!(peer(&r, "t").revoked.as_deref(), Some("its key leaked"));
    // The token already issued: good until its exp, never past it.
    let fresh = Verifier::new(tk.kid(), &r.dyn_.jwk_set()).unwrap();
    let c = fresh.verify(&issued, &Expect::default()).unwrap();
    assert!(c.exp - c.iat <= 60, "{c:?}");
    let later = Verifier::new(tk.kid(), &r.dyn_.jwk_set()).unwrap();
    assert_eq!(later.verify_at(&issued, &Expect::default(), c.exp + SKEW.as_secs() + 1), Err(TokenError::Expired), "within one token lifetime (and the skew) it is gone");
    // No exchange for it either.
    let again = call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": url, "replace": true })).await;
    assert_eq!(again[0]["type"], "connected", "{again:?}");
    assert_eq!(peer(&r, "t").revoked, None, "a new registration ends the revocation");
    assert_eq!(call(&r, ADMIN, "dyn.peer.t.claims", json!({})).await[0]["claims"]["sub"], ADMIN);
    t.abort();
}

/// One audit record per hop — the mint for relay, the exchange for t,
/// joined by the call — and no token's bytes in any record or log line.
async fn every_hop_is_audited_without_a_secret() {
    use plexus_core::plexus::peer_token::{AuditKind, PeerKey};
    let records = Arc::new(Records::default());
    let sink = records.clone();
    let r = rig_opts(None, move |o| o.audit = Some(plexus_dyn::Audit(sink))).await;
    let (tk, rk) = (PeerKey::generate(), PeerKey::generate());
    let (tp, rp) = (free_port(), free_port());
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    let relay = served_peer(rp, RelayActivation, verifying(&rk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "relay", "url": format!("ws://127.0.0.1:{rp}") })).await;
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.t.claims"] })).await;
    records.0.lock().unwrap().clear();
    let got = call(&r, USER, "dyn.peer.relay.ask", json!({})).await.remove(0);
    let token = got["token"].as_str().unwrap().to_string();
    let seen = records.0.lock().unwrap().clone();
    assert_eq!(seen.iter().map(|r| r.kind).collect::<Vec<_>>(), [AuditKind::Mint, AuditKind::Exchange], "{seen:?}");
    let (mint, exchange) = (&seen[0], &seen[1]);
    assert_eq!((mint.sub.as_str(), mint.aud.as_str()), (USER, rk.kid()));
    assert_eq!((exchange.sub.as_str(), exchange.aud.as_str()), (USER, tk.kid()));
    assert_eq!(exchange.presented_call.as_deref(), Some(mint.call.as_str()), "joined by the call");
    assert_eq!(exchange.act, [r.dyn_.issuer().kid(), rk.kid().to_string(), r.dyn_.issuer().kid()]);
    assert!(!mint.method.is_empty() && !exchange.method.is_empty());
    // No secret: neither the token's parts nor its signature, anywhere.
    let text = serde_json::to_string(&seen).unwrap();
    let log = String::from_utf8_lossy(&AUDIT_LOG.lock().unwrap()).to_string();
    assert!(log.contains("peer token") && log.contains(&exchange.jti), "the tracing event is written: {log}");
    for part in token.split('.') {
        assert!(!text.contains(part), "a record holds the token's bytes");
        assert!(!log.contains(part), "a log line holds the token's bytes");
    }
    t.abort();
    relay.abort();
}

/// A rotation: the new key signs from now, the old one stays in the JWKS
/// for one token lifetime; the key file is replaced, still 0600.
async fn the_signing_key_rotates() {
    use plexus_core::plexus::peer_token::{Expect, PeerKey, TokenError, Verifier};
    let r = rig().await;
    let tk = PeerKey::generate();
    let tp = free_port();
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    let old_jwks = r.dyn_.jwk_set();
    let old = r.dyn_.issuer().kid();
    let rotated = call(&r, ADMIN, "dyn.rotate_key", json!({})).await;
    assert_eq!(rotated[0]["type"], "rotated", "{rotated:?}");
    assert_eq!(rotated[0]["previous"], old);
    let new = rotated[0]["kid"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    let kids: Vec<String> = r.dyn_.jwk_set().keys.iter().filter_map(|k| k.kid.clone()).collect();
    assert_eq!(kids, [new.clone(), old.clone()], "the old key stays for one lifetime");
    // t still trusts only the old JWKS: it refuses the new key's tokens
    // until it fetches `dyn.jwks` again.
    let refused = call(&r, ADMIN, "dyn.peer.t.claims", json!({})).await;
    assert!(refused[0]["message"].as_str().is_some_and(|m| m.contains("not trusted")), "{refused:?}");
    let v = Verifier::new(tk.kid(), &old_jwks).unwrap();
    let issuer = r.dyn_.issuer();
    let (tok, _) = issuer.mint(plexus_core::plexus::peer_token::MintRequest { sub: USER.into(), peer_key: Some(tk.kid().into()), name: "t".into(), scope: vec![], call: "c".into(), method: "m".into(), presented: None }).unwrap();
    assert!(matches!(v.verify(&tok, &Expect::default()), Err(TokenError::UnknownKey(_))));
    v.trust(&r.dyn_.jwk_set()).unwrap();
    assert_eq!(v.verify(&tok, &Expect::default()).unwrap().iss, new);
    // The file holds the new key.
    let file = r.dyn_.options().data_dir.join("dyn.key");
    assert_eq!(PeerKey::load_or_create(&file).unwrap().kid(), new);
    t.abort();
}

/// Call the host back from inside a call; the items, or the refusal.
async fn up(path: &str, name: &str, params: Value) -> Value {
    use plexus_client::{MethodRef, StreamItem, Transport};
    let t = match plexus_core::plexus::remote_child::host() {
        Ok(t) => t,
        Err(e) => return json!({ "no_host": e.to_string() }),
    };
    let mut out = Vec::new();
    let items: Vec<_> = t.call(MethodRef::named(path.to_string(), name.to_string()), params).collect().await;
    for i in items {
        match i {
            Ok(StreamItem::Data { content, .. }) => out.push(content),
            Ok(StreamItem::Error { message, .. }) => return json!({ "refused": message }),
            Ok(_) => {}
            Err(e) => return json!({ "refused": e.to_string() }),
        }
    }
    json!({ "items": out.len() })
}

/// A keyed peer calls back with a proof of possession of its call's
/// token: a consented need goes through; an unconsented one, and one past
/// its needs, are refused.
async fn a_keyed_peer_calls_back_with_its_proof() {
    use plexus_core::plexus::peer_token::PeerKey;
    let r = rig().await;
    let (vk, rk) = (PeerKey::generate(), PeerKey::generate());
    let (vp, rp) = (free_port(), free_port());
    let v = keyed_peer(vp, verifying(&vk, &r.dyn_.jwk_set(), &r)).await;
    let relay = served_peer(rp, RelayActivation, verifying(&rk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "v", "url": format!("ws://127.0.0.1:{vp}") })).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "relay", "url": format!("ws://127.0.0.1:{rp}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    let mine = listed.iter().find(|c| c["peer"] == "relay").unwrap();
    assert_eq!(mine["declared"], json!(["dyn.peer.t.claims", "dyn.peer.v.forecast"]), "{listed:?}");
    assert_eq!(mine["pending"], mine["declared"], "{listed:?}");
    let before = call(&r, USER, "dyn.peer.relay.rain", json!({ "city": "oslo" })).await;
    assert!(before[0]["refused"].as_str().is_some_and(|m| m.contains("consented")), "{before:?}");
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "relay", "needs": ["dyn.peer.v.forecast"] })).await;
    let after = call(&r, USER, "dyn.peer.relay.rain", json!({ "city": "oslo" })).await;
    assert_eq!(after[0], json!({ "items": 7 }), "through the host, with its proof, to v (which took its own token): {after:?}");
    let sneak = call(&r, ADMIN, "dyn.peer.relay.sneak", json!({})).await;
    assert!(sneak[0]["refused"].as_str().is_some_and(|m| m.contains("dyn.grow")), "past its needs, even under an admin's call: {sneak:?}");
    v.abort();
    relay.abort();
}

/// A WebSocket peer that answers its mount, then never reads again.
async fn silent_peer(port: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let schema = json!({ "namespace": "mute", "version": "0.1.0", "description": "silent", "hash": "m1", "self_hash": "m1", "methods": [{ "name": "x", "description": "", "hash": "x", "streaming": false }] });
        let mut answered = 0;
        while answered < 2 {
            let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) = ws.next().await else { continue };
            let m: Value = serde_json::from_str(&t).unwrap();
            let id = m["id"].clone();
            let (ct, content) = if m["method"] == "_info" { ("_info", json!({ "backend": "mute" })) } else { ("mute.schema", schema.clone()) };
            for f in [
                json!({ "jsonrpc": "2.0", "id": id, "result": 1 }),
                json!({ "jsonrpc": "2.0", "method": "x", "params": { "subscription": 1, "result": { "type": "data", "metadata": { "provenance": ["mute"], "plexus_hash": "m1", "timestamp": 0 }, "content_type": ct, "content": content } } }),
                json!({ "jsonrpc": "2.0", "method": "x", "params": { "subscription": 1, "result": { "type": "done", "metadata": { "provenance": ["mute"], "plexus_hash": "m1", "timestamp": 0 } } } }),
            ] {
                ws.send(tokio_tungstenite::tungstenite::Message::text(f.to_string())).await.unwrap();
            }
            answered += 1;
        }
        // Silent: holds the socket, reads nothing, answers no ping.
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(ws);
    });
}

async fn a_silent_peer_is_marked_down() {
    let port = free_port();
    silent_peer(port).await;
    let r = rig().await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "mute", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let t0 = Instant::now();
    while peer(&r, "mute").up {
        assert!(t0.elapsed() < Duration::from_secs(5), "a silent peer is never marked down");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let down = peer(&r, "mute");
    println!("measure: the silent peer marked down after {:?} (ping every 300 ms): {:?}", t0.elapsed(), down.why);
    assert!(t0.elapsed() >= Duration::from_millis(500), "not before two pings' silence: {:?}", t0.elapsed());
    assert!(down.why.as_deref().is_some_and(|w| w.contains("answered nothing")), "{down:?}");
}

/// A live peer answers the pings: it stays up through many of them.
async fn a_live_peer_stays_up_through_its_pings() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let w = peer(&r, "w");
    assert!(w.up && w.restarts == 0, "{w:?}");
    stop(far).await;
}

async fn the_peers_file_is_connected_at_start() {
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("peers.toml");
    std::fs::write(&file, format!("w = \"ws://127.0.0.1:{port}\"\n")).unwrap();
    // Nothing listens yet: listed down, not dropped.
    let r = rig_with(Some(file)).await;
    let down = peer(&r, "w");
    assert!(!down.up && down.why.is_some(), "{down:?}");
    let far = far(port, false).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !peer(&r, "w").up {
        assert!(Instant::now() < deadline, "the listed peer never came up: {:?}", peer(&r, "w"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "lima" })).await.len(), 7);
    let parsed = plexus_dyn::read_peers_file(&{
        let f = dir.path().join("two.toml");
        std::fs::write(&f, "a = \"ws://h:1\"\n[d]\ndendrite = \"ds/d\"\nvia = [\"a.weather\"]\n").unwrap();
        f
    })
    .unwrap();
    assert_eq!(parsed[0], ("a".to_string(), plexus_dyn::PeerKind::Ws { url: "ws://h:1".into() }));
    assert_eq!(parsed[1].1, plexus_dyn::PeerKind::Dendrite { dir: dir.path().join("ds/d").display().to_string(), via: vec!["a.weather".into()] });
    stop(far).await;
}

async fn a_peer_grows_the_top_level() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig_opts(None, |o| o.top_level = true).await;
    let top = |r: &Rig| -> Vec<String> { r.host.root().names() };
    assert_eq!(top(&r), ["config", "dyn"], "NEST-21: the rig serves `config` too");
    let url = format!("ws://127.0.0.1:{port}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(top(&r), ["config", "dyn", "w"]);
    // At the top level: `w.weather.forecast`, on its own grant.
    let days = call(&r, TOP, "w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert_eq!(days.len(), 7, "{days:?}");
    let refused = call(&r, USER, "w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|e| e.contains("w.weather.forecast")), "{refused:?}");
    // The slot form beside it, unchanged.
    let days = call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert_eq!(days.len(), 7, "{days:?}");
    // The host's schema lists it.
    let schema = call(&r, ADMIN, "host.schema", json!({})).await;
    let kids: Vec<&str> = schema[0]["children"].as_array().unwrap().iter().map(|c| c["namespace"].as_str().unwrap()).collect();
    assert_eq!(kids, ["config", "dyn", "w"], "{schema:?}");
    // A name the service serves already is refused.
    let taken = call(&r, ADMIN, "dyn.connect", json!({ "name": "dyn", "url": url })).await;
    assert!(taken[0]["message"].as_str().is_some_and(|m| m.contains("top level")), "{taken:?}");
    assert_eq!(call(&r, VIEWER, "dyn.names", json!({})).await, [json!("w")]);
    // Disconnected: gone from the top level.
    call(&r, ADMIN, "dyn.disconnect", json!({ "name": "w" })).await;
    assert_eq!(top(&r), ["config", "dyn"]);
    let gone = call(&r, ADMIN, "w.weather.forecast", json!({ "city": "lisbon" })).await;
    assert!(gone[0]["route_error"].as_str().is_some_and(|e| e.contains("w")), "{gone:?}");
    // The far side restarts: the top-level entry is the fresh mount.
    call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    stop(far).await;
    let far = self::far(port, true).await;
    let days = until_data(&r, TOP, "w.weather.forecast", json!({ "city": "lisbon" }), Duration::from_secs(15)).await;
    assert_eq!(days.len(), 7, "{days:?}");
    stop(far).await;
}

/// NEST-14: one client, all the way down — `DynClient::peer(name)` an untyped
/// client at `dyn.peer.<name>`, made typed below it.
async fn dyn_client_reaches_a_peer_untyped_and_typed() {
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let client = DynClient::new(HubTransport::as_(r.host.clone(), who(USER)));
    // Untyped: by name.
    let peer = client.peer("w");
    assert_eq!(peer.path(), "dyn.peer.w");
    let days: Vec<_> = peer.child("weather").call("forecast", json!({ "city": "lisbon" })).collect().await;
    assert_eq!(days.len(), 7, "{days:?}");
    assert!(days.iter().all(|d| d.is_ok()), "{days:?}");
    // Typed: the far activation's own client, checked against the peer's schema.
    let weather: WeatherClient<_> = client.peer("w").into_child("weather").typed().await.expect("the peer serves weather");
    let typed: Vec<_> = weather.forecast("lisbon".into()).collect().await;
    assert_eq!(typed.len(), 7, "{typed:?}");
    assert_eq!(typed[0].as_ref().unwrap()["day"], 0);
    // Not what the peer serves: refused by shape, nothing else called.
    match client.peer("w").into_child("weather").typed::<ExtraClient<_>>().await {
        Err(plexus_client::ClientError::ShapeMismatch { methods, .. }) => assert_eq!(methods, vec!["new_thing".to_string()]),
        other => panic!("{other:?}"),
    }
    // A name that is not a route segment sends nothing.
    let bad: Vec<_> = client.peer("No Such").call("x", json!({})).collect().await;
    assert!(matches!(bad.as_slice(), [Err(plexus_client::ClientError::InvalidName { .. })]), "{bad:?}");
    stop(far).await;
}

/// NEST-16: `expecting` — an interface hash the peer must serve: at
/// connect, and again at every remount.
async fn connect_expecting_refuses_another_interface() {
    use plexus_core::plexus::peer::Interface;
    use plexus_core::plexus::Activation;
    let weather = Interface::named("weather", &WeatherActivation.plugin_schema()).hash;
    let extra = Interface::named("extra", &ExtraActivation.plugin_schema()).hash;
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    let url = format!("ws://127.0.0.1:{port}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url, "expecting": weather })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let refused = call(&r, ADMIN, "dyn.connect", json!({ "name": "x", "url": url, "expecting": extra })).await;
    assert_eq!(refused[0]["type"], "error", "{refused:?}");
    let why = refused[0]["message"].as_str().unwrap();
    assert!(why.contains("does not serve the interface") && why.contains(&extra) && why.contains(&weather), "{why}");
    assert_eq!(call(&r, VIEWER, "dyn.names", json!({})).await, [json!("w")], "nothing kept of the refused one");
    stop(far).await;
    // At a remount: `e` expects `extra`; the far side comes back without it.
    let port = free_port();
    let far = self::far(port, true).await;
    let url = format!("ws://127.0.0.1:{port}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "e", "url": url, "expecting": extra })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    stop(far).await;
    let far = self::far(port, false).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        // A call notices the schema moved; the next look tries the remount.
        let _ = call(&r, USER, "dyn.peer.e.weather.forecast", json!({ "city": "lisbon" })).await;
        let p = peer(&r, "e");
        if p.why.as_deref().is_some_and(|w| w.contains("does not serve the interface")) {
            assert!(!p.up, "{p:?}");
            break;
        }
        assert!(Instant::now() < deadline, "the remount was not refused: {p:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    stop(far).await;
}

/// NEST-16: a dendrite says what it calls of this service (read from its
/// code, or declared); `grow` refuses one whose needs this service does not
/// serve, naming them.
async fn a_dendrite_whose_needs_are_not_served_is_refused() {
    let r = rig().await;
    let source = "export const needs = [\"shop.items\"];\n/** Hello. */\nexport async function hello() { return { hi: true }; }\n";
    let got = call(&r, ADMIN, "dyn.grow", json!({ "name": "stocker", "source": source, "targets": [] })).await;
    assert_eq!(got[0]["type"], "error", "{got:?}");
    let why = got[0]["message"].as_str().unwrap();
    assert!(why.contains("shop.items") && why.contains("stocker"), "{why}");
    assert!(r.dyn_.list().is_empty());
}

// ------------------------------------------------------------------ DYNAUTH-8

async fn ws_beyond_loopback_is_refused() {
    use plexus_dyn::{check_url, Refusal};
    for ok in ["ws://127.0.0.1:1", "ws://127.9.9.9/x", "ws://localhost:80", "ws://LOCALHOST.", "ws://[::1]:4", "ws://u:p@127.0.0.1:1", "wss://example.com", "wss://10.0.0.1:443/ws"] {
        assert_eq!(check_url(ok, false), Ok(()), "{ok}");
    }
    for bad in ["ws://example.com", "ws://10.0.0.1:1", "ws://[::2]:1", "ws://127.0.0.1.example.com", "ws://localhost.example.com:1", "ws://u@example.com", "http://127.0.0.1", "ws://"] {
        assert_eq!(check_url(bad, false).map_err(|e| e.0), Err(Refusal::InsecureTransport), "{bad}");
    }
    assert_eq!(check_url("ws://example.com", true), Ok(()), "the override");
    let port = free_port();
    let far = far(port, false).await;
    let r = rig().await;
    let refused = call(&r, ADMIN, "dyn.connect", json!({ "name": "x", "url": "ws://example.com" })).await;
    assert_eq!((refused[0]["type"].as_str(), refused[0]["reason"].as_str()), (Some("refused"), Some("insecure_transport")), "{refused:?}");
    assert!(r.dyn_.list().is_empty(), "nothing kept");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": format!("ws://localhost:{port}") })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    let listed = call(&r, VIEWER, "dyn.peers", json!({})).await;
    assert_eq!(listed[0]["identity"], json!({ "backend": "far" }), "pinned at connect: {listed:?}");
    assert!(listed[0].get("insecure").is_none(), "loopback is not insecure: {listed:?}");
    stop(far).await;
}

async fn the_insecure_override_is_said() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("peers.toml");
    std::fs::write(&file, "far = \"ws://example.invalid:1\"\n").unwrap();
    // Without the override: listed down, saying why, never dialed.
    let r = rig_with(Some(file.clone())).await;
    let p = peer(&r, "far");
    assert!(!p.up && p.why.as_deref().is_some_and(|w| w.contains("plain ws://")), "{p:?}");
    assert!(p.insecure, "{p:?}");
    // With it: dialed (and failing here: no such host), and said.
    let r = rig_opts(Some(file), |o| o.insecure_ws = true).await;
    let p = peer(&r, "far");
    assert!(!p.up && p.why.as_deref().is_some_and(|w| !w.contains("plain ws://")), "{p:?}");
    let listed = call(&r, VIEWER, "dyn.peers", json!({})).await;
    assert_eq!(listed[0]["insecure"], true, "{listed:?}");
}

/// A test CA (rcgen), its PEM in `dir`, and leaves for 127.0.0.1.
struct Pki {
    dir: tempfile::TempDir,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "DYNAUTH-8 test CA");
        let ca = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
        Self { dir, issuer: rcgen::Issuer::new(params, key) }
    }

    fn roots(&self) -> PathBuf {
        self.dir.path().join("ca.pem")
    }

    /// A fresh leaf (a fresh key), written as `<name>.crt` / `<name>.key`.
    fn leaf(&self, name: &str) -> plexus_transport::TlsConfig {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap().signed_by(&key, &self.issuer).unwrap();
        let (c, k) = (self.dir.path().join(format!("{name}.crt")), self.dir.path().join(format!("{name}.key")));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        plexus_transport::TlsConfig::new(c, k)
    }
}

/// The far service over TLS on `port`.
async fn far_tls(port: u16, tls: plexus_transport::TlsConfig) -> plexus_transport::ServerHandle {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(DynamicHub::new("far").register(WeatherActivation))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let config = plexus_transport::WebSocketConfig::new(port).with_tls(tls.clone());
        match plexus_transport::websocket::serve_websocket_with(module.clone(), config, None, Default::default()).await {
            Ok((h, _)) => return h,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("port {port}: {e}"),
        }
    }
}

async fn a_wss_peer_is_validated_and_its_key_pinned() {
    let pki = Pki::new();
    let port = free_port();
    let url = format!("wss://127.0.0.1:{port}");
    let first = far_tls(port, pki.leaf("one")).await;
    // Not trusting the CA: the certificate does not validate.
    let r = rig().await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(got[0]["type"], "error", "an unknown issuer is refused: {got:?}");
    assert!(got[0]["message"].as_str().is_some_and(|m| m.to_lowercase().contains("certificate")), "{got:?}");
    // Trusting it: mounted, its key pinned.
    let r = rig_opts(None, |o| o.child.tls_roots = Some(pki.roots())).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await.len(), 7);
    let pinned = peer(&r, "w").identity.expect("pinned");
    assert!(pinned.tls_key.as_ref().is_some_and(|k| k.len() == 64), "{pinned:?}");
    // The far side restarts under another key: the redial is refused, and
    // so is every remount, until it is connected again with `replace`.
    let _ = first.stop();
    first.stopped().await;
    let second = far_tls(port, pki.leaf("two")).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await;
        let p = peer(&r, "w");
        if p.why.as_deref().is_some_and(|w| w.contains("identity")) {
            assert!(got.len() < 7 && !p.up, "{got:?} {p:?}");
            break;
        }
        assert!(Instant::now() < deadline, "a new key was never refused: {got:?} {p:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await; // a look or two: the remount refused too
    let p = peer(&r, "w");
    assert!(!p.up && p.identity.as_ref() == Some(&pinned) && p.why.as_deref().is_some_and(|w| w.contains("replace")), "{p:?}");
    let again = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url, "replace": true })).await;
    assert_eq!(again[0]["type"], "connected", "{again:?}");
    let p = peer(&r, "w");
    assert!(p.up && p.identity.as_ref().is_some_and(|i| i.tls_key != pinned.tls_key), "re-pinned: {p:?}");
    assert_eq!(call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await.len(), 7);
    let _ = second.stop();
}

// ------------------------------------------------------------------ NEST-21

/// This machine's address beyond loopback, if it has one (the one a route
/// out would leave from; nothing is sent).
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("10.255.255.255:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// The far service on every address, `port`.
async fn far_anywhere(port: u16) -> jsonrpsee::server::ServerHandle {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(DynamicHub::new("far").register(WeatherActivation))).unwrap();
    let server = jsonrpsee::server::Server::builder().build(format!("0.0.0.0:{port}")).await.unwrap();
    server.start(module)
}

fn audit_log() -> String {
    String::from_utf8_lossy(&AUDIT_LOG.lock().unwrap()).to_string()
}

/// `transport.insecure_ws` flipped through `config` takes effect at the
/// next connect: refused, then admitted; it shows in `config.list`, is
/// refused for a viewer, reverts when unconfirmed, and is in the audit log.
async fn a_setting_flipped_through_config_takes_effect_live() {
    let port = free_port();
    let far = far_anywhere(port).await;
    let r = rig().await;
    // An address beyond loopback: this machine's own, else one that is not
    // there (then admitted means dialed, not refused).
    let (url, reachable) = match lan_ip() {
        Some(ip) => (format!("ws://{ip}:{port}"), true),
        None => ("ws://example.invalid:1".to_string(), false),
    };
    let refused = call(&r, ADMIN, "dyn.connect", json!({ "name": "lan", "url": url })).await;
    assert_eq!(refused[0]["reason"], "insecure_transport", "{refused:?}");
    // A viewer may not, and an admin only as a confirmed commit.
    let got = call(&r, VIEWER, "config.transport.insecure_ws.set", json!({ "value": true, "confirm_within": "5s" })).await;
    assert!(got[0]["route_error"].as_str().is_some_and(|e| e.contains("config.{key}.{key}")), "{got:?}");
    let got = call(&r, ADMIN, "config.transport.insecure_ws.set", json!({ "value": "true" })).await;
    assert_eq!(got[0]["reason"], "confirm_required", "{got:?}");
    let got = call(&r, ADMIN, "config.transport.insecure_ws.set", json!({ "value": "true", "confirm_within": "1500ms" })).await;
    assert_eq!((got[0]["type"].as_str(), got[0]["setting"]["value"].as_bool()), (Some("set"), Some(true)), "{got:?}");
    let listed = call(&r, ADMIN, "config.list", json!({})).await;
    let k = listed.iter().find(|k| k["key"] == "transport.insecure_ws").expect("listed");
    assert_eq!((k["value"].as_bool(), k["source"].as_str()), (Some(true), Some("runtime")), "{k}");
    assert!(k["confirm_until"].is_number(), "{k}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "lan", "url": url })).await;
    println!("measure: transport.insecure_ws flipped live; {url} reachable here: {reachable}");
    if reachable {
        assert_eq!(got[0]["type"], "connected", "admitted: {got:?}");
        assert!(peer(&r, "lan").insecure, "said");
        assert_eq!(call(&r, USER, "dyn.peer.lan.weather.forecast", json!({ "city": "oslo" })).await.len(), 7);
    } else {
        assert_ne!(got[0]["reason"], "insecure_transport", "dialed, not refused: {got:?}");
    }
    // Not confirmed: reverted, and refused again.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let k = call(&r, ADMIN, "config.transport.insecure_ws.get", json!({})).await;
    assert_eq!((k[0]["value"].as_bool(), k[0]["source"].as_str()), (Some(false), Some("default")), "{k:?}");
    let again = call(&r, ADMIN, "dyn.connect", json!({ "name": "lan2", "url": url })).await;
    assert_eq!(again[0]["reason"], "insecure_transport", "{again:?}");
    // Confirmed: kept.
    call(&r, ADMIN, "config.transport.insecure_ws.set", json!({ "value": true, "confirm_within": "1s" })).await;
    assert_eq!(call(&r, ADMIN, "config.transport.insecure_ws.confirm", json!({})).await[0]["type"], "confirmed");
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_ne!(call(&r, ADMIN, "dyn.connect", json!({ "name": "lan3", "url": url })).await[0]["reason"], "insecure_transport");
    // Audited: set, reverted, confirmed — the actor and hashes, never a value.
    let log = audit_log();
    for action in ["Set", "Reverted", "Confirmed", "Refused"] {
        assert!(log.lines().any(|l| l.contains("config") && l.contains("transport.insecure_ws") && l.contains(&format!("action={action}"))), "{action} in the audit log:\n{log}");
    }
    assert!(log.lines().any(|l| l.contains("transport.insecure_ws") && l.contains(ADMIN)), "the actor");
    stop(far).await;
}

/// `dyn.require_consent`, `dyn.containment.*` and the `child.*` settings
/// are on the same configuration; what the options said is their flag layer.
async fn dyn_settings_are_on_the_service_configuration() {
    let r = rig_opts(None, |o| {
        o.require_consent = false;
        o.child.max_calls = 7;
    })
    .await;
    let c = r.host.config();
    assert!(r.dyn_.config().same(&c), "dyn reads the service's");
    let listed = call(&r, ADMIN, "config.list", json!({})).await;
    let by = |k: &str| listed.iter().find(|i| i["key"] == k).cloned().unwrap_or_else(|| panic!("{k} not listed: {listed:?}"));
    assert_eq!((by("dyn.require_consent")["value"].as_bool(), by("dyn.require_consent")["source"].as_str()), (Some(false), Some("flag")));
    assert_eq!(by("child.max_calls")["value"], 7);
    for k in ["dyn.repin_on_valid_cert", "dyn.containment.deny", "dyn.containment.require", "transport.tls_roots", "child.legacy_upcalls", "child.timeout", "child.backoff", "log.redact.keys"] {
        let _ = by(k);
    }
    assert_eq!(by("dyn.repin_on_valid_cert")["value"], false, "D33: refusing is the default");
    // remote = false over the wire.
    let got = call(&r, ADMIN, "config.transport.tls_roots.set", json!({ "value": "/tmp/ca.pem" })).await;
    assert_eq!(got[0]["reason"], "not_remote", "{got:?}");
    // A reset comes back to the flag.
    call(&r, ADMIN, "config.dyn.require_consent.set", json!({ "value": true, "confirm_within": "30s" })).await;
    assert!(c.get(&plexus_dyn::settings::DYN_REQUIRE_CONSENT));
    call(&r, ADMIN, "config.dyn.require_consent.reset", json!({})).await;
    assert!(!c.get(&plexus_dyn::settings::DYN_REQUIRE_CONSENT), "the flag's again");
}

/// `dyn.repin` refuses a wrong fingerprint and takes the presented one;
/// `dyn.pins` shows both.
async fn repin_takes_only_the_presented_fingerprint() {
    use plexus_core::plexus::peer_token::PeerKey;
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}");
    let (one, two) = (PeerKey::generate(), PeerKey::generate());
    let r = rig().await;
    let first = keyed_peer(port, keyed(&one, &r)).await;
    assert_eq!(call(&r, ADMIN, "dyn.connect", json!({ "name": "k", "url": url })).await[0]["type"], "connected");
    let pins = call(&r, VIEWER, "dyn.pins", json!({})).await;
    let pinned_fp = pins[0]["fingerprint"].as_str().expect("pinned").to_string();
    assert!(pinned_fp.starts_with("sha256:") && pins[0].get("presented").is_none(), "{pins:?}");
    let nothing = call(&r, ADMIN, "dyn.repin", json!({ "name": "k", "fingerprint": pinned_fp })).await;
    assert_eq!(nothing[0]["reason"], "not_presented", "{nothing:?}");
    first.abort();
    let _ = first.await;
    let second = keyed_peer(port, keyed(&two, &r)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let presented = loop {
        let _ = call(&r, USER, "dyn.peer.k.forecast", json!({ "city": "oslo" })).await;
        if let Some(p) = peer(&r, "k").presented {
            break p;
        }
        assert!(Instant::now() < deadline, "the new key was never presented: {:?}", peer(&r, "k"));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(presented.key.as_deref(), Some(two.kid()));
    let pins = call(&r, VIEWER, "dyn.pins", json!({})).await;
    let presented_fp = pins[0]["presented_fingerprint"].as_str().expect("presented").to_string();
    assert_eq!(presented_fp, presented.fingerprint());
    assert_eq!(pins[0]["fingerprint"], pinned_fp.as_str(), "still pinned to the first");
    // A viewer may read the pins, not re-pin.
    assert!(call(&r, VIEWER, "dyn.repin", json!({ "name": "k", "fingerprint": presented_fp })).await[0].get("route_error").is_some());
    let wrong = call(&r, ADMIN, "dyn.repin", json!({ "name": "k", "fingerprint": pinned_fp })).await;
    assert_eq!(wrong[0]["reason"], "fingerprint_mismatch", "{wrong:?}");
    assert_eq!(wrong[0]["presented"]["key"], two.kid(), "the presented identity kept and said: {wrong:?}");
    assert_eq!(wrong[0]["old"]["key"], one.kid(), "{wrong:?}");
    let ok = call(&r, ADMIN, "dyn.repin", json!({ "name": "k", "fingerprint": presented_fp })).await;
    assert_eq!((ok[0]["type"].as_str(), ok[0]["up"].as_bool()), (Some("repinned"), Some(true)), "{ok:?}");
    assert_eq!(peer(&r, "k").identity.and_then(|i| i.key), Some(two.kid().to_string()));
    assert_eq!(call(&r, USER, "dyn.peer.k.forecast", json!({ "city": "oslo" })).await.len(), 7);
    assert!(audit_log().lines().any(|l| l.contains("dyn repin") && l.contains(&presented_fp)), "audited");
    second.abort();
}

/// `dyn.repin_on_valid_cert` (off by default, D33): on, a peer whose
/// certificate key moved under a valid chain is re-pinned, not refused.
async fn repin_on_valid_cert_follows_a_renewed_certificate() {
    let pki = Pki::new();
    let port = free_port();
    let url = format!("wss://127.0.0.1:{port}");
    let first = far_tls(port, pki.leaf("one")).await;
    let r = rig_opts(None, |o| o.child.tls_roots = Some(pki.roots())).await;
    assert_eq!(call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await[0]["type"], "connected");
    let pinned = peer(&r, "w").identity.expect("pinned");
    let got = call(&r, ADMIN, "config.dyn.repin_on_valid_cert.set", json!({ "value": true, "confirm_within": "60s" })).await;
    assert_eq!(got[0]["type"], "set", "{got:?}");
    assert_eq!(call(&r, ADMIN, "config.dyn.repin_on_valid_cert.confirm", json!({})).await[0]["type"], "confirmed");
    let _ = first.stop();
    first.stopped().await;
    let second = far_tls(port, pki.leaf("two")).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = call(&r, USER, "dyn.peer.w.weather.forecast", json!({ "city": "oslo" })).await;
        let p = peer(&r, "w");
        if got.len() == 7 && p.identity.as_ref().is_some_and(|i| i.tls_key != pinned.tls_key) {
            assert!(p.presented.is_none(), "{p:?}");
            break;
        }
        assert!(Instant::now() < deadline, "never re-pinned: {got:?} {p:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(audit_log().contains("re-pinned on a valid certificate"));
    let _ = second.stop();
}

// ------------------------------------------------------------------ DYNAUTH-9

const SECRET_ENV: &str = "PLEXUS_DYN_TEST_SECRET";
const PASSED_ENV: &str = "PLEXUS_DYN_TEST_PASSED";

const PROBE: &str = r#"// A dendrite that looks around: what it may read and write, and what it sees.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

/** Try to read `path`: whether it could, and the error's code if not. */
export async function read({ path }: { path: string }) {
  try { readFileSync(path); return { ok: true, code: "" }; } catch (e) { return { ok: false, code: String((e as { code?: string }).code ?? e) }; }
}

/** Try to list the directory `path`. */
export async function list({ path }: { path: string }) {
  try { readdirSync(path); return { ok: true, code: "" }; } catch (e) { return { ok: false, code: String((e as { code?: string }).code ?? e) }; }
}

/** Try to write `path`. */
export async function write({ path }: { path: string }) {
  try { writeFileSync(path, "x"); return { ok: true, code: "" }; } catch (e) { return { ok: false, code: String((e as { code?: string }).code ?? e) }; }
}

/** An environment variable, its HOME and where it runs. */
export async function env({ name }: { name: string }) {
  return { value: process.env[name] ?? "", home: process.env.HOME ?? "", cwd: process.cwd() };
}
"#;

fn landlock_here() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm").is_ok_and(|l| l.split(',').any(|m| m.trim() == "landlock"))
}

async fn a_grown_dendrite_is_contained() {
    let keys = tempfile::tempdir().unwrap();
    let key = keys.path().join("host.key");
    std::fs::write(&key, "a host's signing key").unwrap();
    let landlock = landlock_here();
    let r = rig_opts(None, |o| {
        o.child.env = vec![SECRET_ENV.into(), PASSED_ENV.into()];
        o.contain.env = vec![PASSED_ENV.into()];
        o.contain.deny = vec![keys.path().to_path_buf()];
        o.contain.require = landlock;
    })
    .await;
    let data = r.dyn_.options().data_dir.clone();
    std::fs::create_dir_all(data.join("other")).unwrap();
    std::fs::write(data.join("other/secret.txt"), "another dendrite's").unwrap();
    let grown = call(&r, ADMIN, "dyn.grow", json!({ "name": "probe", "source": PROBE, "targets": [] })).await;
    assert_eq!(grown[0]["type"], "connected", "{grown:?}");
    let own = data.join("probe");
    let read = |p: PathBuf| {
        let r = &r;
        async move { call(r, ADMIN, "dyn.peer.probe.read", json!({ "path": p.display().to_string() })).await.remove(0) }
    };
    // The environment: the host's secret is not there; what it was given is.
    let env = call(&r, ADMIN, "dyn.peer.probe.env", json!({ "name": SECRET_ENV })).await.remove(0);
    assert_eq!(env["value"], "", "the host's environment reached the dendrite: {env:?}");
    assert!(env["home"].as_str().is_some_and(|h| h.ends_with("probe/.home")), "its own HOME: {env:?}");
    assert!(env["cwd"].as_str().is_some_and(|c| c.ends_with("/probe")), "its own directory: {env:?}");
    let passed = call(&r, ADMIN, "dyn.peer.probe.env", json!({ "name": PASSED_ENV })).await.remove(0);
    assert_eq!(passed["value"], "given", "{passed:?}");
    // Its own directory: read and written.
    assert_eq!(read(own.join("index.ts")).await["ok"], true);
    let w = call(&r, ADMIN, "dyn.peer.probe.write", json!({ "path": own.join("note.txt").display().to_string() })).await.remove(0);
    assert_eq!(w["ok"], true, "{w:?}");
    if !landlock {
        println!("measure: no Landlock on this kernel: the environment is cleared, the files are not denied");
        return;
    }
    // The key, another dendrite's directory, ~/.plexus: refused.
    for denied in [key.clone(), data.join("other/secret.txt")] {
        let got = read(denied.clone()).await;
        assert_eq!((got["ok"].as_bool(), got["code"].as_str()), (Some(false), Some("EACCES")), "{}: {got:?}", denied.display());
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if let Some(k) = std::fs::read_dir(home.join(".plexus/keys")).ok().and_then(|mut d| d.next()).and_then(Result::ok) {
            let got = read(k.path()).await;
            assert_eq!(got["code"], "EACCES", "~/.plexus/keys: {got:?}");
        }
    }
    // DYNAUTH-22: every secret store of this machine's user that is there —
    // a file read, a directory listed — refused.
    let stores = Containment::default_deny(&data);
    let mut seen = 0;
    for store in stores.iter().skip(1) {
        let (method, what) = if store.is_dir() { ("dyn.peer.probe.list", "listed") } else { ("dyn.peer.probe.read", "read") };
        let got = call(&r, ADMIN, method, json!({ "path": store.display().to_string() })).await.remove(0);
        assert_eq!((got["ok"].as_bool(), got["code"].as_str()), (Some(false), Some("EACCES")), "{} {what}: {got:?}", store.display());
        seen += 1;
    }
    println!("measure: {seen} secret stores present here, each refused");
    let w = call(&r, ADMIN, "dyn.peer.probe.write", json!({ "path": data.join("other/planted.txt").display().to_string() })).await.remove(0);
    assert_eq!(w["code"], "EACCES", "{w:?}");
    assert!(!data.join("other/planted.txt").exists());
}

async fn a_dendrite_without_its_launcher() {
    let r = rig_opts(None, |o| {
        o.contain.launcher = Some(PathBuf::from("/nonexistent/plexus-dyn-contain"));
        o.contain.require = true;
    })
    .await;
    let refused = call(&r, ADMIN, "dyn.grow", json!({ "name": "probe", "source": PROBE, "targets": [] })).await;
    assert_eq!(refused[0]["type"], "error", "{refused:?}");
    assert!(refused[0]["message"].as_str().is_some_and(|m| m.contains("required")), "{refused:?}");
    // Not required: it runs, with the environment cleared all the same.
    let r = rig_opts(None, |o| {
        o.contain.launcher = Some(PathBuf::from("/nonexistent/plexus-dyn-contain"));
        o.child.env = vec![SECRET_ENV.into()];
    })
    .await;
    let grown = call(&r, ADMIN, "dyn.grow", json!({ "name": "probe", "source": PROBE, "targets": [] })).await;
    assert_eq!(grown[0]["type"], "connected", "{grown:?}");
    let env = call(&r, ADMIN, "dyn.peer.probe.env", json!({ "name": SECRET_ENV })).await.remove(0);
    assert_eq!(env["value"], "", "{env:?}");
    assert!(env["home"].as_str().is_some_and(|h| h.ends_with("probe/.home")), "{env:?}");
}

// ------------------------------------------------------------------ DYNAUTH-31

#[derive(Clone)]
pub struct ProbeActivation;

/// What an in-process peer serves here.
#[plexus_macros::activation(namespace = "probe", version = "1.0.0")]
impl ProbeActivation {
    /// An answer.
    #[plexus_macros::method]
    pub async fn ask(&self) -> Value {
        json!("asked")
    }

    /// One item, then the stream stays open.
    #[plexus_macros::method]
    pub async fn hold(&self) -> impl Stream<Item = Value> + Send + 'static {
        futures::stream::once(async { json!("first") }).chain(futures::stream::pending())
    }

    /// A whole-service method of the peer's.
    #[plexus_macros::method(everywhere)]
    pub async fn rotate(&self) -> Value {
        json!("rotated")
    }
}

/// An in-process peer (any `Peer`): `ProbeActivation`, and whom each call
/// came as — the context it was handed.
struct Probe {
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl plexus_core::plexus::peer::Peer for Probe {
    fn interface(&self) -> plexus_core::plexus::peer::Interface {
        plexus_core::plexus::peer::Peer::interface(&ProbeActivation)
    }
    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, plexus_core::plexus::PlexusError> {
        self.seen.lock().unwrap().push(auth.and_then(|a| a.principal()).map(|p| p.to_string()).unwrap_or_else(|| "nobody".into()));
        plexus_core::plexus::peer::Peer::call(&ProbeActivation, method, params, auth).await
    }
    async fn peer(&self, name: &str) -> Result<Box<dyn plexus_core::plexus::peer::Peer>, plexus_core::plexus::peer::PeerError> {
        plexus_core::plexus::peer::Peer::peer(&ProbeActivation, name).await
    }
}

fn probe() -> (Arc<dyn plexus_core::plexus::peer::Peer>, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(Probe { seen: seen.clone() }), seen)
}

/// DYNAUTH-31: an in-process peer is called through the slot with the
/// caller's own context, gated as any peer, and dyn mints it no token —
/// where a call into a keyed peer, in the same service, is minted one.
async fn dynauth31_an_in_process_peer_is_called_as_its_caller_and_minted_nothing() {
    use plexus_core::plexus::peer_token::{AuditKind, PeerKey};
    let records = Arc::new(Records::default());
    let sink = records.clone();
    let r = rig_opts(None, move |o| o.audit = Some(plexus_dyn::Audit(sink))).await;
    let (p, seen) = probe();
    let got = r.dyn_.attach("p", "test", "b1", p.clone(), false);
    assert!(matches!(&got, plexus_dyn::DynEvent::Connected { name, replaced: false, .. } if name == "p"), "{got:?}");
    assert!(matches!(r.dyn_.attach("p", "test", "b1", p.clone(), false), plexus_dyn::DynEvent::Error { .. }), "a taken name is refused without `replace`");
    let refused = call(&r, VIEWER, "dyn.peer.p.ask", json!({})).await;
    assert!(refused[0]["route_error"].as_str().is_some_and(|e| e.contains("dyn.{peer}")), "the gate, as for any peer: {refused:?}");
    assert_eq!(call(&r, USER, "dyn.peer.p.ask", json!({})).await, [json!("asked")]);
    assert_eq!(*seen.lock().unwrap(), [USER], "called with the caller's own context");
    assert!(records.0.lock().unwrap().is_empty(), "no token minted for an in-process peer: {:?}", records.0.lock().unwrap());
    // The same service mints one for a keyed peer: the sink sees mints.
    let tk = PeerKey::generate();
    let tp = free_port();
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    call(&r, USER, "dyn.peer.t.claims", json!({})).await;
    let minted: Vec<(AuditKind, String)> = records.0.lock().unwrap().iter().map(|m| (m.kind, m.aud.clone())).collect();
    assert_eq!(minted, [(AuditKind::Mint, tk.kid().to_string())], "only the keyed peer's call is minted");
    let listed = peer(&r, "p");
    assert_eq!(listed.peer, plexus_dyn::PeerKind::InProcess { by: "test".into() });
    assert!(listed.up && listed.identity.is_none() && listed.interface.is_some(), "{listed:?}");
    assert_eq!((listed.calls, listed.open), (1, 0));
    let shown = call(&r, VIEWER, "dyn.peers", json!({})).await;
    assert!(shown.iter().any(|v| v["name"] == "p" && v["kind"] == "in_process" && v["by"] == "test"), "{shown:?}");
    t.abort();
}

/// DYNAUTH-31 (acceptance 3): no token addressed to another peer is
/// obtained through an in-process peer. It holds none (nothing is minted
/// for it); it is no exchange's audience; and a token as dyn would mint for
/// a peer on its own pipe — the nearest thing an unkeyed peer could hold —
/// is not exchanged for one addressed to the keyed peer `t`.
async fn dynauth31_no_token_for_another_peer_through_an_in_process_peer() {
    use plexus_core::plexus::peer_token::{prove, MintRequest, PeerKey, EXCHANGE};
    let r = rig().await;
    let (p, _) = probe();
    r.dyn_.attach("p", "test", "b1", p, false);
    let tk = PeerKey::generate();
    let tp = free_port();
    let t = served_peer(tp, TellActivation, verifying(&tk, &r.dyn_.jwk_set(), &r)).await;
    call(&r, ADMIN, "dyn.connect", json!({ "name": "t", "url": format!("ws://127.0.0.1:{tp}") })).await;
    let exchange = |subject: String, proof: String, audience: &str, method: &str| {
        let ask = json!({ "subject_token": subject, "proof": proof, "audience": audience, "method": method });
        let host = r.host.clone();
        async move { items(host.route("dyn.exchange", ask, None).await).await.remove(0) }
    };
    // Not an audience: a real subject (t's token for a user's call), its real proof.
    let told = call(&r, USER, "dyn.peer.t.claims", json!({})).await.remove(0);
    let token = told["token"].as_str().unwrap().to_string();
    let proof = prove(&tk, &token, EXCHANGE, told["claims"]["call"].as_str().unwrap());
    let got = exchange(token, proof, "p", "probe.ask").await;
    assert!(got["type"] == "error" && got["message"].as_str().is_some_and(|m| m.contains("[audience]")), "{got:?}");
    // Not a presenter: what an unkeyed peer could hold is bound to no key, and refused.
    let (theirs, claims) = r.dyn_.issuer().mint(MintRequest { sub: USER.into(), peer_key: None, name: "p".into(), scope: vec!["dyn.{peer}@*".into()], call: "c-p".into(), method: "probe.ask".into(), presented: None }).unwrap();
    assert_eq!(claims.aud, "pipe:p");
    let forged = prove(&PeerKey::generate(), &theirs, EXCHANGE, "c-p");
    let got = exchange(theirs, forged, "t", "tell.claims").await;
    assert_eq!(got["type"], "error", "no token for t through p: {got:?}");
    assert!(got["message"].as_str().is_some_and(|m| m.contains("the exchange is refused")), "{got:?}");
    t.abort();
}

/// DYNAUTH-31: consent gives an in-process peer `callers` — every method but
/// one it marks `everywhere` (KEEL-31) — and no needs: it declares none.
async fn dynauth31_consent_gives_an_in_process_peer_callers_only() {
    let r = rig().await;
    let (p, _) = probe();
    r.dyn_.attach("p", "test", "b1", p, false);
    let needs = call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "needs": ["dyn.peers"] })).await;
    assert!(needs[0]["type"] == "error" && needs[0]["message"].as_str().is_some_and(|m| m.contains("nothing")), "{needs:?}");
    let ok = call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "callers": ["viewer"] })).await;
    assert_eq!(ok[0]["type"], "consented", "{ok:?}");
    assert_eq!(call(&r, VIEWER, "dyn.peer.p.ask", json!({})).await, [json!("asked")]);
    let rotate = call(&r, VIEWER, "dyn.peer.p.rotate", json!({})).await;
    assert!(rotate[0]["route_error"].is_string(), "consent hands no everywhere method: {rotate:?}");
    assert_eq!(call(&r, ADMIN, "dyn.peer.p.rotate", json!({})).await, [json!("rotated")]);
    let listed = call(&r, VIEWER, "dyn.consents", json!({})).await;
    let mine = listed.iter().find(|c| c["peer"] == "p").unwrap();
    assert!(mine.get("key").is_none() && mine.get("declared").is_none(), "{mine:?}");
}

/// Open `method` as `caller` and take its first item; the rest is read later.
async fn opened(r: &Rig, caller: &str, method: &str) -> (Value, PlexusStream) {
    let mut s = r.host.route(method, json!({}), Some(&who(caller))).await.unwrap();
    let first = match s.next().await {
        Some(PlexusStreamItem::Data { content, .. }) => content.into_value(),
        other => panic!("{other:?}"),
    };
    (first, s)
}

/// What is left of an open stream, within a second (it must end).
async fn rest(s: PlexusStream) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(1), items(Ok(s))).await.expect("the open call ended")
}

/// DYNAUTH-31: `dyn.revoke` and `dyn.disconnect` stop an in-process peer as
/// any peer: an open call ends saying why, the next is refused; the
/// revocation stands when it is attached again (as at a restart) and ends
/// only with `replace`, an admin's new registration.
async fn dynauth31_revoke_and_disconnect_stop_an_in_process_peer() {
    let r = rig().await;
    let (p, _) = probe();
    r.dyn_.attach("p", "test", "b1", p.clone(), false);
    let (first, open) = opened(&r, USER, "dyn.peer.p.hold").await;
    assert_eq!(first, json!("first"));
    assert_eq!(peer(&r, "p").open, 1);
    let revoked = call(&r, ADMIN, "dyn.revoke", json!({ "peer": "p", "why": "its bridge leaked" })).await;
    assert_eq!(revoked[0]["type"], "revoked", "{revoked:?}");
    let ended = rest(open).await;
    assert!(ended[0]["message"].as_str().is_some_and(|m| m.contains("its bridge leaked")), "{ended:?}");
    let next = call(&r, ADMIN, "dyn.peer.p.ask", json!({})).await;
    assert!(next[0]["message"].as_str().is_some_and(|m| m.contains("revoked")), "{next:?}");
    let listed = peer(&r, "p");
    assert!(listed.revoked.as_deref() == Some("its bridge leaked") && !listed.up && listed.open == 0, "{listed:?}");
    // Let go and attached again, as at a restart: still revoked.
    assert!(r.dyn_.detach("p", &p));
    r.dyn_.attach("p", "test", "b1", p.clone(), false);
    assert!(call(&r, ADMIN, "dyn.peer.p.ask", json!({})).await[0]["message"].as_str().is_some_and(|m| m.contains("revoked")));
    // `replace`: a new registration, the revocation ends.
    r.dyn_.attach("p", "test", "b1", p.clone(), true);
    assert_eq!(peer(&r, "p").revoked, None);
    assert_eq!(call(&r, USER, "dyn.peer.p.ask", json!({})).await, [json!("asked")]);
    // Disconnected: the open call ends, the name is gone.
    let (_, open) = opened(&r, USER, "dyn.peer.p.hold").await;
    assert_eq!(call(&r, ADMIN, "dyn.disconnect", json!({ "name": "p" })).await[0]["type"], "disconnected");
    let ended = rest(open).await;
    assert!(ended[0]["message"].as_str().is_some_and(|m| m.contains("disconnected")), "{ended:?}");
    let gone = call(&r, USER, "dyn.peer.p.ask", json!({})).await;
    assert!(gone[0]["message"].as_str().is_some_and(|m| m.contains("no peer named `p`")), "{gone:?}");
    // Another holder of the name is not let go by the one before.
    let (other, _) = probe();
    r.dyn_.attach("p", "test", "b1", other, false);
    assert!(!r.dyn_.detach("p", &p), "detach lets go only of the peer it names");
    assert!(r.dyn_.list().iter().any(|x| x.name == "p"));
}

/// Whether VIEWER (no `dyn.{peer}`) is admitted to `method`.
async fn viewer_admitted(r: &Rig, method: &str, params: Value) -> bool {
    call(r, VIEWER, method, params).await.first().is_some_and(|v| v.get("route_error").is_none())
}

fn consented_names(r: &Rig) -> Vec<String> {
    r.dyn_.consent_list().into_iter().filter(|c| !c.callers.is_empty() || !c.needs.is_empty()).map(|c| c.peer).collect()
}

/// DYNAUTH-31 (D2, KEEL-24 extended): a consent is its holder's, not its
/// name's. An in-process peer keeps it only while the same attacher serves
/// the same binding; another binding, a detach, a keyless WebSocket peer
/// taking the name with `replace` — or an in-process peer taking a keyless
/// one's — each starts with none.
async fn dynauth31_a_consent_is_its_holders_not_its_names() {
    let r = rig().await;
    let ask = || json!({});
    let (p, _) = probe();
    r.dyn_.attach("p", "test", "b1", p.clone(), false);
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "callers": ["viewer"] })).await;
    assert!(viewer_admitted(&r, "dyn.peer.p.ask", ask()).await);
    // The same holder again (as at a restart, or a replace that changes nothing): kept.
    r.dyn_.attach("p", "test", "b1", p.clone(), true);
    assert!(viewer_admitted(&r, "dyn.peer.p.ask", ask()).await, "the same binding keeps its consent");
    // Another binding under the name: none.
    let (q, _) = probe();
    r.dyn_.attach("p", "test", "b2", q.clone(), true);
    assert!(!viewer_admitted(&r, "dyn.peer.p.ask", ask()).await, "a consent followed the name to another binding");
    assert!(!consented_names(&r).contains(&"p".to_string()));
    // Detached: its consent goes; the same peer attached again starts with none.
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "callers": ["viewer"] })).await;
    assert!(r.dyn_.detach("p", &q));
    r.dyn_.attach("p", "test", "b2", q.clone(), false);
    assert!(!viewer_admitted(&r, "dyn.peer.p.ask", ask()).await, "a consent outlived its detach");
    // A keyless WebSocket peer over an in-process one's name: none.
    call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "callers": ["viewer"] })).await;
    let port = free_port();
    let far_ = far(port, false).await;
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "p", "url": format!("ws://127.0.0.1:{port}"), "replace": true })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert!(!viewer_admitted(&r, "dyn.peer.p.weather.forecast", json!({ "city": "oslo" })).await, "a keyless peer inherited an in-process peer's consent");
    assert!(!consented_names(&r).contains(&"p".to_string()), "the in-process peer's consent is still kept for the name");
    // And the reverse: an in-process peer over a keyless one's name.
    let c = call(&r, ADMIN, "dyn.consent", json!({ "peer": "p", "callers": ["viewer"] })).await;
    assert_eq!(c[0]["type"], "consented", "{c:?}");
    assert!(viewer_admitted(&r, "dyn.peer.p.weather.forecast", json!({ "city": "oslo" })).await);
    r.dyn_.attach("p", "test", "b1", p, true);
    assert!(!viewer_admitted(&r, "dyn.peer.p.ask", ask()).await, "an in-process peer inherited a keyless peer's consent");
    stop(far_).await;
}

/// DYNAUTH-31 (D1): `holds` — what an attacher asks before acting for its
/// peer outside a call: yes while dyn serves that very peer unrevoked; no
/// once revoked, disconnected, or another peer holds the name.
async fn dynauth31_holds_says_whether_a_peer_may_act() {
    let r = rig().await;
    let (p, _) = probe();
    r.dyn_.attach("p", "test", "b1", p.clone(), false);
    assert_eq!(r.dyn_.holds("p", &p), Ok(()));
    call(&r, ADMIN, "dyn.revoke", json!({ "peer": "p", "why": "breached" })).await;
    assert!(r.dyn_.holds("p", &p).is_err_and(|e| e.contains("revoked")));
    r.dyn_.attach("p", "test", "b1", p.clone(), true);
    assert_eq!(r.dyn_.holds("p", &p), Ok(()));
    let (q, _) = probe();
    r.dyn_.attach("p", "test", "b1", q.clone(), true);
    assert!(r.dyn_.holds("p", &p).is_err_and(|e| e.contains("another peer")), "the one replaced may not act");
    call(&r, ADMIN, "dyn.disconnect", json!({ "name": "p" })).await;
    assert!(r.dyn_.holds("p", &q).is_err());
}

fn main() {
    // DYNAUTH-7: every `plexus::audit` line, kept for a test to read.
    tracing_subscriber::fmt().with_env_filter("plexus::audit=info").with_writer(|| AuditWriter).with_ansi(false).init();
    // DYNAUTH-9: a secret in the host's environment (and one it means to pass).
    std::env::set_var(SECRET_ENV, "s3cret-dynauth9");
    std::env::set_var(PASSED_ENV, "given");
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        // KEEL-19: `cargo test --test dyn -- NAME` (or `DYN_TEST=NAME`) runs
        // only the rows whose name holds NAME — one row alone, to see it red.
        let only: Option<String> = std::env::args().skip(1).find(|a| !a.starts_with('-')).or_else(|| std::env::var("DYN_TEST").ok());
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( if only.as_deref().is_none_or(|f| stringify!($t).contains(f)) { $t().await; println!("test {} ... ok", stringify!($t)); n += 1; } )* n }};
        }
        let n = run!(
            connect_call_disconnect,
            a_caller_without_the_grant_is_refused,
            the_far_side_restarts_and_is_redialed,
            a_changed_schema_is_remounted,
            a_dendrite_calls_its_target_through_the_host,
            a_silent_peer_is_marked_down,
            a_live_peer_stays_up_through_its_pings,
            the_peers_file_is_connected_at_start,
            a_peer_grows_the_top_level,
            dyn_client_reaches_a_peer_untyped_and_typed,
            connect_expecting_refuses_another_interface,
            a_dendrite_whose_needs_are_not_served_is_refused,
            ws_beyond_loopback_is_refused,
            the_insecure_override_is_said,
            a_wss_peer_is_validated_and_its_key_pinned,
            a_grown_dendrite_is_contained,
            a_dendrite_without_its_launcher,
            a_viewer_with_consent_reaches_a_peer,
            a_peer_whose_key_changed_is_refused_at_remount,
            a_verifying_peer_takes_a_call_by_its_token,
            a_keyed_peer_calls_back_with_its_proof,
            an_onward_call_is_an_exchange,
            keel19_an_unconsented_peer_is_refused_an_exchange,
            keel19_a_consented_peer_reaches_another_with_its_proof,
            keel19_a_subject_is_exchanged_once,
            keel19_a_revoked_presenter_is_refused_at_once,
            keel19_a_narrowed_consent_holds_an_open_call,
            keel19_a_key_is_mounted_once,
            keel19_two_connects_racing_on_one_key,
            keel19_dyn_dials_with_a_key_and_no_peer_trusts_a_name,
            keel19_a_revoke_while_dialing_mints_nothing,
            keel19_a_data_directory_open_to_others_is_refused,
            keel19_a_refused_connect_keeps_the_named_consent,
            a_revoked_peer_is_refused_and_its_tokens_expire,
            every_hop_is_audited_without_a_secret,
            the_signing_key_rotates,
            a_setting_flipped_through_config_takes_effect_live,
            dyn_settings_are_on_the_service_configuration,
            repin_takes_only_the_presented_fingerprint,
            repin_on_valid_cert_follows_a_renewed_certificate,
            dynauth31_an_in_process_peer_is_called_as_its_caller_and_minted_nothing,
            dynauth31_no_token_for_another_peer_through_an_in_process_peer,
            dynauth31_consent_gives_an_in_process_peer_callers_only,
            dynauth31_revoke_and_disconnect_stop_an_in_process_peer,
            dynauth31_a_consent_is_its_holders_not_its_names,
            dynauth31_holds_says_whether_a_peer_may_act
        );
        println!("\ntest result: ok. {n} passed; 0 failed");
    });
}
