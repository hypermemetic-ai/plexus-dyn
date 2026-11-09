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
        data_dir: data.path().to_path_buf(),
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
    let gate = Arc::new(Gate::new(members, Arc::new(roles), Arc::new(Everywhere)));
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).with_gate(gate));
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
    let got = call(&r, USER, "dyn.peer.digest.rainy", json!({ "city": "lisbon" })).await;
    assert_eq!(got[0], json!({ "rain_days": rainy_days("lisbon") }), "{got:?}");
    let d = peer(&r, "digest");
    assert_eq!((d.calls_back, d.up), (2, true), "its target's schema at its start, then one call back: {d:?}");
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
    assert_eq!(top(&r), ["dyn"]);
    let url = format!("ws://127.0.0.1:{port}");
    let got = call(&r, ADMIN, "dyn.connect", json!({ "name": "w", "url": url })).await;
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    assert_eq!(top(&r), ["dyn", "w"]);
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
    assert_eq!(kids, ["dyn", "w"], "{schema:?}");
    // A name the service serves already is refused.
    let taken = call(&r, ADMIN, "dyn.connect", json!({ "name": "dyn", "url": url })).await;
    assert!(taken[0]["message"].as_str().is_some_and(|m| m.contains("top level")), "{taken:?}");
    assert_eq!(call(&r, VIEWER, "dyn.names", json!({})).await, [json!("w")]);
    // Disconnected: gone from the top level.
    call(&r, ADMIN, "dyn.disconnect", json!({ "name": "w" })).await;
    assert_eq!(top(&r), ["dyn"]);
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

fn main() {
    // DYNAUTH-9: a secret in the host's environment (and one it means to pass).
    std::env::set_var(SECRET_ENV, "s3cret-dynauth9");
    std::env::set_var(PASSED_ENV, "given");
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( $t().await; println!("test {} ... ok", stringify!($t)); n += 1; )* n }};
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
            a_dendrite_without_its_launcher
        );
        println!("\ntest result: ok. {n} passed; 0 failed");
    });
}
