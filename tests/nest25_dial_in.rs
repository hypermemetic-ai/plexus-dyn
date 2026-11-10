//! NEST-25 · a node behind a NAT dials out to a host and becomes a peer
//! there: `dyn.peer.<name>` in dyn's table, with dyn's consent, revoke and
//! the gate, for as long as its socket lives. The host is a service with
//! `dyn` and a `shop`, on plexus-transport's WebSocket server with key
//! sign-in and dyn's dial-in door on its connection hook (as `plexus-ui
//! serve --dyn --dial-in` runs it). Ports 5620–5659.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_stream::stream;
use futures::{SinkExt, Stream, StreamExt};
use plexus_auth_core::adapters::{Carriers, KeyProofAdapter};
use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_auth_core::identity::AuthenticatorChain;
use plexus_core::plexus::remote_child::{DialOut, DialState, Exposed, PeerSocket};
use plexus_core::plexus::{AuthContext, ChildOptions, Parent, PlexusStreamItem};
use plexus_core::DynamicHub;
use plexus_dyn::{DialIn, DynActivation, DynOptions};
use plexus_transport::ws::{ConnectionHook, Hooks, Outbound};
use plexus_transport::TransportServer;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VIEWER: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub mod shop {
    use super::*;

    #[derive(Clone)]
    pub struct Shop;

    /// The host's shop.
    #[plexus_macros::activation]
    impl Shop {
        /// What is on the shelves, and for whom it was asked.
        #[plexus_macros::method]
        pub async fn items(&self) -> Value {
            let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
            json!({ "items": ["flour"], "caller": caller })
        }
    }
}

/// A node's activation: greets, counts, and knows its parent's shop.
#[derive(Clone)]
pub struct Restock;

#[plexus_macros::activation(parent = shop::ShopClient)]
impl Restock {
    /// Greet, naming the caller the hop names.
    #[plexus_macros::method]
    pub async fn hello(&self, name: String) -> impl Stream<Item = Value> + Send + 'static {
        let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
        stream! { yield json!({ "text": format!("hello {name}"), "caller": caller }); }
    }
    /// Count slowly: a call to hold open.
    #[plexus_macros::method]
    pub async fn count(&self, n: u32) -> impl Stream<Item = u32> + Send + 'static {
        stream! {
            for i in 0..n {
                yield i;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    /// The parent's items, called back through the host.
    #[plexus_macros::method]
    pub async fn low(&self, parent: Parent<shop::ShopClient>) -> Value {
        match parent.items().await {
            Ok(v) => json!({ "low": v }),
            Err(e) => json!({ "error": e.to_string() }),
        }
    }
}

/// A graft whose parent this host does not serve.
pub mod elsewhere {
    use super::*;
    #[derive(Clone)]
    pub struct Bakery;
    /// Another service's bakery.
    #[plexus_macros::activation]
    impl Bakery {
        /// Bread.
        #[plexus_macros::method]
        pub async fn bread(&self) -> Value {
            json!("bread")
        }
    }
}

#[derive(Clone)]
pub struct Baker;

#[plexus_macros::activation(parent = elsewhere::BakeryClient)]
impl Baker {
    /// Bakes with the parent's bread.
    #[plexus_macros::method]
    pub async fn bake(&self, parent: Parent<elsewhere::BakeryClient>) -> Value {
        json!(parent.bread().await.is_ok())
    }
}

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

fn port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(5620);
    loop {
        let p = NEXT.fetch_add(1, Ordering::SeqCst);
        assert!(p <= 5659, "no port left in 5620–5659");
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

/// A key file (0600) in `dir`, and its principal.
fn key(dir: &std::path::Path, name: &str, seed: u8) -> (std::path::PathBuf, String) {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("{name}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([seed; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let p = plexus_core::plexus::remote_child::key_principal(&path).unwrap();
    (path, p)
}

struct Hook(Arc<PeerSocket>);
impl ConnectionHook for Hook {
    fn on_frame(&self, frame: &[u8]) -> bool {
        self.0.on_frame(frame)
    }
    fn on_close(&self) {
        self.0.on_close()
    }
}

struct Host {
    url: String,
    service: Arc<DynamicHub>,
    dyn_: DynActivation,
    door: DialIn,
    _data: tempfile::TempDir,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

async fn host_with(tune: impl FnOnce(&mut DynOptions)) -> Host {
    let port = port();
    let data = tempfile::tempdir().unwrap();
    let mut opts = DynOptions {
        data_dir: data.path().join("dyn"),
        dendrite: data.path().join("no-dendrite"),
        liveness: Duration::from_secs(3600),
        child: ChildOptions { timeout: Duration::from_secs(3), ..ChildOptions::for_service("dyn") },
        ..DynOptions::default()
    };
    tune(&mut opts);
    let dyn_ = DynActivation::new(opts);
    let declared = DynamicHub::new("host").register(dyn_.clone()).register(shop::Shop).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (p, r) in [(ADMIN, "admin"), (VIEWER, "viewer")] {
        members.0.lock().unwrap().push(Membership { principal: p.parse().unwrap(), role: plexus_auth_core::RoleName::new(r), scope: ScopeRef::Everywhere });
    }
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Everywhere)));
    let service = Arc::new(DynamicHub::new("host").register(dyn_.clone()).register(shop::Shop).with_gate(gate));
    dyn_.start(&service).await.unwrap();
    let door = dyn_.dial_in().unwrap();
    let url = format!("ws://127.0.0.1:{port}/ws");
    let keys = KeyProofAdapter::new([url.clone()].iter()).unwrap();
    let chain = Carriers::cookie_and_bearer(AuthenticatorChain::new().with(Arc::new(keys)));
    let for_hook = door.clone();
    let hooks = Hooks::new(move |conn, ext| {
        let auth = ext.get::<Arc<AuthContext>>().map(|a| (**a).clone());
        let writer = conn.writer()?;
        let closer = Arc::clone(conn);
        let (socket, mut out) = for_hook.socket(auth, Some(conn.peer().to_string()), move || closer.close())?;
        tokio::spawn(async move {
            while let Some(f) = out.recv().await {
                if writer.send(Outbound::Text(String::from_utf8(f).unwrap())).await.is_err() {
                    break;
                }
            }
        });
        Some(Arc::new(Hook(socket)) as Arc<dyn ConnectionHook>)
    });
    let server = TransportServer::builder(Arc::clone(&service), |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_session_validator(Arc::new(chain))
        .anonymous_view()
        .reject_upgrade_on_auth_failure()
        .with_hooks(hooks)
        .with_allowed_hosts([format!("127.0.0.1:{port}")])
        .build()
        .await
        .unwrap();
    let serving = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Host { url, service, dyn_, door, _data: data, serving }
}

async fn host() -> Host {
    host_with(|_| {}).await
}

/// A node serving `Restock` as `name`, the host's key pinned.
fn node(host: &Host, name: &str, key: &std::path::Path) -> Exposed {
    let mut d = DialOut::new(host.url.clone(), key).trust(host.door.host_key()).mount(name).agent(name);
    d.backoff.initial = Duration::from_millis(100);
    d.backoff.max = Duration::from_millis(300);
    let e = Exposed::new(d);
    e.serve(Restock);
    e
}

async fn call(host: &Host, caller: &str, method: &str, params: Value) -> Result<Vec<Value>, String> {
    let stream = host.service.route(method, params, Some(&who(caller))).await.map_err(|e| e.to_string())?;
    let items: Vec<PlexusStreamItem> = stream.collect().await;
    let mut out = Vec::new();
    for i in items {
        match i {
            PlexusStreamItem::Data { content, .. } => out.push(content.into_value()),
            PlexusStreamItem::Error { message, .. } => return Err(message),
            _ => {}
        }
    }
    Ok(out)
}

async fn admit(host: &Host, args: Value) -> Vec<Value> {
    call(host, ADMIN, "dyn.admit", args).await.unwrap()
}

fn listed(host: &Host) -> Vec<Value> {
    host.dyn_.list().into_iter().map(|p| serde_json::to_value(p).unwrap()).collect()
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never: {what}");
}

// ------------------------------------------------------------------ row 1, 2

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admitted_key_dials_in_and_is_called_as_dyn_peer_name() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 1);
    let host = host().await;
    let said = admit(&host, json!({ "name": "alice", "key": alice })).await;
    assert_eq!(said[0]["type"], "admitted", "{said:?}");
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();

    let peers = listed(&host);
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0]["name"], "alice");
    assert_eq!(peers[0]["kind"], "dial_in");
    assert_eq!(peers[0]["principal"], alice.as_str());
    assert!(peers[0]["since"].as_u64().unwrap() > 0 && peers[0]["up"] == true, "{peers:?}");

    // Through the gate, as every peer: the admin reaches it, its caller the hop's.
    let got = call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.unwrap();
    assert_eq!(got, [json!({ "text": "hello x", "caller": ADMIN })]);
    // A viewer holds no `dyn.{peer}`: refused before it crosses.
    assert!(call(&host, VIEWER, "dyn.peer.alice.hello", json!({ "name": "x" })).await.is_err());
    // Its consent is its key's.
    let consents = host.dyn_.consent_list();
    assert_eq!(consents[0].key.as_deref(), Some(alice.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_socket_takes_the_peer_out_at_once_and_a_reconnect_brings_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 2);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let mut open = host.service.route("dyn.peer.alice.count", json!({ "n": 1000 }), Some(&who(ADMIN))).await.unwrap();
    assert!(matches!(open.next().await, Some(PlexusStreamItem::Data { .. })));
    a.stop();
    let rest: Vec<PlexusStreamItem> = tokio::time::timeout(Duration::from_secs(5), open.collect()).await.expect("the open call ends");
    assert!(rest.iter().any(|i| i.error_kind() == Some("child_unavailable")), "{rest:?}");
    until("the peer is gone", || listed(&host).is_empty()).await;
    assert!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.is_err());

    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    assert_eq!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "again" })).await.unwrap()[0]["text"], "hello again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_closes_the_socket_and_refuses_its_next_offer() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 3);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let said = call(&host, ADMIN, "dyn.revoke", json!({ "peer": "alice" })).await.unwrap();
    assert_eq!(said[0]["type"], "revoked");
    // The socket is closed; the node dials again and is refused, typed.
    let mut w = a.watch();
    let refused = tokio::time::timeout(Duration::from_secs(10), w.wait_for(|s| matches!(s, DialState::Refused { .. }))).await.expect("refused").unwrap().clone();
    assert!(format!("{refused:?}").contains("revoked"), "{refused:?}");
    assert!(listed(&host).iter().all(|p| p["up"] != true), "{:?}", listed(&host));
    // Admitted again: back.
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_drops_the_socket_and_the_admission_stays() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 4);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let mut w = a.watch();
    let said = call(&host, ADMIN, "dyn.disconnect", json!({ "name": "alice" })).await.unwrap();
    assert_eq!(said[0]["type"], "disconnected");
    tokio::time::timeout(Duration::from_secs(5), w.wait_for(|s| matches!(s, DialState::Down { .. }))).await.expect("its socket dropped").unwrap();
    // It dials again within its backoff and is mounted: the admission stands.
    until("back", || listed(&host).iter().any(|p| p["up"] == true)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_held_by_another_key_is_refused_and_the_same_key_takes_it_over() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 5);
    let (kb, _bob) = key(dir.path(), "bob", 6);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    // Bob asks for alice's name: refused before anything is asked of him.
    let b = node(&host, "alice", &kb);
    let refused = b.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("name_taken"), "{refused}");
    // Alice from a second socket: it takes the name over, the first is closed.
    let mut w = a.watch();
    let a2 = node(&host, "alice", &k);
    a2.mounted(Duration::from_secs(10)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), w.wait_for(|s| matches!(s, DialState::Down { .. }))).await.expect("the old socket closed").unwrap();
    a.stop();
    assert_eq!(listed(&host).len(), 1);
    assert_eq!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.unwrap()[0]["text"], "hello x");
    // One key, one peer: alice's key under another name is refused.
    admit(&host, json!({ "name": "alias", "key": alice })).await;
    let c = node(&host, "alias", &k);
    let refused = c.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("key_in_use"), "{refused}");
}

// ------------------------------------------------------------------ rows 2, 8, 9

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unadmitted_key_waits_pending_mounts_nothing_and_is_admitted_by_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 7);
    let host = host().await;
    let a = node(&host, "alice", &k);
    until("pending", || a.pending().is_some()).await;
    let code = a.pending().unwrap();
    // Nothing mounted, nothing reached.
    assert!(listed(&host).is_empty());
    assert!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.is_err());
    assert!(matches!(a.state(), DialState::Connecting));
    // The operator sees it, with the node's code; nobody else does.
    let pending = call(&host, ADMIN, "dyn.pending", json!({})).await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["name"], "alice");
    assert_eq!(pending[0]["principal"], alice.as_str());
    assert_eq!(pending[0]["code"], code.as_str(), "one code on both sides");
    assert!(pending[0]["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(pending[0]["from"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert!(call(&host, VIEWER, "dyn.pending", json!({})).await.is_err(), "pending offers are the operators'");
    // A wrong code admits nothing.
    let wrong = call(&host, ADMIN, "dyn.admit", json!({ "code": "AAAA-AAAA" })).await.unwrap();
    assert_eq!(wrong[0]["type"], "error", "{wrong:?}");
    // Its code, typed loosely: admitted, and mounted on the same socket.
    let said = admit(&host, json!({ "code": code.to_lowercase().replace('-', " ") })).await;
    assert_eq!(said[0]["type"], "admitted", "{said:?}");
    assert_eq!(said[0]["released"], true);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    assert_eq!(a.code(), Some(code));
    assert_eq!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.unwrap()[0]["text"], "hello x");
    assert!(call(&host, ADMIN, "dyn.pending", json!({})).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_key_stays_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (k, mallory) = key(dir.path(), "mallory", 8);
    let host = host().await;
    let m = node(&host, "mallory", &k);
    until("pending", || m.pending().is_some()).await;
    let code = m.pending().unwrap();
    let said = call(&host, ADMIN, "dyn.refuse", json!({ "code": code })).await.unwrap();
    assert_eq!(said[0]["type"], "key_refused", "{said:?}");
    assert_eq!(said[0]["key"], mallory.as_str());
    let refused = m.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("refused"), "{refused}");
    // Again, from a new socket: refused at once, never pending.
    let m = node(&host, "mallory", &k);
    let refused = m.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("refused"), "{refused}");
    assert!(call(&host, ADMIN, "dyn.pending", json!({})).await.unwrap().is_empty());
    assert!(listed(&host).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_is_capped_in_all_per_address_per_key_and_in_age() {
    let dir = tempfile::tempdir().unwrap();
    let host = host_with(|o| {
        o.dial_in_pending_max = 3;
        o.dial_in_pending_per_address = 2;
        o.dial_in_pending_age = Duration::from_millis(1500);
    })
    .await;
    let (k1, _) = key(dir.path(), "n1", 11);
    let (k2, _) = key(dir.path(), "n2", 12);
    let (k3, _) = key(dir.path(), "n3", 13);
    let n1 = node(&host, "n1", &k1);
    until("n1 pending", || n1.pending().is_some()).await;
    // One per key: the same key again supersedes the first.
    let n1b = node(&host, "n1", &k1);
    let superseded = n1.mounted(Duration::from_secs(5)).await.unwrap_err();
    assert!(superseded.contains("superseded"), "{superseded}");
    until("n1b pending", || n1b.pending().is_some()).await;
    let n2 = node(&host, "n2", &k2);
    until("n2 pending", || n2.pending().is_some()).await;
    // Two from 127.0.0.1 already: a third from there is refused.
    let n3 = node(&host, "n3", &k3);
    let full = n3.mounted(Duration::from_secs(5)).await.unwrap_err();
    assert!(full.contains("pending_full"), "{full}");
    assert_eq!(host.dyn_.pending_list().len(), 2);
    // And each waits its age, no longer.
    let expired = n2.mounted(Duration::from_secs(5)).await.unwrap_err();
    assert!(expired.contains("pending_expired"), "{expired}");
    until("none pending", || host.dyn_.pending_list().is_empty()).await;
    assert!(listed(&host).is_empty());
}

// ------------------------------------------------------------------ row 3

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graft_calls_back_as_its_caller_within_its_consent() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 14);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let consents = host.dyn_.consent_list();
    assert_eq!(consents[0].declared.as_deref(), Some(&["shop.items".to_string()][..]), "its needs are registered");
    // Declared, not consented: refused upward.
    let got = call(&host, ADMIN, "dyn.peer.alice.low", json!({})).await.unwrap();
    assert!(got[0]["error"].as_str().is_some_and(|e| e.contains("not_needed") || e.contains("forbidden") || e.contains("consent")), "{got:?}");
    // Consented: the shop answers, its caller the one the call was for.
    call(&host, ADMIN, "dyn.consent", json!({ "peer": "alice", "needs": ["shop.items"] })).await.unwrap();
    let got = call(&host, ADMIN, "dyn.peer.alice.low", json!({})).await.unwrap();
    assert_eq!(got[0]["low"]["caller"], ADMIN, "{got:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graft_whose_needs_this_service_does_not_serve_is_refused_at_its_mount() {
    let dir = tempfile::tempdir().unwrap();
    let (k, baker) = key(dir.path(), "baker", 15);
    let host = host().await;
    admit(&host, json!({ "name": "baker", "key": baker })).await;
    let mut d = DialOut::new(host.url.clone(), &k).trust(host.door.host_key()).mount("baker");
    d.backoff.initial = Duration::from_millis(100);
    let b = Exposed::new(d);
    b.serve(Baker);
    let refused = b.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("needs_unmet") && refused.contains("bakery.bread"), "{refused}");
    assert!(listed(&host).is_empty());
}

// ------------------------------------------------------------------ rows 2, 6: a socket by hand

/// A raw socket signed in as `seed`'s key (or anonymous), and its frames.
async fn raw(host: &Host, seed: Option<u8>) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = host.url.as_str().into_client_request().unwrap();
    if let Some(seed) = seed {
        let k = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]);
        let bearer = plexus_core::plexus::remote_child::dial_proof(&k, &host.url);
        req.headers_mut().insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    }
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

async fn send(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// The next frame whose `id` is `id`, within `secs`.
async fn answer_to(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, id: &str, secs: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let Some(Ok(Message::Text(t))) = ws.next().await else { panic!("the socket ended") };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v.get("method").is_none() && v["id"] == json!(id) {
                return v;
            }
        }
    })
    .await
    .expect("answered")
}

/// The host's nonce, from `_info {nonce, commit}`.
async fn info(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, node_nonce: &str) -> String {
    send(ws, json!({ "jsonrpc": "2.0", "id": "i", "method": "_info", "params": { "nonce": "n", "commit": plexus_core::plexus::remote_child::pairing::commitment(node_nonce) } })).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Some(Ok(Message::Text(t))) = ws.next().await else { panic!("the socket ended") };
            if let Some(i) = t.find("\"host_nonce\":\"") {
                let rest = &t[i + 14..];
                return rest[..rest.find('"').unwrap()].to_string();
            }
        }
    })
    .await
    .expect("_info answered")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_anonymous_socket_or_an_unproven_key_mounts_nothing_and_learns_nothing() {
    let host = host().await;
    // Anonymous: no hook — its offer is an unknown method, and `_info` proves nothing.
    let mut ws = raw(&host, None).await;
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": "x", "mount": "x" } })).await;
    let a = answer_to(&mut ws, "o", 5).await;
    assert!(a.get("error").is_some() && a.get("result").is_none(), "{a}");
    assert!(host.door.socket(None, None, || {}).is_none(), "no hook for an anonymous socket");
    // A key signed in at the upgrade but not proven on its connection (no `possession`): refused.
    let k = plexus_core::plexus::peer_token::PeerKey::from_seed([21; 32]);
    admit(&host, json!({ "name": "x", "key": k.kid() })).await;
    let mut ws = raw(&host, Some(21)).await;
    let _ = info(&mut ws, "nn").await;
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": "x", "mount": "x", "pairing_nonce": "nn" } })).await;
    let a = answer_to(&mut ws, "o", 5).await;
    assert_eq!(a.pointer("/error/data/error_kind").and_then(Value::as_str), Some("unauthenticated"), "{a}");
    // A forged `possession`: refused.
    let mut ws = raw(&host, Some(21)).await;
    let _ = info(&mut ws, "nn").await;
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": "x", "mount": "x", "pairing_nonce": "nn", "possession": "AAAA" } })).await;
    let a = answer_to(&mut ws, "o", 5).await;
    assert_eq!(a.pointer("/error/data/error_kind").and_then(Value::as_str), Some("unauthenticated"), "{a}");
    assert!(listed(&host).is_empty() && host.dyn_.pending_list().is_empty());
}

/// A node that signs its offer properly and then never answers.
async fn silent(host: &Host, seed: u8, name: &str) -> (tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Value) {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let me = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]).kid().to_string();
    let mut ws = raw(host, Some(seed)).await;
    let host_nonce = info(&mut ws, "nn").await;
    let input = plexus_core::plexus::remote_child::possession_input(host.door.host_key(), &me, "nn", &host_nonce, "host", name);
    use base64::Engine;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(input.as_bytes()).to_bytes());
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": name, "mount": name, "pairing_nonce": "nn", "possession": sig } })).await;
    let me = json!(me);
    (ws, me)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_never_answers_its_schema_is_refused_within_the_timeout() {
    let host = host_with(|o| o.child.timeout = Duration::from_millis(800)).await;
    let k = plexus_core::plexus::peer_token::PeerKey::from_seed([22; 32]);
    admit(&host, json!({ "name": "mute", "key": k.kid() })).await;
    let (mut ws, _) = silent(&host, 22, "mute").await;
    let a = answer_to(&mut ws, "o", 5).await;
    assert!(a.get("error").is_some(), "{a}");
    assert!(a.to_string().contains("not mounted"), "{a}");
    assert!(listed(&host).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn calls_into_one_socket_are_capped() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 23);
    let host = host_with(|o| o.child.max_calls = 1).await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let mut first = host.service.route("dyn.peer.alice.count", json!({ "n": 1000 }), Some(&who(ADMIN))).await.unwrap();
    assert!(matches!(first.next().await, Some(PlexusStreamItem::Data { .. })));
    let second = call(&host, ADMIN, "dyn.peer.alice.count", json!({ "n": 2 })).await;
    assert!(second.as_ref().is_err_and(|e| e.contains("too many") || e.contains("max") || e.contains("calls")), "{second:?}");
}
