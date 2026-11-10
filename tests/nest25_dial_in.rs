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
    /// Reaches past its needs, by hand, on the raw connection back.
    #[plexus_macros::method]
    pub async fn sneak(&self) -> Value {
        use plexus_client::{MethodRef, StreamItem, Transport};
        let t = match plexus_core::plexus::remote_child::host() {
            Ok(t) => t,
            Err(e) => return json!({ "no_host": e.to_string() }),
        };
        let items: Vec<_> = t.call(MethodRef::new("dyn", "rotate_key"), json!({})).collect().await;
        match items.into_iter().next() {
            Some(Ok(StreamItem::Data { content, .. })) => json!({ "reached": content }),
            Some(Ok(StreamItem::Error { message, .. })) => json!({ "refused": message }),
            other => json!({ "refused": format!("{other:?}") }),
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
    /// KEEL-51: the parent's items, called back after `ms` milliseconds.
    #[plexus_macros::method]
    pub async fn later(&self, parent: Parent<shop::ShopClient>, ms: u64) -> Value {
        tokio::time::sleep(Duration::from_millis(ms)).await;
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
    // Admitted for alice's key, not connected yet: bob asking for it is refused, never pending.
    let b = node(&host, "alice", &kb);
    let refused = b.mounted(Duration::from_secs(10)).await.unwrap_err();
    assert!(refused.contains("name_taken"), "{refused}");
    assert!(host.dyn_.pending_list().is_empty());
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    // Bob asks for alice's name while she is connected: refused before anything is asked of him.
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

/// Review M1: offers are held to a rate per address and per key, an
/// address past its share displaces its own oldest, and a full list makes
/// room from its busiest address — so a few addresses cannot hold first
/// contact shut.
fn limits(o: &mut DynOptions) {
    o.dial_in_pending_max = 3;
    o.dial_in_pending_per_address = 2;
    o.dial_in_pending_age = Duration::from_secs(30);
    o.dial_in_offers_per_minute_per_address = 100;
    o.dial_in_offers_per_minute_per_key = 100;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_past_its_share_displaces_its_own_oldest_offer() {
    let host = host_with(limits).await;
    let mut a = offer_from(&host, 41, "a", "127.0.0.2").await;
    assert_eq!(answered_within(&mut a, 300).await, None, "a waits");
    let mut b = offer_from(&host, 42, "b", "127.0.0.2").await;
    assert_eq!(answered_within(&mut b, 300).await, None, "b waits");
    let mut c = offer_from(&host, 43, "c", "127.0.0.2").await;
    assert_eq!(answered_within(&mut c, 300).await, None, "c waits too: its address's share is taken from its own oldest");
    assert_eq!(kind_of(&answered_within(&mut a, 2000).await).as_deref(), Some("superseded"));
    assert_eq!(pending_names(&host), ["b", "c"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_list_makes_room_from_its_busiest_address() {
    let host = host_with(limits).await;
    let mut a = offer_from(&host, 51, "a", "127.0.0.2").await;
    assert_eq!(answered_within(&mut a, 300).await, None);
    let mut b = offer_from(&host, 52, "b", "127.0.0.2").await;
    assert_eq!(answered_within(&mut b, 300).await, None);
    let mut c = offer_from(&host, 53, "c", "127.0.0.3").await;
    assert_eq!(answered_within(&mut c, 300).await, None);
    // Full (3). A newcomer from a fourth address is not shut out: the busiest address gives its oldest.
    let mut d = offer_from(&host, 54, "d", "127.0.0.4").await;
    assert_eq!(answered_within(&mut d, 300).await, None, "the newcomer waits");
    assert_eq!(kind_of(&answered_within(&mut a, 2000).await).as_deref(), Some("superseded"));
    assert_eq!(pending_names(&host), ["b", "c", "d"]);
    // Spread evenly, one an address: a fifth address is refused, nobody's is taken.
    let mut e = offer_from(&host, 55, "e", "127.0.0.5").await;
    let mut f = offer_from(&host, 56, "f", "127.0.0.6").await;
    let (e, f) = (answered_within(&mut e, 2000).await, answered_within(&mut f, 300).await);
    assert!(kind_of(&e).as_deref() == Some("pending_full") || kind_of(&f).as_deref() == Some("pending_full"), "{e:?} {f:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offers_from_one_address_are_rate_limited() {
    let host = host_with(|o| {
        limits(o);
        o.dial_in_pending_per_address = 10;
        o.dial_in_pending_max = 10;
        o.dial_in_offers_per_minute_per_address = 3;
    })
    .await;
    let mut socks = Vec::new();
    for (i, seed) in [61u8, 62, 63].into_iter().enumerate() {
        let mut ws = offer_from(&host, seed, &format!("n{i}"), "127.0.0.7").await;
        assert_eq!(answered_within(&mut ws, 300).await, None);
        socks.push(ws);
    }
    let mut fourth = offer_from(&host, 64, "n3", "127.0.0.7").await;
    assert_eq!(kind_of(&answered_within(&mut fourth, 2000).await).as_deref(), Some("rate_limited"));
    // Another address is not held to this one's rate.
    let mut other = offer_from(&host, 65, "n4", "127.0.0.8").await;
    assert_eq!(answered_within(&mut other, 300).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_offers_by_one_key_are_rate_limited() {
    let host = host_with(|o| {
        limits(o);
        o.dial_in_offers_per_minute_per_key = 2;
    })
    .await;
    // Each re-offer is a fresh code: the rate bounds how many codes one key may try.
    let mut first = offer_from(&host, 71, "k", "127.0.0.9").await;
    assert_eq!(answered_within(&mut first, 300).await, None);
    let mut second = offer_from(&host, 71, "k", "127.0.0.10").await;
    assert_eq!(answered_within(&mut second, 300).await, None);
    assert_eq!(kind_of(&answered_within(&mut first, 2000).await).as_deref(), Some("superseded"), "one pending a key");
    let mut third = offer_from(&host, 71, "k", "127.0.0.11").await;
    assert_eq!(kind_of(&answered_within(&mut third, 2000).await).as_deref(), Some("rate_limited"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_offer_waits_its_age_no_longer() {
    let host = host_with(|o| {
        limits(o);
        o.dial_in_pending_age = Duration::from_millis(800);
    })
    .await;
    let mut a = offer_from(&host, 81, "a", "127.0.0.12").await;
    assert_eq!(kind_of(&answered_within(&mut a, 3000).await).as_deref(), Some("pending_expired"));
    until("none pending", || host.dyn_.pending_list().is_empty()).await;
    assert!(listed(&host).is_empty());
}

// ------------------------------------------------------------------ review M2, L1

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admit_by_key_is_refused_while_an_offer_with_a_code_waits() {
    let host = host().await;
    let me = plexus_core::plexus::peer_token::PeerKey::from_seed([91; 32]).kid().to_string();
    let mut ws = offer_from(&host, 91, "shop", "127.0.0.13").await;
    assert_eq!(answered_within(&mut ws, 300).await, None);
    let code = host.dyn_.pending_list()[0].code.clone().unwrap();
    // Its key by name and key: refused — the code is how this offer is admitted.
    for args in [json!({ "name": "shop", "key": me }), json!({ "name": "other", "key": me })] {
        let said = admit(&host, args.clone()).await;
        assert_eq!(said[0]["type"], "error", "{args}: {said:?}");
        assert!(said[0]["message"].as_str().unwrap().contains("--code"), "{said:?}");
    }
    assert_eq!(pending_names(&host), ["shop"], "still waiting");
    // By its code: admitted.
    let said = admit(&host, json!({ "code": code })).await;
    assert_eq!(said[0]["type"], "admitted", "{said:?}");
}

/// Review R2-2: a stranger's coded offer squatting a name does not stop the
/// operator admitting the honest key for it ahead of time — the way in that
/// flooding cannot block; the squatter's offer is let go `name_taken`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_squatters_coded_offer_does_not_block_admitting_the_honest_key_ahead() {
    let dir = tempfile::tempdir().unwrap();
    let (k, honest) = key(dir.path(), "shop", 93);
    let host = host().await;
    let mut squat = offer_from(&host, 94, "shop", "127.0.0.14").await;
    assert_eq!(answered_within(&mut squat, 300).await, None, "the squatter waits");
    let said = admit(&host, json!({ "name": "shop", "key": honest })).await;
    assert_eq!(said[0]["type"], "admitted", "{said:?}");
    assert_eq!(kind_of(&answered_within(&mut squat, 2000).await).as_deref(), Some("name_taken"));
    assert!(host.dyn_.pending_list().is_empty());
    let a = node(&host, "shop", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
}

/// Review L1: an operator refusing a key while its node is between the
/// check of its schema and its place in the table — the mount is refused,
/// and nothing is left in dyn's table or in the dial-in table under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refuse_racing_a_mount_leaves_nothing_mounted() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 92);
    let (at_vet, vetted) = std::sync::mpsc::channel::<()>();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let wait = Arc::new(Mutex::new(wait));
    let host = host_with(move |o| {
        o.dial_in_vetted = Some(plexus_dyn::VettedHook(Arc::new(move |_name: &str| {
            let _ = at_vet.send(());
            let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(10));
        })));
    })
    .await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    tokio::task::spawn_blocking(move || vetted.recv_timeout(Duration::from_secs(10)).expect("the mount reached its vet")).await.unwrap();
    // Between vet and the table: the operator refuses the key.
    let said = call(&host, ADMIN, "dyn.refuse", json!({ "key": alice })).await.unwrap();
    assert_eq!(said[0]["type"], "key_refused", "{said:?}");
    go.send(()).unwrap();
    let refused = a.mounted(Duration::from_secs(10)).await;
    assert!(refused.is_err(), "mounted past a refusal: {refused:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(listed(&host).is_empty(), "{:?}", listed(&host));
    assert!(host.door.names().is_empty(), "left in the dial-in table: {:?}", host.door.names());
    assert!(call(&host, ADMIN, "dyn.peer.alice.hello", json!({ "name": "x" })).await.is_err());
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

/// The same graft served as a dialed WebSocket peer (`dyn.connect`), on a
/// connection proven at its upgrade, trusting dyn's dial key.
async fn dialed_restock(host: &Host) -> u16 {
    let port = port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let upgrade = Arc::new(plexus_core::plexus::remote_child::KeyedUpgrade::new([format!("ws://127.0.0.1:{port}")]));
    let trusted = vec![host.dyn_.dial_principal().unwrap()];
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (upgrade, trusted) = (Arc::clone(&upgrade), trusted.clone());
            tokio::spawn(async move {
                let _ = plexus_core::plexus::remote_child::serve_child_ws(Restock, tcp, &upgrade, trusted, None, None).await;
            });
        }
    });
    port
}

/// What `path`'s `low` and `sneak` give each caller: the rules of a peer's
/// calls back, as a table to compare.
async fn calls_back(host: &Host, path: &str) -> Vec<(String, bool)> {
    let capped = AuthContext::for_principal(&ADMIN.parse().unwrap(), "s1", vec![], json!({ plexus_auth_core::grants::CEILING_KEY: ["viewer@*"] }));
    let mut out = Vec::new();
    for (label, ctx, method) in [
        ("admin sneak", who(ADMIN), "sneak"),
        ("viewer low", who(VIEWER), "low"),
        ("admin ceilinged to viewer low", capped, "low"),
        ("admin low", who(ADMIN), "low"),
    ] {
        let reached = match host.service.route(&format!("{path}.{method}"), json!({}), Some(&ctx)).await {
            Err(_) => false,
            Ok(s) => {
                let items: Vec<PlexusStreamItem> = s.collect().await;
                let said = format!("{items:?}");
                said.contains("flour") || said.contains("reached")
            }
        };
        out.push((label.to_string(), reached));
    }
    out
}

/// KEEL-19's rules for a peer's calls back hold for a dial-in peer as for a
/// dialed one: never past its needs, even under an admin's call; each as the
/// caller of the call it serves, within that caller's reach and ceiling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_in_peers_calls_back_keep_the_rules_of_a_dialed_peers() {
    let dir = tempfile::tempdir().unwrap();
    let (k, alice) = key(dir.path(), "alice", 16);
    let host = host().await;
    admit(&host, json!({ "name": "alice", "key": alice })).await;
    let a = node(&host, "alice", &k);
    a.mounted(Duration::from_secs(10)).await.unwrap();
    let port = dialed_restock(&host).await;
    let got = call(&host, ADMIN, "dyn.connect", json!({ "name": "far", "url": format!("ws://127.0.0.1:{port}") })).await.unwrap();
    assert_eq!(got[0]["type"], "connected", "{got:?}");
    for peer in ["alice", "far"] {
        call(&host, ADMIN, "dyn.consent", json!({ "peer": peer, "needs": ["shop.items"], "callers": ["viewer"] })).await.unwrap();
    }
    let dialed = calls_back(&host, "dyn.peer.far").await;
    let dialed_in = calls_back(&host, "dyn.peer.alice").await;
    assert_eq!(dialed_in, dialed, "a dial-in peer's calls back are held as a dialed peer's");
    // And the rules themselves: past its needs never; a viewer's call back is the viewer's.
    assert_eq!(dialed_in[0], ("admin sneak".to_string(), false));
    assert_eq!(dialed_in[1], ("viewer low".to_string(), false));
    assert_eq!(dialed_in[3], ("admin low".to_string(), true));
    assert_eq!(dialed_in[2], ("admin ceilinged to viewer low".to_string(), false), "the session's ceiling holds on the call back");
    // A sign-in that ends while the call is open (AUTH-11) ends its call
    // back: admitted at the call, refused after its `expires_at`.
    for peer in ["alice", "far"] {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let ending = AuthContext::for_principal(&ADMIN.parse().unwrap(), "ending", vec![], json!({ plexus_auth_core::auth::EXPIRES_AT_KEY: now + 2 }));
        let s = host.service.route(&format!("dyn.peer.{peer}.later"), json!({ "ms": 3100 }), Some(&ending)).await.expect("admitted while it stands");
        let said = format!("{:?}", s.collect::<Vec<PlexusStreamItem>>().await);
        assert!(!said.contains("flour") && said.contains("unauthenticated"), "{peer}: the call back ran on a sign-in that had ended: {said}");
    }
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

/// A socket by hand.
type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// A raw socket signed in as `seed`'s key (or anonymous), from 127.0.0.1.
async fn raw(host: &Host, seed: Option<u8>) -> Ws {
    raw_from(host, seed, "127.0.0.1").await
}

/// A raw socket signed in as `seed`'s key (or anonymous), from the loopback address `src`.
async fn raw_from(host: &Host, seed: Option<u8>, src: &str) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = host.url.as_str().into_client_request().unwrap();
    if let Some(seed) = seed {
        let k = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]);
        let bearer = plexus_core::plexus::remote_child::dial_proof(&k, &host.url);
        req.headers_mut().insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    }
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(format!("{src}:0").parse().unwrap()).unwrap();
    let port: u16 = host.url.trim_start_matches("ws://127.0.0.1:").trim_end_matches("/ws").parse().unwrap();
    let tcp = sock.connect(([127, 0, 0, 1], port).into()).await.unwrap();
    tokio_tungstenite::client_async(req, tcp).await.unwrap().0
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// The next frame whose `id` is `id`, within `secs`.
async fn answer_to(ws: &mut Ws, id: &str, secs: u64) -> Value {
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
async fn info(ws: &mut Ws, node_nonce: &str) -> String {
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
    // A nonce revealed that is not the one committed to: refused.
    let mut ws = raw(&host, Some(21)).await;
    let _ = info(&mut ws, "nn").await;
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": "x", "mount": "x", "pairing_nonce": "other" } })).await;
    let a = answer_to(&mut ws, "o", 5).await;
    assert_eq!(a.pointer("/error/data/error_kind").and_then(Value::as_str), Some("pairing_mismatch"), "{a}");
    assert!(listed(&host).is_empty() && host.dyn_.pending_list().is_empty());
}

/// A node that signs its offer properly and then never answers.
async fn silent(host: &Host, seed: u8, name: &str) -> (Ws, Value) {
    let ws = offer_from(host, seed, name, "127.0.0.1").await;
    let me = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]).kid().to_string();
    (ws, json!(me))
}

/// A properly signed offer of `name` by `seed`'s key from `src`, sent; the
/// node answers nothing more.
async fn offer_from(host: &Host, seed: u8, name: &str, src: &str) -> Ws {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let me = plexus_core::plexus::peer_token::PeerKey::from_seed([seed; 32]).kid().to_string();
    let mut ws = raw_from(host, Some(seed), src).await;
    let host_nonce = info(&mut ws, "nn").await;
    let input = plexus_core::plexus::remote_child::possession_input(host.door.host_key(), &me, "nn", &host_nonce, "host", name);
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(input.as_bytes()).to_bytes());
    send(&mut ws, json!({ "jsonrpc": "2.0", "id": "o", "method": "host.offer", "params": { "namespace": name, "mount": name, "pairing_nonce": "nn", "possession": sig } })).await;
    ws
}

/// Whether the offer on `ws` is answered within `ms`: `Some(answer)`, or
/// `None` (still waiting, pending).
async fn answered_within(ws: &mut Ws, ms: u64) -> Option<Value> {
    tokio::time::timeout(Duration::from_millis(ms), async {
        loop {
            let Some(Ok(Message::Text(t))) = ws.next().await else { return json!({ "closed": true }) };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v.get("method").is_none() && v["id"] == json!("o") {
                return v;
            }
        }
    })
    .await
    .ok()
}

fn kind_of(answer: &Option<Value>) -> Option<String> {
    answer.as_ref().and_then(|a| a.pointer("/error/data/error_kind")).and_then(Value::as_str).map(str::to_string)
}

fn pending_names(host: &Host) -> Vec<String> {
    let mut n: Vec<String> = host.dyn_.pending_list().into_iter().map(|p| p.name).collect();
    n.sort();
    n
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
