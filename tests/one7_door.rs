//! ONE-7 — **dyn's door, and one peer's**, over real keyed hops.
//!
//! The host serves `dyn`. Two peers, `shop` and `till`, are separate
//! services on loopback WebSockets, each proving its key and taking a call
//! only by the token `dyn` mints for it. The people:
//!
//! - the **owner** holds `admin` on `*`;
//! - the **operator** holds `operator` on `/dyn` — dyn's own methods;
//! - the **shopkeeper** holds `operator` on `/dyn.peer.shop.*` — one peer;
//! - the **gardener** holds `operator` on `/dyn.*` — dyn and every peer;
//! - the **kiln operator** holds `operator` on the data scope `KILN`;
//! - the **viewer** holds `viewer` on `KILN`, and consent names `viewer`
//!   among the shop's callers.
//!
//! - the **vaultkeeper** holds `operator` on `/dyn.peer.vault.*` — the
//!   in-process peer `vault` (attached as the bridge is);
//! - the **shop admin** holds `admin` on `/dyn.peer.shop.*` and on
//!   `/dyn.peer.vault.*`;
//! - the **restocker** holds `restocker` — a role listing the peers' own
//!   `dyn.peer.shop.restock` and `dyn.peer.vault.wipe` — on
//!   `/dyn.peer.shop.*` and `/dyn.peer.vault.*`.
//!
//! `operator` lists `dyn.connect`, `dyn.disconnect` and the peer slot's
//! grant `dyn.{peer}`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef, CEILING_KEY};
use plexus_core::plexus::peer_token::{Jwks, PeerKey, Verifier};
use plexus_core::plexus::remote_child::{ChildPeer, KeyedUpgrade, ServeChild};
use plexus_core::plexus::{AuthContext, PlexusStream, PlexusStreamItem};
use plexus_core::DynamicHub;
use plexus_dyn::{DynActivation, DynClient, DynOptions};
use serde_json::{json, Value};

const OWNER: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OPERATOR: &str = "key:0101010101010101010101010101010101010101010101010101010101010101";
const SHOPKEEPER: &str = "key:0505050505050505050505050505050505050505050505050505050505050505";
const GARDENER: &str = "key:0202020202020202020202020202020202020202020202020202020202020202";
const KILN_OPERATOR: &str = "key:0404040404040404040404040404040404040404040404040404040404040404";
const KILN_ADMIN: &str = "key:0303030303030303030303030303030303030303030303030303030303030303";
const VIEWER: &str = "key:0707070707070707070707070707070707070707070707070707070707070707";
const CLERK: &str = "key:0808080808080808080808080808080808080808080808080808080808080808";
const VAULTKEEPER: &str = "key:0909090909090909090909090909090909090909090909090909090909090909";
const SHOP_ADMIN: &str = "key:0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
const RESTOCKER: &str = "key:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

// ------------------------------------------------------------------ the peers

#[derive(Clone)]
pub struct ShopActivation;

/// A shop: says what reached it, and asks the till through its host.
#[plexus_macros::activation(parent = DynClient)]
impl ShopActivation {
    /// What this call reached the shop as: its caller, its reach, its token's scope.
    #[plexus_macros::method]
    pub async fn stock(&self) -> Value {
        reached()
    }

    /// Restock: acts on the whole shop.
    #[plexus_macros::method(everywhere)]
    pub async fn restock(&self) -> Value {
        json!("restocked")
    }

    /// The till's count, asked through the host as this call's caller.
    #[plexus_macros::method(uses("dyn.peer.till.count"))]
    pub async fn ask_till(&self) -> Value {
        up("dyn.peer.till", "count").await
    }
}

#[derive(Clone)]
pub struct TillActivation;

/// A till.
#[plexus_macros::activation]
impl TillActivation {
    /// How many sales.
    #[plexus_macros::method]
    pub async fn count(&self) -> Value {
        json!(3)
    }
}

#[derive(Clone)]
pub struct VaultActivation;

/// A vault served in process, as the bridge is (`dyn.attach`).
#[plexus_macros::activation(namespace = "vault", version = "1.0.0")]
impl VaultActivation {
    /// An ordinary method.
    #[plexus_macros::method]
    pub async fn look(&self) -> Value {
        json!("looked")
    }

    /// Acts on the whole vault — as the bridge's `add` does on the bridge.
    #[plexus_macros::method(everywhere)]
    pub async fn wipe(&self) -> Value {
        json!("wiped")
    }
}

#[derive(Clone)]
pub struct ClerkActivation {
    dyn_: DynActivation,
}

/// A clerk of the host's own, who looks into the shop by hand.
#[plexus_macros::activation(namespace = "clerk", version = "1.0.0")]
impl ClerkActivation {
    /// Acts on the whole clerk: and, inside, calls the shop itself — not a
    /// call any gate admitted at the shop's door.
    #[plexus_macros::method(everywhere)]
    pub async fn peek(&self) -> Value {
        let auth = plexus_core::call::caller().ok().and_then(|c| c.auth().cloned());
        let Ok(shop) = self.dyn_.get("shop").await else { return json!({ "refused": "no shop" }) };
        let opened = plexus_core::plexus::Activation::call(&shop, "stock", json!({}), auth.as_ref(), None).await;
        items(opened).await.into_iter().next().unwrap_or(Value::Null)
    }
}

/// What the far side holds for the call it serves.
fn reached() -> Value {
    use base64::Engine as _;
    let Ok(caller) = plexus_core::call::caller() else { return json!({ "no_caller": true }) };
    let reach = caller.reach();
    let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
    let token = plexus_core::call::hop().ok().and_then(|h| h.token).unwrap_or_default();
    let claims: Value = token
        .split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    json!({
        "caller": caller.auth().and_then(|a| a.principal()).map(|p| p.to_string()),
        // Review M1: whether this call's door would run the shop's own
        // whole-activation method here — the hop said the door is the
        // method's own (`limit.door_own`), or it holds `*`.
        "whole": plexus_core::call::admits_everywhere("shop.stock").is_ok(),
        "activation": reach.holds_activation(),
        "everywhere": reach.is_everywhere(),
        "held_on": held,
        "token_scope": claims["scope"],
    })
}

/// Call the host back, under the call being served: the first answer, or the refusal.
async fn up(path: &str, name: &str) -> Value {
    use plexus_client::{MethodRef, StreamItem, Transport};
    let Ok(t) = plexus_core::plexus::remote_child::host() else { return json!({ "no_host": true }) };
    let items: Vec<_> = t.call(MethodRef::named(path.to_string(), name.to_string()), json!({})).collect().await;
    match items.into_iter().next() {
        Some(Ok(StreamItem::Data { content, .. })) => content,
        Some(Ok(StreamItem::Error { message, .. })) => json!({ "refused": message }),
        other => json!({ "refused": format!("{other:?}") }),
    }
}

// ------------------------------------------------------------------ the host

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// A ticket lives in its shortcode: `KILN-3` → `[KILN, *]`.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, t: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::named(t.split('-').next().unwrap_or(t)), ScopeRef::Everywhere])
    }
}

struct World {
    host: Arc<DynamicHub>,
    _dyn: DynActivation,
    peers: Vec<tokio::task::JoinHandle<()>>,
    _data: tempfile::TempDir,
}

impl Drop for World {
    fn drop(&mut self) {
        for p in &self.peers {
            p.abort();
        }
    }
}

/// The host, `shop` and `till` connected by the owner, the shop's need of
/// the till and its callers consented.
async fn world() -> World {
    world_minting(true).await
}

/// [`world`]; `tokens` false: `dyn` mints none, and the peers verify none —
/// a call back is held by its ceiling alone.
async fn world_minting(tokens: bool) -> World {
    let data = tempfile::tempdir().unwrap();
    let opts = DynOptions { data_dir: data.path().join("dyn"), dendrite: data.path().join("no-dendrite"), liveness: Duration::from_secs(3600), tokens, ..DynOptions::default() };
    let dyn_ = DynActivation::new(opts);
    let mut lists: Vec<(String, Vec<String>)> = DynamicHub::new("host").register(dyn_.clone()).declared_roles().into_iter().collect();
    lists.push(("operator".into(), vec!["dyn.connect".into(), "dyn.disconnect".into(), "dyn.{peer}".into(), "clerk.peek".into()]));
    lists.push(("restocker".into(), vec!["dyn.peer.shop.restock".into(), "dyn.peer.vault.wipe".into()]));
    let roles = RoleTable::from_lists(lists.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (who, role, scope) in [
        (OWNER, "admin", "*"),
        (OPERATOR, "operator", "/dyn"),
        (SHOPKEEPER, "operator", "/dyn.peer.shop.*"),
        (GARDENER, "operator", "/dyn.*"),
        (KILN_OPERATOR, "operator", "KILN"),
        (KILN_ADMIN, "admin", "KILN"),
        (VIEWER, "viewer", "KILN"),
        (CLERK, "operator", "/clerk"),
        (VAULTKEEPER, "operator", "/dyn.peer.vault.*"),
        (SHOP_ADMIN, "admin", "/dyn.peer.shop.*"),
        (SHOP_ADMIN, "admin", "/dyn.peer.vault.*"),
        (RESTOCKER, "restocker", "/dyn.peer.shop.*"),
        (RESTOCKER, "restocker", "/dyn.peer.vault.*"),
    ] {
        members.0.lock().unwrap().push(Membership { principal: who.parse().unwrap(), role: plexus_auth_core::RoleName::new(role), scope: ScopeRef::parse(scope) });
    }
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Shortcodes)));
    let clerk = ClerkActivation { dyn_: dyn_.clone() };
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).register(clerk).with_gate(gate));
    dyn_.start(&host).await.unwrap();
    dyn_.attach("vault", "test", "b1", Arc::new(VaultActivation), false);
    let jwks = dyn_.jwk_set();
    let trusted = vec![dyn_.dial_principal().expect("dyn dials with a key")];
    let jwks = tokens.then_some(jwks);
    let (shop_port, shop) = keyed_peer(ShopActivation, jwks.as_ref(), trusted.clone()).await;
    let (till_port, till) = keyed_peer(TillActivation, jwks.as_ref(), trusted).await;
    let w = World { host, _dyn: dyn_, peers: vec![shop, till], _data: data };
    for (name, port) in [("shop", shop_port), ("till", till_port)] {
        let got = w.call(OWNER, "dyn.connect", json!({ "name": name, "url": format!("ws://127.0.0.1:{port}") })).await;
        assert_eq!(got[0]["type"], "connected", "{got:?}");
    }
    let c = w.call(OWNER, "dyn.consent", json!({ "peer": "shop", "needs": ["dyn.peer.till.count"], "callers": ["viewer"] })).await;
    assert_eq!(c[0]["type"], "consented", "{c:?}");
    w
}

/// A peer on a loopback WebSocket of its own: it proves its key at the
/// upgrade, trusts `dyn`'s dial key to act for others, and — given `dyn`'s
/// JWKS — takes a call only by a token `dyn` minted for it.
async fn keyed_peer<A>(activation: A, jwks: Option<&Jwks>, trusted: Vec<String>) -> (u16, tokio::task::JoinHandle<()>)
where
    A: plexus_core::plexus::Activation + Clone + Send + Sync + 'static,
{
    let key = PeerKey::generate();
    let tokens = jwks.map(|j| Arc::new(Verifier::new(key.kid(), j).unwrap()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upgrade = Arc::new(KeyedUpgrade::new([format!("ws://127.0.0.1:{port}")]));
    let opts = ServeChild { key: Some(key), tokens, peer: ChildPeer::connection("(proven at the upgrade)", trusted.clone()) };
    let task = tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let (activation, upgrade, trusted, key, tokens) = (activation.clone(), Arc::clone(&upgrade), trusted.clone(), opts.key.clone(), opts.tokens.clone());
            conns.spawn(async move {
                let _ = plexus_core::plexus::remote_child::serve_child_ws(activation, tcp, &upgrade, trusted, key, tokens).await;
            });
        }
    });
    (port, task)
}

impl World {
    async fn call(&self, who: &str, method: &str, params: Value) -> Vec<Value> {
        let auth = AuthContext::for_principal(&who.parse().unwrap(), "s1", vec![], Value::Null);
        self.call_as(&auth, method, params).await
    }

    async fn call_as(&self, auth: &AuthContext, method: &str, params: Value) -> Vec<Value> {
        items(self.host.route(method, params, Some(auth)).await).await
    }

    /// The owner, its session capped by `ceiling`.
    async fn owner_capped(&self, ceiling: &[&str], method: &str) -> Vec<Value> {
        let auth = AuthContext::for_principal(&OWNER.parse().unwrap(), "capped", vec![], json!({ CEILING_KEY: ceiling }));
        self.call_as(&auth, method, json!({})).await
    }
}

async fn items(r: Result<PlexusStream, plexus_core::plexus::PlexusError>) -> Vec<Value> {
    match r {
        Err(e) => vec![json!({ "refused": format!("{e}") })],
        Ok(stream) => stream
            .filter_map(|i| async move {
                match i {
                    PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                    PlexusStreamItem::Error { message, .. } => Some(json!({ "refused": message })),
                    _ => None,
                }
            })
            .collect()
            .await,
    }
}

/// Refused, naming `grant`.
fn refused(got: &[Value], grant: &str) -> bool {
    got.len() == 1 && got[0]["refused"].as_str().is_some_and(|m| m.contains(grant))
}

// ------------------------------------------------------------------ the rows

/// KEEL-31 kept: dyn's whole-activation methods are the operator's at dyn's
/// door, never an admin's of a data scope.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_of_dyn_connects_and_an_admin_of_a_data_scope_does_not() {
    let w = world().await;
    let gone = w.call(OPERATOR, "dyn.disconnect", json!({ "name": "till" })).await;
    assert_eq!(gone[0]["type"], "disconnected", "{gone:?}");
    let refused_connect = w.call(KILN_ADMIN, "dyn.connect", json!({ "name": "x", "url": "ws://127.0.0.1:1" })).await;
    assert!(refused(&refused_connect, "dyn.connect"), "{refused_connect:?}");
    // `/dyn` is dyn's own methods: no peer through it.
    assert!(refused(&w.call(OPERATOR, "dyn.peer.shop.stock", json!({})).await, "dyn.{peer}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_of_one_peer_reaches_it_and_is_admitted_at_its_far_side() {
    let w = world().await;
    let got = w.call(SHOPKEEPER, "dyn.peer.shop.stock", json!({})).await;
    assert_eq!(
        got[0],
        json!({ "caller": SHOPKEEPER, "whole": false, "activation": true, "everywhere": false, "held_on": [], "token_scope": "shop.stock@/shop.stock" }),
        "the far side holds the door of this call alone, and no data — a slot's door, not the method's own: {got:?}"
    );
    // Review M1 (flipped: until this round the shopkeeper restocked): the
    // shop's whole-activation method is not the slot grant's.
    assert!(refused(&w.call(SHOPKEEPER, "dyn.peer.shop.restock", json!({})).await, "shop.restock"));
}

/// Review M1, the reviewer's three probes: the slot's grant `dyn.{peer}` at
/// a peer's address — on the peer, on everything of dyn, a session capped
/// to the peer or to the very method — runs no whole-activation method of
/// the peer: not the in-process vault's `wipe` (the bridge's shape), not
/// the remote shop's `restock`. Their ordinary methods it does.
#[tokio::test(flavor = "multi_thread")]
async fn the_slot_grant_at_a_peers_address_runs_no_whole_activation_method() {
    let w = world().await;
    for who in [VAULTKEEPER, GARDENER] {
        let got = w.call(who, "dyn.peer.vault.wipe", json!({})).await;
        assert!(refused(&got, "vault.wipe"), "{who}: {got:?}");
        assert_eq!(w.call(who, "dyn.peer.vault.look", json!({})).await, [json!("looked")], "{who}");
    }
    for cap in ["operator@/dyn.peer.vault.*", "operator@/dyn.peer.vault.wipe"] {
        let got = w.owner_capped(&[cap], "dyn.peer.vault.wipe").await;
        assert!(refused(&got, "vault.wipe"), "{cap}: {got:?}");
    }
    assert_eq!(w.owner_capped(&["operator@/dyn.peer.vault.*"], "dyn.peer.vault.look").await, [json!("looked")]);
    for who in [SHOPKEEPER, GARDENER] {
        assert!(refused(&w.call(who, "dyn.peer.shop.restock", json!({})).await, "shop.restock"), "{who}");
    }
    assert!(refused(&w.owner_capped(&["operator@/dyn.peer.shop.*"], "dyn.peer.shop.restock").await, "shop.restock"));
}

/// Review M1: the method's own grant at the peer's address runs it — admin
/// there, or a role listing the peer's method; in process, and across the
/// hop, where the far side is told the door is the method's own
/// (`limit.door_own`) and its own backstop runs it. Not at another peer.
#[tokio::test(flavor = "multi_thread")]
async fn the_methods_own_grant_at_a_peers_address_runs_it() {
    let w = world().await;
    for who in [SHOP_ADMIN, RESTOCKER] {
        assert_eq!(w.call(who, "dyn.peer.vault.wipe", json!({})).await, [json!("wiped")], "{who}");
        assert_eq!(w.call(who, "dyn.peer.shop.restock", json!({})).await, [json!("restocked")], "{who}");
        assert!(refused(&w.call(who, "dyn.peer.till.count", json!({})).await, "dyn.{peer}"), "{who}");
    }
    assert_eq!(w.owner_capped(&["admin@/dyn.peer.vault.*"], "dyn.peer.vault.wipe").await, [json!("wiped")]);
    assert_eq!(w.owner_capped(&["admin@/dyn.*"], "dyn.peer.shop.restock").await, [json!("restocked")]);
    // The far side is told: the shop admin's door is the method's own; the shopkeeper's, the slot's.
    let got = w.call(SHOP_ADMIN, "dyn.peer.shop.stock", json!({})).await;
    assert_eq!((got[0]["whole"].clone(), got[0]["activation"].clone(), got[0]["held_on"].clone()), (json!(true), json!(true), json!([])), "{got:?}");
    // The restocker's role lists `restock` alone: the shop's other methods are not its.
    assert!(refused(&w.call(RESTOCKER, "dyn.peer.shop.stock", json!({})).await, "dyn.{peer}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shopkeeper_is_refused_another_peer_and_dyn_connect() {
    let w = world().await;
    assert!(refused(&w.call(SHOPKEEPER, "dyn.peer.till.count", json!({})).await, "dyn.{peer}"));
    assert!(refused(&w.call(SHOPKEEPER, "dyn.connect", json!({ "name": "x", "url": "ws://127.0.0.1:1" })).await, "dyn.connect"));
    // The gardener (`/dyn.*`) reaches each.
    assert_eq!(w.call(GARDENER, "dyn.peer.till.count", json!({})).await, [json!(3)]);
}

/// KEEL-44 closed for the slot grant: a role listing `dyn.{peer}` on a data
/// scope reaches no peer. (Until plexus-core 0.11.4 the kiln operator was
/// admitted to every peer, the peer told `held_on [KILN]`.)
#[tokio::test(flavor = "multi_thread")]
async fn a_data_scope_reaches_no_peer_through_the_slot() {
    let w = world().await;
    for peer in ["shop", "till"] {
        let got = w.call(KILN_OPERATOR, &format!("dyn.peer.{peer}.stock"), json!({})).await;
        assert!(refused(&got, "dyn.{peer}"), "{peer}: {got:?}");
    }
}

/// Not closed here, said so: `admin` lists every grant, a peer method's
/// literal path among them (what consent's `callers` give), and a literal
/// path is decided as before. An admin of a data scope reaches a peer's
/// ordinary method — as a data holder, no door — and not its
/// whole-activation one.
#[tokio::test(flavor = "multi_thread")]
async fn an_admin_of_a_data_scope_still_reaches_a_peer_by_its_literal_path() {
    let w = world().await;
    let got = w.call(KILN_ADMIN, "dyn.peer.shop.stock", json!({})).await;
    assert_eq!((got[0]["activation"].clone(), got[0]["held_on"].clone()), (json!(false), json!(["KILN"])), "{got:?}");
    assert!(refused(&w.call(KILN_ADMIN, "dyn.peer.shop.restock", json!({})).await, "shop.restock"));
}

/// The shop calls the till back as its caller: the owner reaches it; one
/// who holds the shop's door alone — or every peer's — does not, through
/// the shop: the call back holds that one door and no more.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_back_runs_under_no_more_than_the_call_held() {
    let w = world().await;
    assert_eq!(w.call(OWNER, "dyn.peer.shop.ask_till", json!({})).await, [json!(3)]);
    for who in [SHOPKEEPER, GARDENER] {
        let got = w.call(who, "dyn.peer.shop.ask_till", json!({})).await;
        assert!(got[0]["refused"].as_str().is_some_and(|m| m.contains("dyn.peer.till.count")), "{who}: {got:?}");
    }
}

/// The same, with no token on either side: the call back is held by the
/// ceiling it is made under — the shop's door for its own grant, and the
/// data the caller holds the grant on (none) — and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_back_is_held_by_the_door_it_was_made_under() {
    let w = world_minting(false).await;
    assert_eq!(w.call(OWNER, "dyn.peer.shop.ask_till", json!({})).await, [json!(3)]);
    let got = w.call(SHOPKEEPER, "dyn.peer.shop.stock", json!({})).await;
    assert_eq!((got[0]["activation"].clone(), got[0]["held_on"].clone()), (json!(true), json!([])), "{got:?}");
    for who in [SHOPKEEPER, GARDENER] {
        let got = w.call(who, "dyn.peer.shop.ask_till", json!({})).await;
        assert!(got[0]["refused"].as_str().is_some_and(|m| m.contains("dyn.{peer}")), "{who}: {got:?}");
    }
}

/// KEEL-51: a session capped to one peer's door stays capped through the
/// hop and back; one capped to a data scope opens no peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_capped_session_stays_capped_through_the_hop_and_back() {
    let w = world().await;
    let shop_only = ["operator@/dyn.peer.shop.*"];
    let got = w.owner_capped(&shop_only, "dyn.peer.shop.stock").await;
    assert_eq!((got[0]["activation"].clone(), got[0]["held_on"].clone()), (json!(true), json!([])), "the owner's `*` capped to the shop's door: {got:?}");
    assert!(refused(&w.owner_capped(&shop_only, "dyn.peer.till.count").await, "dyn.{peer}"));
    assert!(refused(&w.owner_capped(&shop_only, "dyn.connect").await, "dyn.connect"));
    let back = w.owner_capped(&shop_only, "dyn.peer.shop.ask_till").await;
    assert!(back[0]["refused"].as_str().is_some_and(|m| m.contains("dyn.peer.till.count")), "{back:?}");
    assert!(refused(&w.owner_capped(&["operator@KILN"], "dyn.peer.shop.stock").await, "dyn.{peer}"));
}

/// Consent's `callers` work as they did: a viewer of a data scope, named
/// among the shop's callers, calls its methods (as a data holder: the shop
/// told `held_on [KILN]`, no door) and reads its schema (GAMMA-11).
#[tokio::test(flavor = "multi_thread")]
async fn a_consented_viewer_still_calls_the_peer_and_reads_its_schema() {
    let w = world().await;
    let got = w.call(VIEWER, "dyn.peer.shop.stock", json!({})).await;
    assert_eq!((got[0]["activation"].clone(), got[0]["held_on"].clone()), (json!(false), json!(["KILN"])), "{got:?}");
    let schema = w.call(VIEWER, "dyn.peer.shop.schema", json!({})).await;
    assert!(schema[0]["methods"].as_array().is_some_and(|m| m.iter().any(|m| m["name"] == "stock")), "{schema:?}");
    // And the shopkeeper reads the schema of the peer it may call.
    let schema = w.call(SHOPKEEPER, "dyn.peer.shop.schema", json!({})).await;
    assert!(schema[0]["methods"].as_array().is_some_and(|m| m.iter().any(|m| m["name"] == "stock")), "{schema:?}");
    assert!(w.call(KILN_OPERATOR, "dyn.peer.shop.schema", json!({})).await[0]["refused"].is_string());
}

/// A door is one call's: the clerk is admitted at the clerk's door, and a
/// call its method makes into the shop by hand carries no door across — the
/// shop, verifying, refuses it (nothing held for it), where a door would
/// have let it in.
#[tokio::test(flavor = "multi_thread")]
async fn a_door_does_not_cross_for_a_call_the_gate_did_not_admit_at_it() {
    let w = world().await;
    let got = w.call(CLERK, "clerk.peek", json!({})).await;
    assert!(got[0]["refused"].as_str().is_some_and(|m| m.contains("does not hold")), "{got:?}");
    assert!(refused(&w.call(CLERK, "dyn.peer.shop.stock", json!({})).await, "dyn.{peer}"));
}
