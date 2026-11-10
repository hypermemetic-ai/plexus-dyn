//! KEEL-31 (third pass): consent's `callers` hand a role every method of a
//! peer — but none the peer's schema marks `everywhere`. Before it, a role
//! held on `*` (a viewer of the whole service) was handed the peer's
//! whole-service method by consent, and the gate's `check_everywhere`
//! admitted it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_core::plexus::{AuthContext, PlexusError, PlexusStreamItem};
use plexus_core::DynamicHub;
use plexus_dyn::{DynActivation, DynOptions};
use serde_json::{json, Value};

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// `viewer` on `*`: a role consent names.
const VIEWER: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Clone)]
struct VaultActivation;

/// A far service with an ordinary method and a whole-service one.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0")]
impl VaultActivation {
    /// Read it.
    #[plexus_macros::method]
    async fn read(&self) -> Value {
        json!("read")
    }

    /// Rotate the whole service's key.
    #[plexus_macros::method(everywhere)]
    async fn rotate(&self) -> Value {
        json!("rotated")
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

async fn far() -> (u16, jsonrpsee::server::ServerHandle) {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(DynamicHub::new("far").register(VaultActivation))).unwrap();
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    (port, server.start(module))
}

async fn answer(host: &DynamicHub, caller: &str, method: &str) -> Result<Value, String> {
    let stream = host.route(method, json!({}), Some(&who(caller))).await.map_err(|e: PlexusError| e.to_string())?;
    let items: Vec<_> = stream.collect().await;
    items
        .into_iter()
        .find_map(|i| match i {
            PlexusStreamItem::Data { content, .. } => Some(Ok(content.into_value())),
            PlexusStreamItem::Error { message, .. } => Some(Err(message)),
            _ => None,
        })
        .unwrap_or_else(|| Err("nothing answered".into()))
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_hands_a_role_no_everywhere_method() {
    let (port, _far) = far().await;
    let data = tempfile::tempdir().unwrap();
    let dyn_ = DynActivation::new(DynOptions {
        data_dir: data.path().join("dyn"),
        dendrite: data.path().join("no-dendrite"),
        liveness: Duration::from_secs(3600),
        ..DynOptions::default()
    });
    let declared = DynamicHub::new("host").register(dyn_.clone()).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (p, r) in [(ADMIN, "admin"), (VIEWER, "viewer")] {
        members.0.lock().unwrap().push(Membership { principal: p.parse().unwrap(), role: plexus_auth_core::RoleName::new(r), scope: ScopeRef::Everywhere });
    }
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Everywhere)));
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).with_gate(gate));
    dyn_.start(&host).await.unwrap();

    let connected = host.route("dyn.connect", json!({ "name": "w", "url": format!("ws://127.0.0.1:{port}") }), Some(&who(ADMIN))).await.unwrap();
    let got: Vec<_> = connected.collect().await;
    assert!(format!("{got:?}").contains("connected"), "{got:?}");
    let consented = host.route("dyn.consent", json!({ "peer": "w", "callers": ["viewer"] }), Some(&who(ADMIN))).await.unwrap();
    let got: Vec<_> = consented.collect().await;
    assert!(format!("{got:?}").contains("consented"), "{got:?}");

    // The ordinary method: consent's.
    assert_eq!(answer(&host, VIEWER, "dyn.peer.w.vault.read").await, Ok(json!("read")));
    // The whole-service one: not consent's to give.
    let rotate = answer(&host, VIEWER, "dyn.peer.w.vault.rotate").await;
    assert!(rotate.is_err(), "a viewer on * reached the peer's everywhere method through consent: {rotate:?}");
    // The admin still reaches it.
    assert_eq!(answer(&host, ADMIN, "dyn.peer.w.vault.rotate").await, Ok(json!("rotated")));
}
