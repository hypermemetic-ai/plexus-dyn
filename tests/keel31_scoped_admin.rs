//! KEEL-31 — dyn's admin methods (and its service-wide reads) act on the whole service (they run code
//! on the host, change who it trusts, rotate its key): each declares
//! `#[plexus_macros::method(everywhere)]`, so the gate admits it only where
//! its grant is held on `*`. An admin of one ticket or organization, and a
//! session minted `admin@X`, is refused before the method runs.
//!
//! The review's probe (`scoped_admin.rs`, KEEL-28): `admin@MENGER-5` was
//! admitted to `dyn.grow`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef, CEILING_KEY};
use plexus_core::plexus::{AuthContext, PlexusError};
use plexus_core::DynamicHub;
use plexus_dyn::{DynActivation, DynOptions};
use serde_json::{json, Value};

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// `admin` on the ticket MENGER-5 alone.
const CORNER: &str = "key:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// A ticket lives in its shortcode: `MENGER-5` → `[MENGER-5, MENGER, *]`.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, t: &str) -> Option<Vec<ScopeRef>> {
        let code = t.split_once('-').map(|(c, _)| c).unwrap_or(t);
        Some(vec![ScopeRef::named(t), ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

fn who(p: &str, ceiling: Option<&[&str]>) -> AuthContext {
    let meta = match ceiling {
        Some(c) => json!({ CEILING_KEY: c }),
        None => Value::Null,
    };
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], meta)
}

async fn host() -> (Arc<DynamicHub>, tempfile::TempDir) {
    let data = tempfile::tempdir().unwrap();
    let opts = DynOptions {
        data_dir: data.path().join("dyn"),
        dendrite: data.path().join("no-dendrite"),
        liveness: Duration::from_secs(3600),
        ..DynOptions::default()
    };
    let dyn_ = DynActivation::new(opts);
    let declared = DynamicHub::new("host").register(dyn_.clone()).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (p, scope) in [(ADMIN, ScopeRef::Everywhere), (CORNER, ScopeRef::named("MENGER-5"))] {
        members.0.lock().unwrap().push(Membership { principal: p.parse().unwrap(), role: plexus_auth_core::RoleName::new("admin"), scope });
    }
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Shortcodes)));
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).with_gate(gate));
    dyn_.start(&host).await.unwrap();
    (host, data)
}

/// Each admin method, with params that do nothing harmful when admitted.
fn admin_calls() -> Vec<(&'static str, Value)> {
    vec![
        ("dyn.connect", json!({ "name": "x", "url": "ws://127.0.0.1:1" })),
        ("dyn.grow", json!({ "name": "x", "source": "", "targets": [] })),
        ("dyn.disconnect", json!({ "name": "x" })),
        ("dyn.consent", json!({ "peer": "x" })),
        ("dyn.revoke", json!({ "peer": "x" })),
        ("dyn.rotate_key", json!({})),
        ("dyn.repin", json!({ "name": "x", "fingerprint": "00" })),
        // NEST-25 (review): who may dial in is the whole service's.
        ("dyn.admit", json!({ "name": "x", "key": "key:abababababababababababababababababababababababababababababababab" })),
        ("dyn.refuse", json!({ "name": "x" })),
        ("dyn.pending", json!({})),
    ]
}

#[tokio::test]
async fn a_scoped_admin_is_refused_every_admin_method() {
    let (host, _data) = host().await;
    for (method, params) in admin_calls() {
        for (label, caller) in [("admin@MENGER-5", who(CORNER, None)), ("a session minted admin@MENGER-5", who(ADMIN, Some(&["admin@MENGER-5"])))] {
            match host.route(method, params.clone(), Some(&caller)).await {
                Err(PlexusError::Forbidden { .. }) => {}
                Err(other) => panic!("{method} as {label}: refused, but not forbidden: {other}"),
                Ok(_) => panic!("{method} as {label}: admitted"),
            }
        }
    }
}

#[tokio::test]
async fn an_admin_of_everywhere_is_admitted_and_the_schema_says_why() {
    let (host, _data) = host().await;
    // Harmless ones: an unknown peer is answered in band.
    for (method, params) in [("dyn.disconnect", json!({ "name": "x" })), ("dyn.revoke", json!({ "peer": "x" }))] {
        assert!(host.route(method, params, Some(&who(ADMIN, None))).await.is_ok(), "{method} as admin@*");
    }
    use futures::StreamExt;
    let items: Vec<_> = host.route("dyn.schema", json!({}), Some(&who(ADMIN, None))).await.unwrap().collect().await;
    let schema = items
        .into_iter()
        .find_map(|i| match i {
            plexus_core::plexus::PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
            _ => None,
        })
        .unwrap();
    let everywhere: Vec<&str> = schema["methods"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["everywhere"] == json!(true))
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(everywhere, plexus_dyn::EVERYWHERE, "{schema}");
}

/// The reads of every peer, consent and pin are the whole service's too: a
/// viewer on one scope is refused them; a viewer on `*` reads them.
#[tokio::test]
async fn a_scoped_viewer_reads_no_service_wide_list() {
    let (host, _data) = host().await;
    for method in ["dyn.peers", "dyn.names", "dyn.consents", "dyn.pins"] {
        match host.route(method, json!({}), Some(&who(ADMIN, Some(&["viewer@MENGER-5"])))).await {
            Err(PlexusError::Forbidden { .. }) => {}
            Err(other) => panic!("{method}: refused, but not forbidden: {other}"),
            Ok(_) => panic!("{method}: answered a viewer on MENGER-5"),
        }
        assert!(host.route(method, json!({}), Some(&who(ADMIN, Some(&["viewer@*"])))).await.is_ok(), "{method} as viewer@*");
    }
}

/// KEEL-31 (N2): the backstop that does not depend on the macro — dyn
/// refuses to start when a whole-service method lost its mark.
#[tokio::test]
async fn dyn_refuses_to_start_without_its_marks() {
    use plexus_core::plexus::Activation;
    let data = tempfile::tempdir().unwrap();
    let dyn_ = DynActivation::new(DynOptions { data_dir: data.path().join("dyn"), ..DynOptions::default() });
    let mut schema = dyn_.plugin_schema();
    assert!(plexus_core::plexus::require_everywhere(&schema, plexus_dyn::EVERYWHERE).is_ok());
    for m in schema.methods.iter_mut().filter(|m| m.name == "grow") {
        m.everywhere = false;
    }
    let why = plexus_core::plexus::require_everywhere(&schema, plexus_dyn::EVERYWHERE).unwrap_err();
    assert!(why.contains("dyn.grow"), "{why}");
}

/// KEEL-31 (third pass): the backstop runs at construction, so a host that
/// never calls `start` is held too — a `dyn` refused there connects and
/// grows nothing. Shown with the refusal construction shares (a data
/// directory open to others); a build that lost a mark is refused the same
/// way, naming the methods.
#[tokio::test]
async fn a_refused_dyn_connects_nothing_unstarted() {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let open = data.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dyn_ = DynActivation::new(DynOptions { data_dir: open, dendrite: data.path().join("no-dendrite"), ..DynOptions::default() });
    let got = serde_json::to_value(dyn_.connect("x".into(), "ws://127.0.0.1:1".into(), None, None).await).unwrap();
    assert_eq!(got["type"], "error", "{got}");
    assert!(got["message"].as_str().unwrap().contains("data directory"), "{got}");
    // This build: every mark there, nothing refused for it.
    let fine = DynActivation::new(DynOptions { data_dir: data.path().join("dyn"), dendrite: data.path().join("no-dendrite"), ..DynOptions::default() });
    let got = serde_json::to_value(fine.connect("x".into(), "ws://127.0.0.1:1".into(), None, None).await).unwrap();
    assert!(!got.to_string().contains("must be marked `everywhere`"), "{got}");
}
