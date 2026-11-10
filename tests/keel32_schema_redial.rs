//! KEEL-32 — introspection dials no peer for a caller who does not hold
//! the peer slot's grant. Before it, an anonymous `host.dyn.peer.<name>.schema`
//! passed the gate as introspection and was routed into `get()` → `mount()`:
//! any registered peer, a revoked one included, was redialed on every
//! request (the review, KEEL-28, finding 4).
//!
//! A registered peer here points at a listener that counts the connections
//! made to it and closes each at once; its liveness look is an hour away, so
//! every connection counted is one a call made.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plexus_auth_core::grants::{Gate, Membership, Memberships, Resolve, RoleTable, ScopeRef};
use plexus_core::plexus::{AuthContext, PlexusError};
use plexus_core::DynamicHub;
use plexus_dyn::{DynActivation, DynOptions};
use serde_json::{json, Value};

const ADMIN: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Holds the peer slot (`dyn.{peer}`).
const USER: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// Holds `viewer`: `dyn.peers`, `dyn.names`, … — not the slot.
const VIEWER: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

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

/// A listener that counts each connection and closes it.
fn counting() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let seen = n.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    (port, n)
}

#[tokio::test]
async fn a_schema_ask_dials_no_peer_for_a_caller_without_the_slot() {
    let (port, dials) = counting();
    let data = tempfile::tempdir().unwrap();
    let peers = data.path().join("peers.toml");
    std::fs::write(&peers, format!("w = \"ws://127.0.0.1:{port}\"\n")).unwrap();
    let dyn_ = DynActivation::new(DynOptions {
        data_dir: data.path().join("dyn"),
        dendrite: data.path().join("no-dendrite"),
        liveness: Duration::from_secs(3600),
        peers_file: Some(peers),
        ..DynOptions::default()
    });
    let declared = DynamicHub::new("host").register(dyn_.clone()).declared_roles();
    let mut lists: Vec<(String, Vec<String>)> = declared.into_iter().collect();
    lists.push(("user".into(), vec!["dyn.{peer}".into()]));
    let roles = RoleTable::from_lists(lists.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let members = Arc::new(Members::default());
    for (p, r) in [(ADMIN, "admin"), (USER, "user"), (VIEWER, "viewer")] {
        members.0.lock().unwrap().push(Membership { principal: p.parse().unwrap(), role: plexus_auth_core::RoleName::new(r), scope: ScopeRef::Everywhere });
    }
    let gate = Arc::new(Gate::new(members, dyn_.consent_roles(Arc::new(roles)), Arc::new(Everywhere)));
    let host = Arc::new(DynamicHub::new("host").register(dyn_.clone()).with_gate(gate));
    dyn_.start(&host).await.unwrap();
    // The start dialed it once (the peers file), and it did not come up.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Revoked: the review's case — a revoked peer was redialed too.
    assert!(host.route("dyn.revoke", json!({ "peer": "w" }), Some(&who(ADMIN))).await.is_ok());
    let before = dials.load(Ordering::SeqCst);

    let anonymous: Option<&AuthContext> = None;
    let viewer = who(VIEWER);
    let mut not_refused = Vec::new();
    for caller in [anonymous, Some(&viewer)] {
        for m in ["host.dyn.peer.w.schema", "dyn.peer.w.schema", "host.dyn.peer.w.weather.schema", "dyn.peer.nobody.schema"] {
            for _ in 0..3 {
                match host.route(m, json!({}), caller).await {
                    Err(PlexusError::ActivationNotFound(_) | PlexusError::MethodNotFound { .. }) => {}
                    Err(other) => not_refused.push(format!("{m}: refused, but not as not found: {other}")),
                    Ok(_) => not_refused.push(format!("{m}: answered a caller without the slot")),
                }
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = dials.load(Ordering::SeqCst);
    assert_eq!(after, before, "a schema ask dialed the (revoked) peer {} times for callers without its slot", after - before);
    assert!(not_refused.is_empty(), "{not_refused:#?}");

    // The slot's holder: its ask does reach the peer (and finds it down).
    let _ = host.route("dyn.peer.w.schema", json!({}), Some(&who(USER))).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(dials.load(Ordering::SeqCst) > before, "the slot's holder is routed to the peer");
}
