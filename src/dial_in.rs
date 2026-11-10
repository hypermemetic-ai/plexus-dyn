//! NEST-25 · a node that dials in.
//!
//! A service with no listening port — behind a NAT, outbound only — opens
//! one WebSocket to this service, signs in with its key at the upgrade,
//! offers an activation on that socket (plexus-wire spec/14) and is held in
//! dyn's table as `dyn.peer.<name>` (`kind: dial_in`) for as long as the
//! socket lives: called through the gate as every peer is, its consent its
//! key's, revoked and disconnected as every peer is. plexus-core's dial-in
//! machinery ([`Peers`], [`PeerSocket`]) carries the socket; this module is
//! the [`Admission`] that decides who is mounted, before anything is.
//!
//! | when | then |
//! | -- | -- |
//! | a socket whose key is not proven on its connection offers | refused `unauthenticated`; nothing asked, nothing mounted |
//! | a key admitted for the name (`dyn.admit --name N --key K`) offers | its schema is asked, its `needs` checked (NEST-16), it is mounted as `dyn.peer.<N>` |
//! | a key not admitted offers | held **pending**: nothing mounted, nothing served, the node told only "pending" and the pairing code; `dyn.pending` lists it for an operator, who admits it (`dyn.admit --code`) or refuses it (`dyn.refuse`) |
//! | pending: 16 at once, 4 from one address, 1 per key (a newer offer supersedes), 10 minutes | past any: refused (`pending_full`, `pending_expired`, `superseded`) |
//! | a refused key, a revoked name, a name another peer or key holds, a key another peer holds | refused before its schema is asked |
//! | the same key offers the name from a new socket | it takes the name over; the old socket is closed (a reconnect) |
//! | the socket closes | the peer is gone from the table at once; a call open into it ends `child_unavailable` |
//! | `dyn.revoke` | the socket is closed and the name refused until admitted again |
//! | `dyn.disconnect` | the socket is closed; the admission stays, so the node comes back by dialing again |

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use plexus_core::plexus::remote_child::pairing::{key_fingerprint, normalize_code};
use plexus_core::plexus::remote_child::{Admission, Decision, Offer, OfferRefused, PeerSocket, Peers};
use plexus_core::plexus::peer_token::PeerKey;
use plexus_core::plexus::{AuthContext, RemoteChild};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::{check_name, key_held_by, key_in_use, DynActivation, DynEvent, Entry, Inner, PeerKind};

/// An offer held pending, as `dyn.pending` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PendingInfo {
    /// The name it asks to be mounted as.
    pub name: String,
    /// The key it proved (`key:<hex>`).
    pub principal: String,
    /// The key's fingerprint, as ssh shows one (`SHA256:<base64>`).
    pub fingerprint: String,
    /// The pairing code: the node prints the same one (`XXXX-XXXX`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// When it offered (unix seconds).
    pub since: u64,
    /// The address it came from, as the transport saw it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// One offer waiting for an operator.
pub(crate) struct Pending {
    pub(crate) info: PendingInfo,
    socket: u64,
    release: oneshot::Sender<Result<(), OfferRefused>>,
}

/// The pending offers, by socket.
pub(crate) type PendingTable = BTreeMap<u64, Pending>;

/// The address part of `ip:port` (the port is the socket's, not the machine's).
fn address_of(from: &str) -> String {
    from.parse::<std::net::SocketAddr>().map(|a| a.ip().to_string()).unwrap_or_else(|_| from.to_string())
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The door a transport hands each accepted socket to
/// ([`DynActivation::dial_in`]). Cheap to clone.
#[derive(Clone)]
pub struct DialIn {
    peers: Peers,
    host_key: String,
}

impl std::fmt::Debug for DialIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialIn").field("host_key", &self.host_key).finish()
    }
}

impl DialIn {
    /// The key this service proves to a dialing node (`key:<hex>`): what the
    /// node pins (`--trust`, or its known hosts at first contact).
    pub fn host_key(&self) -> &str {
        &self.host_key
    }

    /// A socket the transport accepted, signed in as `auth`, from `from`;
    /// `close` drops it. `None` — no hook for this socket — unless it signed
    /// in with a key (`key:<hex>`): an anonymous socket, or one signed in any
    /// other way, offers nothing and is answered nothing here. Feed the
    /// socket every inbound frame ([`PeerSocket::on_frame`]) and its close
    /// ([`PeerSocket::on_close`]); write every frame the receiver yields.
    pub fn socket(&self, auth: Option<AuthContext>, from: Option<String>, close: impl Fn() + Send + Sync + 'static) -> Option<(Arc<PeerSocket>, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let principal = auth.as_ref().and_then(|a| a.principal()).map(|p| p.to_string())?;
        plexus_core::plexus::peer_token::key_of(&principal)?;
        Some(self.peers.socket_from(auth, from, Some(Box::new(close))))
    }
}

/// dyn's word on each offer.
pub(crate) struct DialAdmission {
    pub(crate) inner: Weak<Inner>,
}

fn refused(kind: &str, message: impl Into<String>) -> OfferRefused {
    OfferRefused::new(kind, message)
}

impl DialAdmission {
    fn dyn_(&self) -> Option<DynActivation> {
        self.inner.upgrade().map(|inner| DynActivation { inner })
    }
}

impl DynActivation {
    /// NEST-25: what refuses `principal` as `name` before anything is asked
    /// of its socket, if anything does.
    fn dial_refusal(&self, name: &str, principal: &str) -> Option<OfferRefused> {
        if let Some(why) = &self.inner.refused {
            return Some(refused("unavailable", why.clone()));
        }
        if let Err(why) = check_name(name) {
            return Some(refused("invalid_params", why));
        }
        {
            let store = self.inner.store.lock().unwrap();
            if let Some(why) = store.refused_keys.get(principal) {
                return Some(refused("refused", format!("the key {principal} is refused here ({why})")));
            }
            if let Some(why) = store.revoked.get(name) {
                return Some(refused("revoked", format!("`{name}` is revoked ({why}): an operator admits it again")));
            }
            if let Some(k) = store.admitted.get(name).filter(|k| *k != principal) {
                return Some(refused("name_taken", format!("`{name}` is admitted for another key ({k})")));
            }
        }
        let peers = self.inner.peers.lock().unwrap();
        match peers.get(name) {
            Some(e) if e.dial.is_none() => return Some(refused("name_taken", format!("`{name}` is held by a peer of another kind"))),
            Some(e) if e.child.as_ref().and_then(|c| c.peer_key()) != Some(principal) => return Some(refused("name_taken", format!("`{name}` is held by another key's connection"))),
            _ => {}
        }
        // KEEL-19: one key, one peer.
        key_held_by(&peers, name, Some(principal)).map(|other| refused("key_in_use", key_in_use(name, principal, &other)))
    }

    /// NEST-25: hold `offer` pending, within the caps.
    fn hold_pending(&self, offer: &Offer) -> Decision {
        let o = &self.inner.opts;
        let (tx, rx) = oneshot::channel();
        let info = PendingInfo {
            name: offer.name.clone(),
            principal: offer.principal.clone(),
            fingerprint: key_fingerprint(&offer.principal).unwrap_or_default(),
            code: offer.code.clone(),
            since: now(),
            from: offer.from.clone(),
        };
        {
            let mut pending = self.inner.pending.lock().unwrap();
            // One per key: a newer offer supersedes the older.
            let older: Vec<u64> = pending.iter().filter(|(_, p)| p.info.principal == offer.principal).map(|(s, _)| *s).collect();
            for s in older {
                if let Some(p) = pending.remove(&s) {
                    let _ = p.release.send(Err(refused("superseded", "a newer offer of the same key waits in its place")));
                }
            }
            if pending.len() >= o.dial_in_pending_max {
                return Decision::Refuse(refused("pending_full", format!("{} offers wait already: try again later", pending.len())));
            }
            // By address, not by port: one machine's sockets are one address.
            let here = offer.from.as_deref().map(address_of);
            if here.is_some() && pending.values().filter(|p| p.info.from.as_deref().map(address_of) == here).count() >= o.dial_in_pending_per_address {
                return Decision::Refuse(refused("pending_full", "too many offers wait from this address"));
            }
            pending.insert(offer.socket, Pending { info, socket: offer.socket, release: tx });
        }
        tracing::warn!(target: "plexus::audit", peer = %offer.name, principal = %offer.principal, from = ?offer.from, code = ?offer.code, "dyn: a dial-in offer waits for an operator (dyn.pending, dyn.admit)");
        let age = o.dial_in_pending_age;
        let weak = Arc::downgrade(&self.inner);
        let socket = offer.socket;
        Decision::Pending(Box::pin(async move {
            let said = tokio::time::timeout(age, rx).await;
            if let Some(inner) = weak.upgrade() {
                inner.pending.lock().unwrap().remove(&socket);
            }
            match said {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(refused("refused", "no longer waiting")),
                Err(_) => Err(refused("pending_expired", format!("no operator answered within {age:?}"))),
            }
        }))
    }

    /// NEST-25: the offers waiting for an operator.
    pub fn pending_list(&self) -> Vec<PendingInfo> {
        self.inner.pending.lock().unwrap().values().map(|p| p.info.clone()).collect()
    }

    /// NEST-25: admit — by `code` the pending offer whose pairing code it is
    /// (its key for its name), or `key` for `name` ahead of time (and a
    /// pending offer of that key for that name, if one waits). An admission
    /// lifts a refusal of the key and a revocation of the name.
    pub fn admit_key(&self, name: Option<&str>, key: Option<&str>, code: Option<&str>) -> DynEvent {
        if let Some(message) = &self.inner.refused {
            return DynEvent::Error { message: message.clone() };
        }
        let (name, key, socket) = match (code, key) {
            (Some(code), _) => {
                let Some(code) = normalize_code(code) else { return DynEvent::Error { message: format!("`{code}` is not a pairing code (8 letters and digits, `XXXX-XXXX`)") } };
                let pending = self.inner.pending.lock().unwrap();
                let found: Vec<&Pending> = pending.values().filter(|p| p.info.code.as_deref() == Some(code.as_str()) && name.is_none_or(|n| n == p.info.name)).collect();
                match found.as_slice() {
                    [] => return DynEvent::Error { message: format!("no offer waits with the code {code} (dyn.pending lists them)") },
                    [p] => {
                        if key.is_some_and(|k| k != p.info.principal) {
                            return DynEvent::Error { message: format!("the offer with the code {code} is {}'s, not the key given", p.info.principal) };
                        }
                        (p.info.name.clone(), p.info.principal.clone(), Some(p.socket))
                    }
                    many => return DynEvent::Error { message: format!("{} offers wait with the code {code}: name one ({})", many.len(), many.iter().map(|p| p.info.name.as_str()).collect::<Vec<_>>().join(", ")) },
                }
            }
            (None, Some(key)) => {
                let Some(name) = name else { return DynEvent::Error { message: "admit a key for a name: `--name N --key K`".into() } };
                if plexus_core::plexus::peer_token::key_of(key).is_none() {
                    return DynEvent::Error { message: format!("`{key}` is not a key (`key:<64 hex>`)") };
                }
                if let Err(message) = check_name(name) {
                    return DynEvent::Error { message };
                }
                let socket = self.inner.pending.lock().unwrap().values().find(|p| p.info.principal == key && p.info.name == name).map(|p| p.socket);
                (name.to_string(), key.to_string(), socket)
            }
            (None, None) => return DynEvent::Error { message: "admit by `--code XXXX-XXXX` (a pending offer) or `--name N --key K`".into() },
        };
        {
            let mut store = self.inner.store.lock().unwrap();
            store.refused_keys.remove(&key);
            store.revoked.remove(&name);
            store.admitted.insert(name.clone(), key.clone());
        }
        if let Err(message) = self.save_store() {
            return DynEvent::Error { message };
        }
        // Another key's live connection under the name goes.
        let other = self.inner.peers.lock().unwrap().get(&name).and_then(|e| e.dial.clone().filter(|_| e.child.as_ref().and_then(|c| c.peer_key()) != Some(key.as_str())));
        if let Some(s) = other {
            s.close("its name was admitted for another key");
        }
        let released = socket.and_then(|s| self.inner.pending.lock().unwrap().remove(&s)).map(|p| p.release.send(Ok(())).is_ok()).unwrap_or(false);
        tracing::warn!(target: "plexus::audit", peer = %name, %key, by_code = code.is_some(), released, "dyn admit (dial-in)");
        DynEvent::Admitted { name, key, released }
    }

    /// NEST-25: refuse — by `code` the pending offer whose code it is, by
    /// `key` that key, by `name` the key admitted for it. The key is kept
    /// refused (refused at once from now, never pending again) until
    /// admitted; its admissions go, its pending offers are refused, its live
    /// connections closed.
    pub fn refuse_key(&self, name: Option<&str>, key: Option<&str>, code: Option<&str>, why: &str) -> DynEvent {
        let key = match (code, key, name) {
            (Some(code), _, _) => {
                let Some(code) = normalize_code(code) else { return DynEvent::Error { message: format!("`{code}` is not a pairing code") } };
                match self.inner.pending.lock().unwrap().values().find(|p| p.info.code.as_deref() == Some(code.as_str())) {
                    Some(p) => p.info.principal.clone(),
                    None => return DynEvent::Error { message: format!("no offer waits with the code {code}") },
                }
            }
            (None, Some(key), _) if plexus_core::plexus::peer_token::key_of(key).is_some() => key.to_string(),
            (None, Some(key), _) => return DynEvent::Error { message: format!("`{key}` is not a key (`key:<64 hex>`)") },
            (None, None, Some(name)) => {
                let admitted = self.inner.store.lock().unwrap().admitted.get(name).cloned();
                let pending = || self.inner.pending.lock().unwrap().values().find(|p| p.info.name == name).map(|p| p.info.principal.clone());
                match admitted.or_else(pending) {
                    Some(k) => k,
                    None => return DynEvent::Error { message: format!("no key is admitted or waits for `{name}`") },
                }
            }
            (None, None, None) => return DynEvent::Error { message: "refuse by `--code`, `--key` or `--name`".into() },
        };
        let names: Vec<String> = {
            let mut store = self.inner.store.lock().unwrap();
            store.refused_keys.insert(key.clone(), why.to_string());
            let names: Vec<String> = store.admitted.iter().filter(|(_, k)| **k == key).map(|(n, _)| n.clone()).collect();
            for n in &names {
                store.admitted.remove(n);
            }
            names
        };
        if let Err(message) = self.save_store() {
            return DynEvent::Error { message };
        }
        let waiting: Vec<Pending> = {
            let mut pending = self.inner.pending.lock().unwrap();
            let sockets: Vec<u64> = pending.iter().filter(|(_, p)| p.info.principal == key).map(|(s, _)| *s).collect();
            sockets.into_iter().filter_map(|s| pending.remove(&s)).collect()
        };
        for p in waiting {
            let _ = p.release.send(Err(refused("refused", format!("refused by an operator ({why})"))));
        }
        let live: Vec<Arc<PeerSocket>> = self.inner.peers.lock().unwrap().values().filter(|e| e.child.as_ref().and_then(|c| c.peer_key()) == Some(key.as_str())).filter_map(|e| e.dial.clone()).collect();
        for s in live {
            s.close("its key was refused");
        }
        tracing::warn!(target: "plexus::audit", %key, ?names, %why, "dyn refuse (dial-in)");
        DynEvent::KeyRefused { key, names, why: why.to_string() }
    }

    /// NEST-25: the dial-in door, made once the service is started (its name
    /// is what a node offers to, `<service>.offer`; dyn's dial key is what it
    /// proves). Hand each accepted socket to [`DialIn::socket`].
    pub fn dial_in(&self) -> Result<DialIn, String> {
        if let Some(why) = &self.inner.refused {
            return Err(why.clone());
        }
        let mut door = self.inner.door.lock().unwrap();
        if let Some(d) = door.as_ref() {
            return Ok(d.clone());
        }
        let service = self.inner.host.lock().unwrap().as_ref().and_then(|w| w.upgrade()).ok_or("start dyn in its service before opening the dial-in door")?;
        let key_path = self.inner.dial_key.clone().ok_or("dyn has no dial key: it cannot prove itself to a dialing node")?;
        let key = PeerKey::load_or_create(&key_path)?;
        let host_key = key.kid().to_string();
        let ns = plexus_core::plexus::Activation::namespace(&service).to_string();
        let opts = self.child_options(&PeerKind::DialIn { principal: String::new(), since: 0, from: None });
        let peers = Peers::new("dyn.peer", ns.clone(), host_key.clone())
            .with_options(opts)
            .with_key(key)
            .with_admission(Arc::new(DialAdmission { inner: Arc::downgrade(&self.inner) }));
        tracing::info!(target: "plexus::dyn", service = %ns, %host_key, "dial-in open: a node offers `{ns}.offer` and is held by key (dyn.admit, dyn.pending)");
        let d = DialIn { peers, host_key };
        *door = Some(d.clone());
        Ok(d)
    }
}

impl Admission for DialAdmission {
    fn decide(&self, offer: &Offer) -> Decision {
        let Some(d) = self.dyn_() else { return Decision::Refuse(refused("unavailable", "dyn is gone")) };
        // KEEL-19: a node is its key, proven on this connection (its offer
        // signs both nonces); a sign-in by anything else is not a node.
        if !offer.key_proven {
            return Decision::Refuse(refused("unauthenticated", "a node dials in with its key proven on its connection (an offer signing both nonces); nothing else is admitted"));
        }
        if let Some(r) = d.dial_refusal(&offer.name, &offer.principal) {
            return Decision::Refuse(r);
        }
        let admitted = d.inner.store.lock().unwrap().admitted.get(&offer.name).is_some_and(|k| *k == offer.principal);
        if admitted {
            return Decision::Admit;
        }
        d.hold_pending(offer)
    }

    fn vet(&self, offer: &Offer, child: &RemoteChild) -> Result<(), OfferRefused> {
        let d = self.dyn_().ok_or_else(|| refused("unavailable", "dyn is gone"))?;
        // Admitted a moment ago; asked again after the schema's round trip.
        if let Some(r) = d.dial_refusal(&offer.name, &offer.principal) {
            return Err(r);
        }
        if !d.inner.store.lock().unwrap().admitted.get(&offer.name).is_some_and(|k| *k == offer.principal) {
            return Err(refused("refused", "no longer admitted"));
        }
        if child.peer_key() != Some(offer.principal.as_str()) {
            return Err(refused("unauthenticated", "its key is not its mount's identity"));
        }
        // NEST-16: a graft's needs, served by this service.
        d.vet(&offer.name, child, None).map_err(|m| refused("needs_unmet", m))
    }

    fn mounted(&self, offer: &Offer, child: &RemoteChild, socket: &Arc<PeerSocket>) {
        let Some(d) = self.dyn_() else { return };
        let name = offer.name.clone();
        let kind = PeerKind::DialIn { principal: offer.principal.clone(), since: now(), from: offer.from.clone() };
        let old = {
            let mut peers = d.inner.peers.lock().unwrap();
            let pin = child.identity().map(crate::PeerIdentity::from);
            peers.insert(name.clone(), Entry { kind, child: Some(child.clone()), local: None, why: None, remounts: 0, expecting: None, pin, presented: None, dial: Some(Arc::clone(socket)) })
        };
        // A reconnect: the old socket goes.
        if let Some(old) = old.and_then(|e| e.dial).filter(|s| s.id() != socket.id()) {
            old.close("a new connection of the same key took the name");
        }
        d.register(&name, child.peer_key(), None);
        d.hold(&name, child);
        // Not served at the top level (`DynOptions::top_level`): only as `dyn.peer.<name>`.
        d.moved();
        tracing::info!(target: "plexus::audit", peer = %name, principal = %offer.principal, from = ?offer.from, "dyn: a node dialed in");
        // Closed while it was put in the table: take it out again.
        if socket.is_closed() {
            d.drop_dialed(&name, socket.id());
        }
    }

    fn closed(&self, socket: u64, mount: Option<&str>, why: &str) {
        let Some(d) = self.dyn_() else { return };
        if let Some(p) = d.inner.pending.lock().unwrap().remove(&socket) {
            let _ = p.release.send(Err(refused("child_unavailable", "its socket closed")));
        }
        if let Some(name) = mount {
            if d.drop_dialed(name, socket) {
                tracing::info!(target: "plexus::dyn", peer = %name, "a dialed-in node is gone: {why}");
            }
        }
    }
}

impl DynActivation {
    /// The dialed-in peer `name`, when socket `socket` still holds it, out of
    /// the table. Whether it was.
    pub(crate) fn drop_dialed(&self, name: &str, socket: u64) -> bool {
        let gone = {
            let mut peers = self.inner.peers.lock().unwrap();
            match peers.get(name).and_then(|e| e.dial.as_ref()) {
                Some(s) if s.id() == socket => peers.remove(name),
                _ => None,
            }
        };
        if gone.is_none() {
            return false;
        }
        self.moved();
        true
    }
}

