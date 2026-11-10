//! DYNAUTH-31 · a peer served in this process.
//!
//! An activation of the service's own — a bridge, anything that answers
//! [`Peer`] — is held in dyn's table beside the mounted ones
//! ([`DynActivation::attach`]) and called as one, `dyn.peer.<name>.<path>`:
//! admitted by the same gate (`dyn.{peer}`, or a role its consent's
//! `callers` names), listed by `dyn.peers` (`kind: in_process`), stopped by
//! `dyn.revoke` and `dyn.disconnect`.
//!
//! **No key proof, no forwarded token.** Nothing crosses a wire, so there is
//! nothing to prove and nobody to hand a token to: the peer is called with
//! the caller's own context, as any activation of the service is, and dyn
//! mints nothing for it. It proves no key, so it is never an exchange's
//! presenter or audience (`dyn.exchange` finds both by key, KEEL-19): no
//! token addressed to another peer is ever obtained through it. It declares
//! no needs — it calls nothing back through dyn — so consent gives it
//! `callers` only.
//!
//! **Stopped as any peer.** A revoked in-process peer is refused at once and
//! every call open into it ends with one error item saying why; it stays
//! listed as revoked, across the service's restarts (the revocation is kept
//! in `consent.json`), until it is attached again with `replace`. A
//! disconnected one is gone, its open calls ended the same way.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use plexus_core::plexus::peer::{Interface, Peer, PeerError};
use plexus_core::plexus::{AuthContext, PlexusError, PlexusStream};
use serde_json::Value;
use tokio::sync::watch;

use crate::{check_name, DynActivation, DynEvent, Entry, Inner, PeerKind};

/// One in-process peer as the table holds it.
#[derive(Clone)]
pub(crate) struct Local {
    pub(crate) peer: Arc<dyn Peer>,
    /// `Some(why)` once it is stopped: every call open into it ends.
    stop: Arc<watch::Sender<Option<String>>>,
    pub(crate) open: Arc<AtomicUsize>,
    pub(crate) calls: Arc<AtomicU64>,
}

impl Local {
    fn new(peer: Arc<dyn Peer>) -> Self {
        Self { peer, stop: Arc::new(watch::channel(None).0), open: Arc::default(), calls: Arc::default() }
    }

    /// End every call open into it, saying `why`.
    pub(crate) fn stop(&self, why: &str) {
        self.stop.send_replace(Some(why.to_string()));
    }

    fn is(&self, peer: &Arc<dyn Peer>) -> bool {
        std::ptr::addr_eq(Arc::as_ptr(&self.peer), Arc::as_ptr(peer))
    }

    /// Its interface's hash, as `dyn.peers` shows a mount's.
    pub(crate) fn interface_hash(&self) -> String {
        self.peer.interface().hash
    }
}

/// Every method path an in-process peer serves (its schema's), but none it
/// marks `everywhere` (KEEL-31): what consent's `callers` hand a role.
pub(crate) fn method_paths(local: &Local) -> Vec<String> {
    local.peer.interface().schema().methods.iter().filter(|m| !m.everywhere).map(|m| m.name.clone()).collect()
}

/// An in-process peer (or one of its own peers) as the slot hands it to
/// routing: refused once revoked, each call's stream ended when it stops.
struct Served {
    inner: Arc<Inner>,
    name: String,
    local: Local,
    peer: Arc<dyn Peer>,
}

impl Served {
    fn refused(&self) -> Option<PeerError> {
        if let Some(why) = self.inner.store.lock().unwrap().revoked.get(&self.name) {
            return Some(PeerError::Unavailable { reason: format!("`{}` is revoked ({why})", self.name) });
        }
        let why = self.local.stop.borrow().clone()?;
        Some(PeerError::Unavailable { reason: format!("`{}` is stopped ({why})", self.name) })
    }
}

#[async_trait]
impl Peer for Served {
    fn interface(&self) -> Interface {
        self.peer.interface()
    }

    async fn call(&self, method: &str, params: Value, auth: Option<&AuthContext>) -> Result<PlexusStream, PlexusError> {
        let provenance = vec!["dyn".to_string(), self.name.clone()];
        if let Some(e) = self.refused() {
            return Ok(e.stream(provenance));
        }
        let mut stopped = self.local.stop.subscribe();
        // The caller's own context, as it reached dyn: nothing minted, nothing forwarded.
        let stream = self.peer.call(method, params, auth).await?;
        self.local.calls.fetch_add(1, Ordering::Relaxed);
        let open = Open::new(self.local.open.clone());
        let name = self.name.clone();
        Ok(Box::pin(async_stream::stream! {
            let _open = open;
            let mut stream = stream;
            // Why it stopped, said once it does (a `Ref` is never held across a yield).
            let stop = async move {
                match stopped.wait_for(Option::is_some).await {
                    Ok(w) => w.clone().unwrap_or_default(),
                    Err(_) => "disconnected".to_string(),
                }
            };
            tokio::pin!(stop);
            loop {
                tokio::select! {
                    biased;
                    why = &mut stop => {
                        yield PeerError::Unavailable { reason: format!("`{name}` is stopped ({why})") }.item(provenance.clone());
                        break;
                    }
                    item = stream.next() => match item {
                        Some(i) => yield i,
                        None => break,
                    },
                }
            }
        }))
    }

    async fn peer(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        if let Some(e) = self.refused() {
            return Err(e);
        }
        let below = self.peer.peer(name).await?;
        Ok(Box::new(Served { inner: self.inner.clone(), name: self.name.clone(), local: self.local.clone(), peer: Arc::from(below) }))
    }
}

/// A call open into an in-process peer, counted while its stream lives.
struct Open(Arc<AtomicUsize>);
impl Open {
    fn new(n: Arc<AtomicUsize>) -> Self {
        n.fetch_add(1, Ordering::Relaxed);
        Self(n)
    }
}
impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl DynActivation {
    /// DYNAUTH-31: hold `peer`, served in this process, as the peer `name`:
    /// `dyn.peer.<name>.<path>.<method>`, gated, listed, revoked and
    /// disconnected as every peer is (`dyn.peers` says `kind: in_process`,
    /// `by` naming who attached it). It is called with the caller's own
    /// context: no key proof, no token minted, never an exchange's presenter
    /// or audience. A taken name is refused unless `replace`; `replace` is
    /// also an admin's new registration — a revocation kept for `name` ends
    /// with it, as `connect … replace` ends one. Without it a revocation
    /// stands: a peer attached again at the service's start stays revoked.
    /// Not served at the service's top level ([`DynOptions::top_level`]).
    ///
    /// [`DynOptions::top_level`]: crate::DynOptions::top_level
    pub fn attach(&self, name: &str, by: &str, peer: Arc<dyn Peer>, replace: bool) -> DynEvent {
        if let Some(message) = &self.inner.refused {
            return DynEvent::Error { message: message.clone() };
        }
        if let Err(message) = check_name(name) {
            return DynEvent::Error { message };
        }
        let local = Local::new(peer);
        let interface = local.peer.interface();
        let methods = interface.schema().methods.iter().map(|m| m.name.clone()).collect();
        let old = {
            let mut peers = self.inner.peers.lock().unwrap();
            if peers.contains_key(name) && !replace {
                return DynEvent::Error { message: format!("a peer is connected as `{name}`: disconnect it, or attach with `replace`") };
            }
            let entry = Entry { kind: PeerKind::InProcess { by: by.to_string() }, child: None, local: Some(local), why: None, remounts: 0, expecting: None, pin: None, presented: None };
            peers.insert(name.to_string(), entry)
        };
        let replaced = old.is_some();
        if let Some(l) = old.as_ref().and_then(|e| e.local.as_ref()) {
            l.stop("replaced");
        }
        // A mount it replaces may have been served at the top level; this is not.
        self.unsurface(name);
        // DYNAUTH-5: it proves no key — a consent kept for a keyed peer of this name is another client's.
        self.register(name, None);
        if replace && self.inner.store.lock().unwrap().revoked.remove(name).is_some() {
            if let Err(why) = self.save_store() {
                tracing::error!(target: "plexus::dyn", "{why}");
            }
        }
        self.moved();
        tracing::info!(target: "plexus::audit", peer = %name, %by, replaced, "dyn attach (in process)");
        DynEvent::Connected { name: name.to_string(), interface: interface.hash, methods, replaced }
    }

    /// DYNAUTH-31: let go of the in-process peer `name` — only when it is
    /// still `peer` (a peer connected over it since is not touched). Every
    /// call open into it ends. Whether it was let go.
    pub fn detach(&self, name: &str, peer: &Arc<dyn Peer>) -> bool {
        let gone = {
            let mut peers = self.inner.peers.lock().unwrap();
            match peers.get(name).and_then(|e| e.local.as_ref()) {
                Some(l) if l.is(peer) => peers.remove(name),
                _ => None,
            }
        };
        let Some(e) = gone else { return false };
        if let Some(l) = &e.local {
            l.stop("disconnected");
        }
        self.moved();
        true
    }

    /// The in-process peer `name`, as the slot serves it: `Ok(None)` when
    /// `name` is not one; refused once revoked.
    pub(crate) fn served_local(&self, name: &str) -> Result<Option<Box<dyn Peer>>, PeerError> {
        let Some(local) = self.inner.peers.lock().unwrap().get(name).and_then(|e| e.local.clone()) else { return Ok(None) };
        let served = Served { inner: self.inner.clone(), name: name.to_string(), peer: local.peer.clone(), local };
        match served.refused() {
            Some(e) => Err(e),
            None => Ok(Some(Box::new(served))),
        }
    }
}
