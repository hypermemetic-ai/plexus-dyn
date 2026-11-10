//! DYNAUTH-5 · a peer's registration and an admin's consent.
//!
//! **Registration.** `connect` and `grow` register a peer as a client of
//! this service: the Ed25519 key it proved at its mount (`_info` over a
//! nonce; a dendrite on its pipe proves none — the pipe is the host's own)
//! and the `needs` its schema publishes (NEST-16). Both are pinned with its
//! identity: a remount proving another key is refused as one proving
//! another certificate key is (DYNAUTH-8's pin).
//!
//! **Consent.** A peer's `needs` are a *request*. `dyn.consent { peer,
//! needs, callers }` (admin) answers it:
//!
//! - `needs`: the subset of its declared needs it may call back up through
//!   this service, each `method` (anywhere its caller reaches) or
//!   `method@scope` (only there). A need declared and not consented is
//!   refused upward (`forbidden`, `not_needed`, saying so). Consenting to a
//!   method it does not declare is refused.
//! - `callers`: the roles whose holders may call into it
//!   (`dyn.peer.<name>.<path>.<method>`, and `<name>.…` at the top level):
//!   [`ConsentRoles`] — the service's roles with, for each role named, every
//!   method of each peer consented to it. The blanket slot grant `dyn.{peer}`
//!   stays the admin's.
//!
//! The consent is kept in `dyn`'s data directory (`consent.json`, 0600),
//! with the key it was given for: a peer connected again with another key
//! is a new client, and its consent is dropped. A change of consent moves
//! the gate's grants generation, so what was decided under the old one is
//! decided again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use plexus_auth_core::grants::{Grant, GrantSet, Roles};
use plexus_auth_core::RoleName;
use plexus_core::plexus::{Consented, RemoteChild};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What an admin consented to for one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Consent {
    /// Needs it may call back up: `method` or `method@scope`.
    #[serde(default)]
    pub needs: Vec<String>,
    /// Roles whose holders may call into it.
    #[serde(default)]
    pub callers: Vec<String>,
    /// The key it was given for (`key:<hex>`); `None` for a peer that proved
    /// none (a dendrite on its pipe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// One peer's registration and consent, as `dyn.consents` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConsentInfo {
    pub peer: String,
    /// The key it proved, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// What its schema says it needs (`None`: it declares nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<Vec<String>>,
    /// Needs consented, `method` or `method@scope`.
    pub needs: Vec<String>,
    /// Declared needs not consented: refused upward.
    pub pending: Vec<String>,
    /// Roles that may call into it.
    pub callers: Vec<String>,
    /// DYNAUTH-7: revoked (`dyn.revoke`), and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
}

/// What `dyn` keeps in `consent.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Store {
    #[serde(default)]
    pub consents: BTreeMap<String, Consent>,
    /// DYNAUTH-7: revoked peers, and why.
    #[serde(default)]
    pub revoked: BTreeMap<String, String>,
}

impl Store {
    /// KEEL-19 (P5, KEEL-25): read only when it is the user's own, 0600, and
    /// not a symbolic link; a missing file is no consent.
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        match plexus_core::plexus::peer_token::read_private_if_any(path)? {
            Some(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
            None => Ok(Self::default()),
        }
    }

    /// Written whole (a temporary file, renamed into place), 0600.
    pub(crate) fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let tmp: PathBuf = path.with_extension("json.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let text = serde_json::to_vec_pretty(self).unwrap_or_default();
        o.open(&tmp).and_then(|mut f| f.write_all(&text)).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// `method` or `method@scope`, split (`*` when no scope is named).
pub(crate) fn split_need(entry: &str) -> (&str, &str) {
    match entry.rsplit_once('@') {
        Some((m, s)) if !s.is_empty() => (m, s),
        _ => (entry.trim_end_matches('@'), "*"),
    }
}

/// Check a consent against what the peer declares: every need one it
/// declares, every caller a role's name. `Err` names each refused entry.
pub(crate) fn check(peer: &str, consent: &Consent, declared: Option<&[String]>) -> Result<(), String> {
    let declared: BTreeSet<&str> = declared.unwrap_or_default().iter().map(String::as_str).collect();
    let undeclared: Vec<&str> = consent.needs.iter().map(|n| split_need(n).0).filter(|m| !declared.contains(m)).collect();
    if !undeclared.is_empty() {
        let shown = if declared.is_empty() { "nothing".to_string() } else { declared.iter().copied().collect::<Vec<_>>().join(", ") };
        return Err(format!("`{peer}` does not declare {} among its needs (it declares {shown}): consent answers a request, it does not widen one", undeclared.join(", ")));
    }
    if let Some(bad) = consent.callers.iter().find(|c| c.is_empty() || c.contains('.') || c.contains('@')) {
        return Err(format!("`{bad}` is not a role's name"));
    }
    Ok(())
}

/// What a mount holds its child's calls back to: each consented need that
/// is still declared, on its scopes.
pub(crate) fn consented(consent: Option<&Consent>, declared: Option<&[String]>) -> Vec<Consented> {
    let declared: BTreeSet<&str> = declared.unwrap_or_default().iter().map(String::as_str).collect();
    let mut by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for n in consent.map(|c| c.needs.as_slice()).unwrap_or_default() {
        let (m, s) = split_need(n);
        if declared.contains(m) {
            by.entry(m.to_string()).or_default().insert(s.to_string());
        }
    }
    by.into_iter()
        .map(|(method, scopes)| {
            let scopes = if scopes.contains("*") { vec!["*".to_string()] } else { scopes.into_iter().collect() };
            Consented { method, scopes }
        })
        .collect()
}

/// Every method path a mounted peer serves, below its mount: `m` for its
/// own methods, `<path>.m` for each static child's — but none its schema
/// marks `everywhere` (KEEL-31): consent hands a role an ordinary method,
/// never one held only on `*`.
pub(crate) fn method_paths(child: &RemoteChild) -> Vec<String> {
    use plexus_core::plexus::Activation;
    let mut out: Vec<String> = child.plugin_schema().methods.iter().filter(|m| !m.everywhere).map(|m| m.name.clone()).collect();
    for (path, schema) in child.static_child_schemas() {
        out.extend(schema.methods.iter().filter(|m| !m.everywhere).map(|m| format!("{path}.{}", m.name)));
    }
    out
}

/// What [`ConsentRoles`] asks `dyn` for: the grants consent gives `role`.
pub(crate) trait ConsentSource: Send + Sync {
    fn consented_grants(&self, role: &str) -> Vec<String>;
}

/// The service's roles, plus what consent gives: for each role a peer's
/// consent names among its `callers`, every method of that peer
/// (`dyn.peer.<name>.<path>.<method>`, and `<name>.<path>.<method>` when it
/// is served at the top level). Hand it to the gate in place of the roles
/// it wraps: `Gate::new(members, dyn.consent_roles(roles), resolve)`.
pub struct ConsentRoles {
    pub(crate) base: Arc<dyn Roles>,
    pub(crate) source: Weak<dyn ConsentSource>,
}

impl Roles for ConsentRoles {
    fn grants(&self, role: &RoleName) -> Option<GrantSet> {
        let base = self.base.grants(role);
        if matches!(base, Some(GrantSet::All)) {
            return base;
        }
        let more = self.source.upgrade().map(|s| s.consented_grants(role.as_str())).unwrap_or_default();
        if more.is_empty() {
            return base;
        }
        let mut set = match base {
            Some(GrantSet::Listed(s)) => s,
            _ => Default::default(),
        };
        set.extend(more.into_iter().map(Grant::new));
        Some(GrantSet::Listed(set))
    }

    fn names(&self) -> Vec<RoleName> {
        self.base.names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_consent_is_within_what_is_declared() {
        let declared = vec!["shop.items".to_string(), "dyn.peer.w.weather.forecast".to_string()];
        let ok = Consent { needs: vec!["shop.items@MENGER".into()], callers: vec!["viewer".into()], key: None };
        assert!(check("p", &ok, Some(&declared)).is_ok());
        let wider = Consent { needs: vec!["dyn.grow".into()], ..Consent::default() };
        assert!(check("p", &wider, Some(&declared)).unwrap_err().contains("dyn.grow"));
        assert!(check("p", &wider, None).unwrap_err().contains("nothing"));
        let bad_role = Consent { callers: vec!["dyn.peers".into()], ..Consent::default() };
        assert!(check("p", &bad_role, Some(&declared)).is_err());
        let held = consented(Some(&Consent { needs: vec!["shop.items@A".into(), "shop.items@B".into(), "dyn.peer.w.weather.forecast".into(), "gone.method".into()], ..Consent::default() }), Some(&declared));
        assert_eq!(held, vec![
            Consented { method: "dyn.peer.w.weather.forecast".into(), scopes: vec!["*".into()] },
            Consented { method: "shop.items".into(), scopes: vec!["A".into(), "B".into()] },
        ]);
        assert!(consented(None, Some(&declared)).is_empty(), "no consent: nothing upward");
    }

    #[test]
    fn the_store_is_private_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("consent.json");
        let mut s = Store::default();
        s.consents.insert("w".into(), Consent { needs: vec!["a.b".into()], callers: vec![], key: Some("key:00".into()) });
        s.save(&path).unwrap();
        assert_eq!(Store::load(&path).unwrap().consents, s.consents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(Store::load(&dir.path().join("none.json")).unwrap().consents.is_empty());
    }
}
