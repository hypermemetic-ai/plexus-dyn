//! NEST-21 · `dyn`'s settings, declared on the service's configuration
//! (`plexus_core::plexus::config`) beside plexus-core's
//! `transport.insecure_ws`, `transport.tls_roots` and `child.*`, which `dyn`
//! reads at every connect and mount.

use plexus_core::plexus::config::{Config, Setting};

/// NEST-18 D33's alternative, as a setting: a pinned peer whose certificate
/// key moved — its chain validated as every dial's is, its backend and own
/// key the same — is re-pinned instead of refused. Off by default (D33:
/// refusing is the safe default). Critical: it decides who is trusted.
pub const DYN_REPIN_ON_VALID_CERT: Setting<bool> = plexus_core::setting!(
    "dyn.repin_on_valid_cert",
    default = false,
    critical = true,
    doc = "re-pin a peer whose certificate key moved under a valid chain (same backend and key) instead of refusing it"
);

/// Paths no dendrite may read, beside the defaults and the host's own
/// `Containment::deny`: it adds, never takes one away. Read at each spawn.
pub const DYN_CONTAINMENT_DENY: Setting<Vec<String>> = plexus_core::setting!(
    "dyn.containment.deny",
    default = Vec::new(),
    doc = "more paths no dendrite may read, beside the defaults and the host's; read at each spawn"
);

/// Refuse to start a dendrite Landlock cannot contain. Read at each spawn.
/// Critical: turning it off lets a dendrite run uncontained.
pub const DYN_CONTAINMENT_REQUIRE: Setting<bool> = plexus_core::setting!(
    "dyn.containment.require",
    default = false,
    critical = true,
    doc = "refuse a dendrite Landlock cannot contain; read at each spawn"
);

/// DYNAUTH-5: a peer's declared needs are called back only once an admin
/// consents. Live: every mounted peer is held again when it moves.
/// Critical: off, every declared need may be called.
pub const DYN_REQUIRE_CONSENT: Setting<bool> = plexus_core::setting!(
    "dyn.require_consent",
    default = true,
    critical = true,
    doc = "a peer's declared needs are called back only once an admin consents (dyn.consent)"
);

/// Declare `dyn`'s settings in `c`.
pub fn declare(c: &Config) {
    c.declare(&DYN_REPIN_ON_VALID_CERT);
    c.declare(&DYN_CONTAINMENT_DENY);
    c.declare(&DYN_CONTAINMENT_REQUIRE);
    c.declare(&DYN_REQUIRE_CONSENT);
}
