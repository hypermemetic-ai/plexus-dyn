# Changelog

## [Unreleased]

DYNAUTH-5: **registration and consent.** `connect` and `grow` register a
peer: the Ed25519 key it proves at `_info` (plexus-core's `_info {nonce}`
→ `{backend, key, proof}`), pinned with its identity (`PeerIdentity::key`;
a remount proving another key is refused, `identity_changed`), and its
declared `needs`. `dyn.consent { peer, needs, callers }` (admin): the needs
it may call back up (`method` or `method@scope`, a subset of what it
declares) and the roles that may call into it; `dyn.consents` (viewer)
lists each peer's key, declared needs, consent and what is pending. A
declared need not consented is refused upward (`DynOptions::require_consent`,
on by default). `DynActivation::consent_roles(roles)` wraps the service's
roles so a consented role reaches `dyn.peer.<name>.…`; `dyn.{peer}` stays
the admin's. Kept in `<data_dir>/consent.json` (0600) with the key it was
given for; a peer connected again under another key loses it. New:
`consent` (`Consent`, `ConsentInfo`, `ConsentRoles`),
`DynEvent::Consented`, `DynOptions::require_consent`.

DYNAUTH-8 (TM-3): **transport hardening.** `ws://` only to loopback;
`wss://` beyond it, certificates validated (plexus-core's `child-wss`, with
`ChildOptions::tls_roots` for more CAs); `DynOptions::insecure_ws` allows a
test network's plain `ws://`, said as `insecure` in `dyn.peers`. A peer's
identity (`_info` backend, the TLS key) is pinned at connect, shown in
`dyn.peers`, and a redial or remount that proves another is refused until a
`connect … replace`. New: `DynEvent::Refused { reason, message }`,
`Refusal`, `PeerIdentity`, `check_url`, `PeerInfo::{identity, insecure}`.
Needs the plexus-core after 0.10.1 (`RemoteChild::identity`,
`ChildOptions::tls_roots`).

DYNAUTH-22: **every secret store denied by default.** A contained
dendrite's default deny list grows from six paths to every secret store on
the machine that is there: hyperforge's (plaintext `secrets.yaml`), gh's,
menger's, cargo's credentials, docker's `config.json`, `~/.kube`, `~/.aws`,
`~/.config/gcloud`, `~/.netrc`, `~/.npmrc`, `~/.pypirc` and
`$XDG_RUNTIME_DIR/synapse` (the signed-in holder). A path not there is
skipped. New: `contain::{SECRET_STORES, RUNTIME_SECRETS}`,
`Containment::default_deny_in`.

DYNAUTH-9 (TM-5): **a grown dendrite, contained.** Spawned through the new
binary `plexus-dyn-contain`: a cleared environment (own `HOME`, `TMPDIR`),
its own directory as cwd, and on Linux a Landlock ruleset (landlock 0.4.7,
best-effort to ABI 9) denying `dyn`'s data directory, `~/.plexus`,
`~/.ssh`, `~/.gnupg`, `~/.password-store`, the dial key and
`Containment::deny` — at every path the same files are mounted at — with
writes only in its own directory, and signals, abstract and by-path UNIX
sockets scoped. Degrades with a warning; `Containment::require` refuses
instead. New: `contain` (`Containment`, `launcher_main`),
`DynOptions::contain`.

## 0.1.0

NEST-12: the first release. `dyn`, an activation that connects to other
services at runtime (`connect`), grows TypeScript dendrites (`grow`, served
by `plexus-dendrite serve DIR --via-host …`), lets go (`disconnect`) and
lists them (`peers`, `names`); each is a peer in one untyped slot,
`dyn.peer.<name>.<path>.<method>`, gated by `dyn.{peer}`. Liveness (a look
every `liveness`, a ping on each WebSocket peer), a remount when a peer's
schema changes, `--peers FILE` connected at `start`. On plexus-core 0.10.1
(by path until it is published).

NEST-15: **`top_level`** (`DynOptions::top_level`, the example's
`--top-level`; off by default): each peer is also served at the service's
own top level, `<name>.<path>.<method>` (`svc w weather forecast`, not `svc
dyn peer w weather forecast`), through plexus-core 0.10.2's service root —
added on `connect` / `grow` (and at `start` for peers connected before it),
replaced on a remount, removed on `disconnect`. `dyn.peer.<name>` keeps
working beside it. A name the service already serves at its top level is
refused. At the top level a peer is gated as a mounted child: each method on
its own grant (`w.weather.forecast`), not the slot's `dyn.{peer}`. Needs
plexus-core 0.10.2.
