# Changelog

## [0.2.1]

On plexus-core 0.11.1.

KEEL-19 (security, High): **`dyn.exchange` is decided where a call back is
decided.** In 0.2.0 it checked only that the audience was a keyed,
unrevoked peer. Now the presenter — the subject token's audience, proven by
its proof — must be a peer mounted here, not revoked, holding a consented
need that covers the audience and the method asked
(`dyn.peer.<audience>.<m>` for the audience's `<backend>.<m>`, or
`<audience>.<m>` for a peer at the top level), held by the subject token
(plexus-core's `RemoteChild::may_exchange`). `method` is required. The
token's scope is `method` on the scopes both the subject holds that need on
and consent allows, narrowed to `scope` when asked; it is bound to the
presenter's key, so the audience takes it only with the presenter's proof;
and a subject token is exchanged once per audience and method. A refusal's
message names its reason in brackets (`[not_consented]`, `[presenter]`,
`[revoked]`, `[again]`, `[proof]`, `[subject]`, `[audience]`) and is
audited (`plexus::audit`). A revoked presenter is refused at once.

## [0.2.0] — unreleased

On plexus-core, plexus-macros and plexus-client 0.11 (NEST-24): a new minor,
since 0.1.0 is on plexus-core 0.10.1 and this one cannot share its number.

KEEL-7: `check_url` decides by plexus-core's `check_ws_url` (the one
loopback/scheme function every dial of the service asks), keeping no copy;
its refusal now also names `transport.insecure_ws`. A mount's options carry
`transport.insecure_ws` to plexus-core's dial, which refuses on its own too.

NEST-21: **settings and re-pinning.** `dyn` reads the service's
configuration (plexus-core's `config`; `DynOptions::config`, else the
service's at `start`) at every connect, mount and spawn:
`transport.insecure_ws`, `transport.tls_roots`, `child.*`, and its own
(`plexus_dyn::settings`) `dyn.repin_on_valid_cert` (default false, NEST-18
D33; critical), `dyn.containment.deny` (adds only), `dyn.containment.require`
(critical), `dyn.require_consent` (critical; mounted peers held again when
it moves). The options' values are the flag layer. `dyn.pins` (viewer):
each peer's pinned identity and fingerprint, and the identity it presented
and was refused for. `dyn.repin { name, fingerprint }` (admin): pins the
presented identity only when `fingerprint` is its
(`PeerIdentity::fingerprint`, `sha256:` over backend, certificate key and
key); else `refused` `fingerprint_mismatch` (or `not_presented`) with `old`
and `presented`. New: `PinInfo`, `PeerInfo::presented`,
`DynEvent::Repinned`, `DynEvent::Refused { old, presented }`,
`Refusal::{FingerprintMismatch, NotPresented}`.

DYNAUTH-7: **revocation and audit.** `dyn.revoke { peer, why? }` (admin):
nothing is forwarded to it from now (no token minted), its calls back end,
its consent goes, and it stays listed as revoked (`PeerInfo::revoked`,
`dyn.consents`' `revoked`) until an admin connects or grows it again with
`replace`; a token already issued expires within 60 s. `dyn.rotate_key`
(admin): a new signing key from now (the key file replaced), the old one in
`dyn.jwks` for one token lifetime and the skew. `DynOptions::audit`
(`Audit`, a `TokenAudit` sink) beside the `plexus::audit` event for every
mint and exchange. New: `DynEvent::{Revoked, Rotated}`,
`DynActivation::{revoke_peer, rotate_signing_key}`.

DYNAUTH-6: **token exchange.** A peer calling onward through the host gets
the next peer a token by exchange (plexus-core): the caller stays `sub`,
the presenter joins `act`, the scope never widens. `dyn.exchange {
subject_token, proof, audience, scope?, method? }` (public; the authority is
the token and its proof) does it as a method, RFC 8693's response as
`ExchangeEvent::Exchanged`; refused without a proof, for a pipe's token,
or for a peer that proved no key.

DYNAUTH-12: **peer tokens.** `dyn` signs a token for every call forwarded
to a peer that proved a key (bound to it) and to a dendrite on its pipe
(plexus-core's `ChildOptions::tokens`): `sub` the caller, `act` the host,
`aud` the peer, `scope` the forwarded grant and its consented needs within
the call's reach, ≤ 60 s. Its key is `<data_dir>/dyn.key` (0600, made when
missing; `DynOptions::key_file`), denied to every dendrite. `dyn.jwks`
(public) answers the JWK Set a peer verifies with. New:
`DynOptions::{tokens, key_file}`, `DynActivation::{jwk_set, issuer}`.

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
