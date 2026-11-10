# Changelog

## [0.4.0] — unreleased

NEST-25: **a node that dials in.** A service with no listening port opens a
socket to the host, proves its key and offers an activation; once its key is
admitted for its name it is `dyn.peer.<name>` while the socket lives —
`PeerKind::DialIn { principal, since, from }` (`kind: dial_in`), gated,
consented by its key, revoked (its socket closed, its next offer refused)
and disconnected (its socket closed, its admission kept) as every peer.
`DynActivation::dial_in()` opens the door (`DialIn::socket` for each
accepted socket; `DialIn::host_key`, the dial key the node pins); new
methods `dyn.admit { name?, key?, code? }`, `dyn.refuse { name?, key?,
code?, why? }` and `dyn.pending` (all `everywhere`, operators only); new
`DynEvent::Admitted` and `DynEvent::KeyRefused`; `DynOptions::
dial_in_pending_max` (16), `dial_in_pending_per_address` (4),
`dial_in_pending_age` (10 min); `consent.json` keeps `admitted` and
`refused_keys`. An offer from a key not admitted waits pending (nothing
mounted, the node told only its pairing code) until `dyn.admit --code`;
first contact on the node's side (known hosts, the pairing code) is
plexus-core's. Needs plexus-core with NEST-25's dial-in seams (0.11.3).
`examples/dial_shop.rs`: a shop dialing in. README "A node that dials in".

Review round 1: offers going pending are rate limited by address (an IPv4
address, an IPv6 /64) and by key (`DynOptions::dial_in_offers_per_minute_
per_address` 10, `…_per_key` 3); an address past its share supersedes its
own oldest, and a full list takes the oldest of its busiest address. `dyn
admit --name --key` is refused while an offer under that name or key waits
with a pairing code. A mount re-checks admission, refusal and revocation
under the store's lock as it enters the table (a refusal racing it wins).
`DialIn::names`. Needs plexus-core's `Admission::mounted -> Result`.

## [0.3.0] — unreleased

DYNAUTH-31 (breaking only in that `PeerKind` gains a variant): **an
in-process peer.** `DynActivation::attach(name, by, peer, replace)` holds
any plexus-core `Peer` served in this process (plexus-bridge's bridges) in
dyn's table as `dyn.peer.<name>` — `PeerKind::InProcess { by }`, listed by
`dyn.peers` as `kind: in_process` — and `DynActivation::detach(name, &peer)`
lets go of it (only that very peer). It is gated as every peer, called with
the caller's own context, and **needs no key proof and no forwarded token**:
dyn mints it nothing, and it is never an exchange's presenter or audience
(both are found by key), so no token addressed to another peer is obtained
through it — the rule written beside KEEL-19's in README "An in-process
peer needs no key proof and no forwarded token". `dyn.revoke` refuses its
next call and ends every call open into it with one error item saying why;
the revocation stands when it is attached again and ends only with
`replace`. `dyn.disconnect` ends its open calls too. `dyn.consent` gives it
`callers` only (it declares no needs). Not served at the top level.
`DynActivation::get` answers `Unavailable` for an in-process name (it is not
a mount); a `--peers` entry naming one is skipped.

Review 1: **a consent is its holder's, not its name's** (D2, KEEL-24
extended). `Consent` gains `holder` — none for a keyed peer (its key
decides, unchanged), `ws` or `dendrite` for a keyless one, and
`in_process:<by>:<binding>` for an in-process one; `Consent::is_for` decides
wherever a consent is applied or kept. `attach` takes `binding` (the
attacher's word for what the peer is). Another holder of a name — another
binding, a keyless peer of another kind, an in-process peer over a remote
one or the reverse — starts with no consent, and `detach` drops it. A
consent kept before 0.3.0 reads as a keyed or keyless remote peer's.
`DynActivation::holds(name, &peer)`: whether dyn serves that very peer,
unrevoked — what an attacher asks before acting for it outside a call.
`PeerKind` is `#[non_exhaustive]`.

**Moving from 0.2.1:**

- A `match` on `PeerKind` needs a wildcard arm (`#[non_exhaustive]`);
  `Consent` gains `holder` (a struct literal names it).
- `dyn.{peer}` now reaches every in-process peer (every bridge) as well as
  every remote peer and dendrite. Separating one peer's callers from
  another's is `dyn.consent … callers`, which hands a role each of the
  peer's flat method paths — not a path with dynamic segments (a bridge's
  `repos.<owner>.<repo>.get`).
- Consenting a dendrite's (or any peer's) need on an in-process peer that
  acts on third-party accounts — a bridge — lets it act on each caller's
  account there, with that caller's credential.
- A keyless WebSocket peer or dendrite connected or grown over the name of
  another kind (and a consent of a name now held by an in-process peer) no
  longer inherits that name's consent.

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

Second pass: **a key is mounted once.** A peer proving a key another peer
here holds (mounted, or pinned) is refused — `refused` with
`Refusal::IdentityChanged`, its message starting `key_in_use:`, `old` the
holder's pin, audited — at `connect`/`grow` and at a remount (checked again
where the entry is reserved, under one hold of the lock: two connects
racing on one key mount one); so a token addressed to a key, and an
exchange's presenter found by its key, name one peer, and a revoked peer's
key gets no sibling mount. With plexus-core 0.11.1 a keyed peer is served on
`ChildPeer::connection` (the tests' WebSocket peers are served as proven
`service:dyn`), every forwarded hop carries the service's proof, and a
consent narrowed under an open call narrows its next call back. Both sides
upgrade together (plexus-core's CHANGELOG).

Third pass: **`dyn` dials with a key by default** — `<data_dir>/dial.key`
(0600, made when missing; `DynOptions::child.key` overrides), its own, not
the token-signing `dyn.key`: a peer trusts the dial key as the service
acting for others, the JWKS key signs tokens and forward proofs, and
rotating one changes only its role (`dyn.rotate_key` leaves the dial
identity; a new dial key must be re-trusted by the peers). Its principal is
`DynActivation::dial_principal()`; without a dial key no keyed peer mounts.
The dial key is denied to every dendrite. The tests serve keyed peers with
plexus-core's `serve_child_ws` (the upgrade's key proof verified), never on
a name.

Fourth pass: **the data directory is the user's own** (KEEL-25, folded
in). The default is `$XDG_DATA_HOME/plexus-dyn`, else
`~/.local/share/plexus-dyn` (with neither, `<tmp>/plexus-dyn-<uid>`), no
longer `/tmp/plexus-dyn`; it is made 0700, and one that is a link, another
user's, or open to group or others is refused — `start` answers why,
naming it, and no key or consent is read from or kept in it.
`consent.json` and the keys are read only as the user's own, 0600, never
through a link. A connect refused for a key another peer holds is refused
before it touches the consent of the name it gave (`register`/`hold` after
the entry is reserved; a consent kept for another key is no longer read
for a peer, at `hold` nor by the gate's roles). A refused data directory is
a behaviour change: an existing one made 0755 by an earlier version (e.g.
plexus-ui's `<data-dir>/dyn`) is refused until `chmod 700`.

Fifth pass: `dyn` dials its peers as the reserved agent
`plexus.child-dial` (plexus-core 0.11.1's `ws::dial`), which a keyed peer's
`serve_child_ws` requires, so a peer on 0.11.1 refuses a 0.2.0 `dyn`'s
dial: upgrade `dyn` and its keyed peers together. A peer's upgrade ledger
refuses when full (4096 proofs a minute) instead of evicting. The example
prints the dial principal at start (`dial principal: key:…`), which each
keyed peer trusts. Requires plexus-macros 0.11.1 and plexus-auth-core
0.3.2. A service behind key sign-in is mounted as before: its sign-in
takes the dial proof as `dyn`'s key.

**Moving from 0.2.0:** upgrade with plexus-core 0.11.1 on both sides; give
each keyed peer `dial_principal()` to trust and serve it with
`serve_child_ws`; `chmod 700` a data directory an earlier version made
group- or world-readable, or move it (the default moved from
`/tmp/plexus-dyn`, whose keys and consent are not carried over).

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
