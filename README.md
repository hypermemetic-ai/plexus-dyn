# plexus-dyn

A Plexus service grows peers at runtime. `dyn` is an activation a service
registers to **connect** to other services and to **grow** TypeScript
dendrites, each served as a peer in one untyped slot:

| method | who | what |
| -- | -- | -- |
| `dyn.connect { name, url, replace?, expecting? }` | admin | a service on a WebSocket, mounted as the peer `name` (a taken name refused unless `replace`); `expecting` an interface hash (a contract's stamp) it must serve, at connect and every remount (NEST-16) |
| `dyn.grow { name, source, targets, replace?, expecting? }` | admin | `source` written to `<data-dir>/<name>/index.ts` and served by `plexus-dendrite serve DIR --via-host …`; each target (`w` or `w.weather`, a peer's path) is grown from the host's view of `dyn.peer.<target>` and called back **through the host** |
| `dyn.disconnect { name }` | admin | let go |
| `dyn.peers` | viewer | each peer: kind (`ws` / `dendrite` / `in_process`, DYNAUTH-31), up, why down, interface hash, restarts, open calls, calls, calls back, remounts |
| `dyn.names` | viewer | each peer's name — the slot's list |
| `dyn.consent { peer, needs?, callers? }` | admin | DYNAUTH-5: the needs `peer` may call back up (`method`, or `method@scope` for only there; a subset of what it declares) and the roles whose holders may call into it; replaces what it held |
| `dyn.jwks` | public | DYNAUTH-12: the JWK Set (Ed25519, `kid` = `key:<hex>`) a peer verifies this service's tokens with |
| `dyn.exchange { subject_token, proof, audience, scope?, method? }` | public | DYNAUTH-6: RFC 8693 token exchange — a peer's token, with its proof of possession (method `exchange`, the token's `call`), for one addressed to the connected keyed peer `audience` and its `method`, its scope never wider. KEEL-19: only for a presenter mounted here, not revoked and consented to reach `dyn.peer.<audience>.<m>`; bound to the presenter's key; once per subject, audience and method |
| `dyn.revoke { peer, why? }` | admin | DYNAUTH-7: nothing forwarded to it from now (no token minted), its calls back end, its consent goes; listed revoked until connected or grown again with `replace` |
| `dyn.rotate_key` | admin | DYNAUTH-7: a new signing key from now; the old one in `dyn.jwks` for one token lifetime |
| `dyn.consents` | viewer | each peer's key (proved at `_info`), declared needs, consented needs and callers, what is pending |
| `dyn.peer.<name>.<path>.<method>` | `dyn.{peer}` | a call into a peer; a role may list a literal path (`dyn.peer.digest.rainy`) instead, or be named by its consent's `callers` |

**Grafts** (NEST-16): every connect, grow and remount reads the peer's
`needs` (what it calls of this service: a graft written with `parent =
ShopClient`, or a dendrite calling back `--via-host`) and refuses it unless
this service serves each, by its shape hash, naming every one missing or
changed. A need below `dyn.{peer}` counts as served when the slot is.

`connect`, `grow` and `disconnect` are listed in no role: only `admin`
holds them. `dyn.{peer}` is the untyped slot's grant, also `admin`'s
unless a role lists it; the peer decides again inside it.

## At the top level (`top_level`)

With `DynOptions { top_level: true, .. }` (the example's `--top-level`),
each peer is also served at the service's own top level — `<name>.<path>.<method>`,
`svc w weather forecast` rather than `svc dyn peer w weather forecast` —
through plexus-core's service root (0.10.2, NEST-15): added as it is
connected or grown, swapped on a remount, removed on `disconnect`.
`dyn.peer.<name>` keeps working beside it. A name the service already
serves at its top level is refused. There a peer is gated as a mounted
child is: each method on its own grant (`w.weather.forecast`), `admin`'s
unless a role lists it.

## A dendrite calls through the host

A dendrite's call back is routed by the host's own gate **as the caller of
the call the dendrite is serving**, within that call's reach (plexus-core
0.10.1, plexus-wire spec/14 "A child calls its service back"). A caller
who may call `dyn.peer.digest.rainy` but not `dyn.{peer}` reaches the
dendrite and is refused the peer it calls.

```ts
// what `dyn.grow { name: "digest", targets: ["w.weather"] }` serves
import { weather } from "./clients/weather"; // grown from dyn.peer.w.weather

export async function rainy({ city }: { city: string }) {
  let rain_days = 0;
  for await (const day of weather.forecast({ city })) if (day.rain > 0.5) rain_days++;
  return { rain_days };
}
```

## Liveness and remount

Every `liveness` (5 s) each peer is looked at: one down is brought up
(redialed, restarted) within its backoff, one that never mounted is tried
again. A WebSocket peer is pinged at the same period and marked down when
nothing has come from it for two. A peer whose restart published another
schema is refused by its mount for good; `dyn` connects a fresh mount and
swaps it in (at the next look, or on the next call), counting a remount.

## Transport (DYNAUTH-8)

A WebSocket peer beyond loopback is reached by `wss://` only, its
certificate validated against the webpki roots plus
`DynOptions::child.tls_roots` (a PEM file of more CAs: a private one, a test
network's). `ws://` is for `127.0.0.0/8`, `::1` and `localhost`; any other
host is refused `{"type":"refused","reason":"insecure_transport"}` — at
`connect`, and for a `--peers` entry, listed down saying so.
`DynOptions::insecure_ws` allows it for a test network, and `dyn.peers` says
`"insecure": true` on each such peer.

A peer's identity is pinned when it is connected: its `_info` backend and,
on `wss://`, the sha256 of its certificate's public key (a renewal over the
same key is the same peer). `dyn.peers` shows it (`identity`). A redial or a
remount that proves another is refused (`identity_changed`), the peer listed
down saying why, until it is connected again with `replace`.

## A dendrite, contained (DYNAUTH-9)

A dendrite is arbitrary code run as the host's OS user, so `dyn.grow` is
the admin's and host-equivalent trust until dendrites run in microVMs. The
floor beneath that: each is spawned through **`plexus-dyn-contain`** (this
crate's binary, found beside the service's executable or on `PATH`; or
`DynOptions::contain.launcher`), which

- clears its environment — `PATH`, `LANG` and `PLEXUS_CHILD_NAME` pass,
  and each name of `contain.env` (it must also be in `child.env`, which
  takes it from the service's); `HOME` is `<dir>/.home`, `TMPDIR`
  `<dir>/.tmp`;
- starts it in its own directory;
- on Linux, restricts it with **Landlock** before it executes: it reads
  everything but `dyn`'s data directory (every other dendrite's),
  every secret store of the user's that is there (`~/.plexus`, `~/.ssh`,
  `~/.gnupg`, `~/.password-store`, `~/.config/hyperforge`, `~/.config/gh`,
  `~/.config/menger`, `~/.local/share/menger`, `~/.cargo/credentials{,.toml}`,
  `~/.docker/config.json`, `~/.kube`, `~/.aws`, `~/.config/gcloud`,
  `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `$XDG_RUNTIME_DIR/synapse`; one
  not there is skipped), the dial key (`child.key`) and each path of `contain.deny` (the host's signing key, a
  bridge's sealed store) — wherever those are also mounted (a bind mount,
  a btrfs subvolume); it writes only its own directory (and `/dev/null`);
  on kernels that have them, it may not signal a process outside it, reach
  an abstract UNIX socket made outside it, or connect to a UNIX socket by
  path outside its directory (Linux 7.1: no Docker socket, no signed-in
  synapse holder).

Where Landlock is not there (an old kernel, another OS) the dendrite runs
with the cleared environment and the launcher logs a warning; where the
launcher is not found, with `env -i` and a warning.
`contain.require` refuses to start one that cannot be contained instead.
The network is not restricted.

## Registration and consent (DYNAUTH-5)

`connect` and `grow` register each peer as a client: the Ed25519 key it
proves at `_info` (a nonce signed; plexus-core's `ServeChild::key` on the
far side) — pinned with its identity, so a remount proving another key is
refused (`identity_changed`) until `connect … replace` — and the `needs` its
schema declares. A dendrite on its pipe proves no key: the pipe is the
host's own. KEEL-19: the proof is made for its asker — the principal the
peer's connection proved (a keyed peer is served on plexus-core's
`ChildPeer::connection`, never a `Pipe`) — so a proof one peer asks of
another and relays is refused; and one key is one peer: a peer proving a
key another peer here holds is refused (`identity_changed`, its message `key_in_use: …`).

Declared needs are a request. Until an admin answers it with `dyn.consent`
every one is refused upward (`forbidden`, `not_needed`, "no admin has
consented to it"); `DynOptions::require_consent = false` restores NEST-16's
rule (declared is enough). A consent names only needs the peer declares; a
`method@scope` need is reached only on that scope. `callers` are roles: a
service that hands its gate `dyn.consent_roles(roles)` lets a holder of a
named role call every method of the peer (`dyn.peer.<name>.…`, and
`<name>.…` at the top level) — except one its schema marks `everywhere`
(KEEL-31): a whole-service method is never consent's to give, and stays
with whoever holds its grant on `*` by their own role. Consent is kept in `<data-dir>/consent.json`
(0600) with the key it was given for; another key is another client, and
its consent is dropped. Every change moves the gate's grants generation.

## Peer tokens (DYNAUTH-12)

Every call forwarded for a signed-in caller to a peer that proved a key
carries a token in its hop (`hop.token`): an EdDSA-signed JWT (`typ`
`plexus-peer+jwt`) — `sub` the caller, `act` the actor chain, `aud` the
peer's key, `cnf.jkt` its thumbprint, `scope` the forwarded grant and the
peer's consented needs within the call's reach, `call` and `method` the
forwarded call, `jti`, at most 60 s. A dendrite on its pipe gets one too,
addressed `pipe:<name>` and bound to no key. A peer verifies with
`dyn.jwks` (plexus-core's `Verifier`, `ServeChild::tokens`): the algorithm
pinned, the audience its own, fresh, each `jti` once — and, KEEL-19, sent
with the service's proof that it sends it (`hop.proof`, by the key that
signed the token), over a connection proven as the service. Calling back under a
key-bound token, a peer sends a proof of possession by its key for that
method and call (plexus-core's `host()` does it); without one it is
refused. The signing key is `<data-dir>/dyn.key` (0600), denied to every
dendrite. A WebSocket peer that proves no key gets no token.

## The dial key and the data directory (KEEL-19)

`dyn` dials every peer with a key of its own, `<data_dir>/dial.key` (0600,
made at the first start; `DynOptions::child.key` names another), apart from
the token-signing `dyn.key`. Its principal, `key:<hex>`, is
`DynActivation::dial_principal()` (the example prints it at start,
`dial principal: key:…`; plexus-core's `remote_child::key_principal(path)`
reads it from the file). A keyed peer serves itself with plexus-core's
`serve_child_ws`, trusting that principal (its `trusted`): the peer believes
a forwarded hop only from a connection whose upgrade that key proved. The
key is the service's identity to its peers: keep it, and when it changes
(a new data directory, a deleted file, `child.key` moved) every keyed peer
must be told the new principal. `dyn.rotate_key` rotates the token key
only, never the dial key.

The data directory defaults to `$XDG_DATA_HOME/plexus-dyn`, else
`~/.local/share/plexus-dyn` (no longer `/tmp/plexus-dyn`). It is made 0700;
one that is a symbolic link, another user's, or open to group or others is
refused — `start` answers why, naming it, and no key or consent is read
from it or kept in it. One an earlier version made 0755 is refused until
`chmod 700 DIR`.

## The rules a keyed peer and its service apply (KEEL-19)

What the code checks, in order — the text a change to `remote_child` or
`peer_token` is checked against.

**Before a peer runs a hop** (`{ns}.call` for method M; a schema call needs
none of this):

1. A child with a key, or verifying tokens addressed to a key, is served
   only by `serve_child_proven`, which takes a `Proven` — a type with no
   constructor from a string, made only by `KeyedUpgrade::verify` checking
   the upgrade's `plexus-key.` proof (`serve_child_ws` does it) — and is
   believed from that principal alone. `serve_child_with` refuses one,
   whatever `ChildPeer` it is given.
2. A keyless, non-verifying child (`serve_child_with`) believes every
   sender its `ChildPeer` takes. Served as `ChildPeer::Pipe` on a
   WebSocket, it believes every sender who can reach that socket, as
   whoever the frame claims to be. **Do not do this**: a keyless child
   belongs on its parent's stdin/stdout or a socket only that parent can
   open; a child reachable over a network has a key and is served with
   `serve_child_ws`. On `ChildPeer::connection` the sender is the string it
   was given, which proves nothing by itself.
3. With a verifier, the hop's token must verify: an EdDSA JWS signed by a trusted
   JWKS key (`iss` = `kid`), `aud` this child, within its times, naming
   `hop.call` and M, its `sub` the hop's caller, its scope holding the
   hop's grant on every scope the hop says.
4. And its sender must be proven by `hop.proof` over (token, M, `hop.call`):
   a token bound to this child's own key (or, to a pipe, to none) is the
   service's forward — the proof by its issuer key, and on a connection a
   sender `ChildPeer` takes; a token bound to another key is an exchanged
   one — the proof by that key, over a connection proven as it, which the
   hop names. Only then is the token's `jti` spent (once).
5. Then the far side's own check (the hop's grant is M or M's slot) and M
   runs as the hop's caller, within the scopes the hop says.

**Before a service mounts a keyed peer** (`RemoteChild::connect`):

1. It dials with its own key proof on the upgrade (`ChildOptions::key`;
   plexus-dyn: `<data_dir>/dial.key` by default), so its principal is the
   `key:` the peer's transport proves.
2. It asks `_info {nonce, asker}`; a peer that names a key must prove it
   with `plexus-peer-key/v2` over (nonce, backend, the asker its connection
   proved), checked against the service's own principal — refused when
   that principal is not a key (`keyed_mount_needs_a_key`) or the proof was
   made for anyone else.
3. The key is pinned with the peer's identity: a remount proving another
   is refused (`identity_changed`); plexus-dyn refuses a key another peer
   holds, mounted or pinned (`identity_changed`, `key_in_use:`), checked
   where the entry is reserved.
4. Tokens are minted for that key only while it is mounted and not
   revoked — asked at the top of each forward and again, after the dial
   it may await, where the token is minted and where its call back is
   opened — by a service whose principal is a key; each forwarded hop
   carries the service's proof (`TokenIssuer::prove_forward`).
5. An exchange (`dyn.exchange`) is decided as a call back is: the presenter
   mounted, not revoked, holding a consented need for the audience and the
   method, within the consent of now; once per (`jti`, audience, method);
   the token bound to the presenter's key.

Replay: an upgrade's key proof is taken once while its 60 s window lasts,
and a token's `jti` once while it lives. `KeyedUpgrade` holds at most 4096
proofs (`UPGRADE_LEDGER_MAX`); full, it **refuses** a new upgrade — never
forgets a proof early — until proofs leave their window: the dialer gets
HTTP 401 with `this child holds 4096 key proofs in their 60 s window: a new
upgrade is refused until some expire`, and the child logs a warning on
target `plexus::audit` (`child upgrade ledger full`, with the count held
and refused) at most once per 10 s. So at most 4096 upgrades a minute are
taken per child (about 68 a second, sustained); a flood can deny upgrades
for a minute, never replay one. Both are kept in memory: a restarted child
forgets, so a proof or token captured in the 60 s before a restart can be
replayed to it once after it (a token only while it lives, at most its
`exp`).

Key files and the data directory are the user's own, 0600 and 0700, never
read through a symbolic link.

A child dial's key proof is spec/00's one form, signed as the reserved agent
`plexus.child-dial` (`CHILD_DIAL_AGENT`; `agent` is in the signed bytes): a
child takes only that agent, so a sign-in proof replayed to a child at
the same URL is refused. A server's sign-in (plexus-auth-core's
`KeyProofAdapter`) takes a dial proof as the dialing key's sign-in, by
design: a dial proof is addressed to the dialed URL and usable only there,
and it is how a service mounts another service behind key sign-in
(`--child far=wss://…`, `dyn.connect`). A context of its own would be a
plexus-wire spec/00 change, not made.

## An in-process peer needs no key proof and no forwarded token (DYNAUTH-31)

The rule beside KEEL-19's. An activation of the service's own — a bridge,
anything that answers plexus-core's `Peer` — is held in dyn's table by the
host, never over the wire: `DynActivation::attach(name, by, peer, replace)`
(`dyn.peers` says `kind: in_process`, `by` who attached it) and
`DynActivation::detach(name, &peer)` (only that very peer: one connected
over the name since is not touched). It is called as
`dyn.peer.<name>.<path>.<method>`, admitted by the same gate as every peer
(`dyn.{peer}`, a literal path, or its consent's `callers`).

1. **No key proof**: nothing crosses a transport, so there is no
   connection to prove and no `_info` to ask; it is never pinned and proves
   no key.
2. **No forwarded token**: it is called with the caller's own context, as
   any activation of the service is; dyn mints it nothing (no mint record,
   no `hop.token`).
3. **No token for another peer through it**: `dyn.exchange` finds its
   presenter and its audience by their keys, and an in-process peer has
   none, so it is neither — a token for another peer is never obtained by
   presenting it, nor one addressed to it. A token bound to no key (what a
   pipe child holds) is not exchanged (KEEL-19).
4. **No needs**: it calls nothing back through dyn, so `dyn.consent` gives
   it `callers` only (never a method it marks `everywhere`, KEEL-31); a
   `needs` is refused, as for a peer that declares none.
5. **Stopped as any peer**: `dyn.revoke` refuses its next call at once and
   ends every call open into it with one error item saying why; it stays
   revoked across the service's restarts (`consent.json`), attached again
   revoked, until it is attached with `replace` — an admin's new
   registration, as `connect … replace` is. `dyn.disconnect` lets it go and
   ends its open calls the same way.

It is not served at the service's top level (`top_level`).

## Onward calls (DYNAUTH-6)

A peer's call back is held to its needs, to consent, and to the token its
call was made under; the NEST-11 `admin@<scope>` layer stays only as the
outer bound ("any grant, only there"). When that call back reaches another
peer, the token minted for it is an exchange of the presented one: the
original caller stays `sub`, `act` names each hop nearest first (`{sub:
host, act: {sub: <presenter>, act: {sub: host}}}`), and its scope is never
wider. `dyn.exchange` does the same as a method.

KEEL-19: `dyn.exchange` is decided as a call back is — the presenter (the
subject token's audience) must be mounted here, not revoked, and hold a
consented need that covers the audience and the method asked
(`dyn.peer.<audience>.<m>`); anything else is refused, its reason in
brackets, and audited. The token it gives is bound to the presenter's key
(`cnf`): the audience takes it only with the presenter's proof
(`hop.proof`, by `prove(key, token, <method>, <hop.call>)`), over a
connection proven as that key. A token the service forwards is taken only
from the service's own connection. A subject token is exchanged once per
audience and method.

## Revocation and audit (DYNAUTH-7)

| what is revoked | how fast |
| -- | -- |
| a peer (`dyn.revoke`) | at once at the host: no call forwarded, no token minted, its calls back end. A token already in its hand verifies at a peer that does not ask for ≤ 60 s (its `exp`, plus the 30 s skew) |
| a caller's grant | the gate's grants generation moves; calls back under its reach end (NEST-11); outstanding tokens ≤ 60 s |
| consent (`dyn.consent`, withdrawn) | the grants generation moves; the next call back is refused |
| the signing key (`dyn.rotate_key`) | new tokens signed by the new key at once; the old key leaves `dyn.jwks` after one lifetime and the skew; a peer must fetch `dyn.jwks` again to take the new one |

Every mint and exchange writes one audit record — `iss`, `sub`, the actor
chain, `aud`, `scope`, `call`, `jti`, `exp`, `method`, and for an exchange
the call of the token presented (which joins one hop to the one before) —
as a `plexus::audit` tracing event and to `DynOptions::audit`. Never the
token, a signature or a proof.

## In a service

```rust
let dyn_ = plexus_dyn::DynActivation::new(plexus_dyn::DynOptions {
    data_dir: "/var/lib/svc/dendrites".into(),
    dendrite: "plexus-dendrite".into(),
    peers_file: Some("peers.toml".into()),
    ..Default::default()
});
// DYNAUTH-5: the gate's roles, plus what consent gives a role.
let gate = Gate::new(members, dyn_.consent_roles(Arc::new(roles)), resolve);
let service = Arc::new(DynamicHub::new("svc").register(dyn_.clone()).with_gate(Arc::new(gate)));
dyn_.start(&service).await?; // the --peers file, the liveness task, the service dendrites call back through
```

`--peers FILE`, connected at `start` (one that fails is listed down, not
dropped, and tried again at every look):

```toml
weather = "ws://127.0.0.1:4801"

[digest]
dendrite = "dendrites/digest"   # relative to the file
via = ["weather.weather"]
```

`examples/dyn_service.rs` serves one on a port: `cargo run --example
dyn_service -- PORT [--peers FILE] [--data-dir DIR] [--dendrite PATH]`.

## Tests

```sh
CARGO_TARGET_DIR=~/.cache/cargo-target/NEST-11 cargo test
```

`tests/dyn.rs` runs a far service on a WebSocket (ports 4800–4899) and a
gated host in memory: connect, call, disconnect; a caller without the grant
refused; the far side restarted and redialed; restarted with another schema
and remounted; a dendrite grown against a peer calling it through the host
(and refused as a caller who lacks the peer's grant); a silent peer marked
down by the ping; a live one staying up; the peers file; `ws://` beyond
loopback refused, or allowed and said; a `wss://` peer (a test CA, rcgen)
refused untrusted, pinned trusted, and refused once it restarts under
another key until it is connected again; a contained
dendrite refused a key file, another dendrite's file and `~/.plexus/keys`,
seeing none of the host's environment, reading and writing its own
directory; one whose launcher is missing refused when containment is
required, else run with a cleared environment; a viewer reaching a peer
only once its role is consented, a consent beyond what is declared refused,
a dendrite's call back refused until its need is consented; a peer proving
its key at `_info` (plexus-core's far side over a WebSocket), refused at a
remount under another key, and its consent dropped when connected again
under it; DYNAUTH-31: an in-process peer called as its caller with no
token minted (a keyed peer beside it is minted one), no exchange naming it
audience or presented through it, consent giving it callers only, and
revoke and disconnect ending its open calls. The dendrite needs
`plexus-dendrite` (the sibling checkout, or `PLEXUS_DENDRITE`) and Node 22.

## Rough

- plexus-core 0.10.1 is not yet published: the dependency is by path.
- `connect` / `grow` / `disconnect` change the running set only; the peers
  file is read at start and never written.
- A dendrite's targets are peers under `dyn`; a target elsewhere on the
  host is not named yet.
