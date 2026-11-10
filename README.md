# plexus-dyn

A Plexus service grows peers at runtime. `dyn` is an activation a service
registers to **connect** to other services and to **grow** TypeScript
dendrites, each served as a peer in one untyped slot:

| method | who | what |
| -- | -- | -- |
| `dyn.connect { name, url, replace?, expecting? }` | admin | a service on a WebSocket, mounted as the peer `name` (a taken name refused unless `replace`); `expecting` an interface hash (a contract's stamp) it must serve, at connect and every remount (NEST-16) |
| `dyn.grow { name, source, targets, replace?, expecting? }` | admin | `source` written to `<data-dir>/<name>/index.ts` and served by `plexus-dendrite serve DIR --via-host …`; each target (`w` or `w.weather`, a peer's path) is grown from the host's view of `dyn.peer.<target>` and called back **through the host** |
| `dyn.disconnect { name }` | admin | let go |
| `dyn.peers` | viewer | each peer: kind (`ws` / `dendrite`), up, why down, interface hash, restarts, open calls, calls, calls back, remounts |
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
key another peer here holds is refused `key_in_use`.

Declared needs are a request. Until an admin answers it with `dyn.consent`
every one is refused upward (`forbidden`, `not_needed`, "no admin has
consented to it"); `DynOptions::require_consent = false` restores NEST-16's
rule (declared is enough). A consent names only needs the peer declares; a
`method@scope` need is reached only on that scope. `callers` are roles: a
service that hands its gate `dyn.consent_roles(roles)` lets a holder of a
named role call every method of the peer (`dyn.peer.<name>.…`, and
`<name>.…` at the top level). Consent is kept in `<data-dir>/consent.json`
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
under it. The dendrite needs
`plexus-dendrite` (the sibling checkout, or `PLEXUS_DENDRITE`) and Node 22.

## Rough

- plexus-core 0.10.1 is not yet published: the dependency is by path.
- `connect` / `grow` / `disconnect` change the running set only; the peers
  file is read at start and never written.
- A dendrite's targets are peers under `dyn`; a target elsewhere on the
  host is not named yet.
