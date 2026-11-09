# plexus-dyn

A Plexus service grows peers at runtime. `dyn` is an activation a service
registers to **connect** to other services and to **grow** TypeScript
dendrites, each served as a peer in one untyped slot:

| method | who | what |
| -- | -- | -- |
| `dyn.connect { name, url, replace? }` | admin | a service on a WebSocket, mounted as the peer `name` (a taken name refused unless `replace`) |
| `dyn.grow { name, source, targets, replace? }` | admin | `source` written to `<data-dir>/<name>/index.ts` and served by `plexus-dendrite serve DIR --via-host …`; each target (`w` or `w.weather`, a peer's path) is grown from the host's view of `dyn.peer.<target>` and called back **through the host** |
| `dyn.disconnect { name }` | admin | let go |
| `dyn.peers` | viewer | each peer: kind (`ws` / `dendrite`), up, why down, interface hash, restarts, open calls, calls, calls back, remounts |
| `dyn.names` | viewer | each peer's name — the slot's list |
| `dyn.peer.<name>.<path>.<method>` | `dyn.{peer}` | a call into a peer; a role may list a literal path (`dyn.peer.digest.rainy`) instead |

`connect`, `grow` and `disconnect` are listed in no role: only `admin`
holds them. `dyn.{peer}` is the untyped slot's grant, also `admin`'s
unless a role lists it; the peer decides again inside it.

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

## In a service

```rust
let dyn_ = plexus_dyn::DynActivation::new(plexus_dyn::DynOptions {
    data_dir: "/var/lib/svc/dendrites".into(),
    dendrite: "plexus-dendrite".into(),
    peers_file: Some("peers.toml".into()),
    ..Default::default()
});
let service = Arc::new(DynamicHub::new("svc").register(dyn_.clone()));
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
required, else run with a cleared environment. The dendrite needs
`plexus-dendrite` (the sibling checkout, or `PLEXUS_DENDRITE`) and Node 22.

## Rough

- plexus-core 0.10.1 is not yet published: the dependency is by path.
- `connect` / `grow` / `disconnect` change the running set only; the peers
  file is read at start and never written.
- A dendrite's targets are peers under `dyn`; a target elsewhere on the
  host is not named yet.
