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
down by the ping; a live one staying up; the peers file. The dendrite needs
`plexus-dendrite` (the sibling checkout, or `PLEXUS_DENDRITE`) and Node 22.

## Rough

- plexus-core 0.10.1 is not yet published: the dependency is by path.
- `connect` / `grow` / `disconnect` change the running set only; the peers
  file is read at start and never written.
- A dendrite's targets are peers under `dyn`; a target elsewhere on the
  host is not named yet.
