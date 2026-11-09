# Changelog

## [Unreleased]

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
