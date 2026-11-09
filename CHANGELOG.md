# Changelog

## [Unreleased] — 0.1.0

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
