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
