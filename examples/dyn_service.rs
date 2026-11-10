//! A service with `dyn`, on a WebSocket:
//!
//! ```sh
//! cargo run --example dyn_service -- PORT [--peers FILE] [--data-dir DIR] [--dendrite PATH] [--top-level]
//! synapse -P PORT svc dyn connect --name weather --url ws://127.0.0.1:4801
//! synapse -P PORT svc dyn peers
//! synapse -P PORT svc dyn peer weather weather forecast --city lisbon
//! synapse -P PORT svc weather weather forecast --city lisbon      # with --top-level (NEST-15)
//! synapse -P PORT svc dyn grow --name digest --source "$(cat index.ts)" --targets weather.weather
//! ```
//!
//! No gate: every call is admitted (a service with a gate gives `connect`,
//! `grow` and `disconnect` to `admin`, `peers` to `viewer`, and each call
//! into a peer to whoever holds `dyn.{peer}`).

use std::path::PathBuf;
use std::sync::Arc;

use plexus_core::DynamicHub;
use plexus_dyn::{DynActivation, DynOptions};
use plexus_transport::TransportServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).with_writer(std::io::stderr).init();
    let mut args = std::env::args().skip(1);
    let usage = "usage: dyn_service PORT [--peers FILE] [--data-dir DIR] [--dendrite PATH] [--top-level]";
    let port: u16 = args.next().ok_or_else(|| anyhow::anyhow!(usage))?.parse()?;
    let mut opts = DynOptions::default();
    while let Some(a) = args.next() {
        // NEST-15: each peer at the service's top level too (`svc weather …`).
        if a == "--top-level" {
            opts.top_level = true;
            continue;
        }
        let v = args.next().ok_or_else(|| anyhow::anyhow!(usage))?;
        match a.as_str() {
            "--peers" => opts.peers_file = Some(PathBuf::from(v)),
            "--data-dir" => opts.data_dir = PathBuf::from(v),
            "--dendrite" => opts.dendrite = PathBuf::from(v),
            _ => anyhow::bail!(usage),
        }
    }
    let dyn_ = DynActivation::new(opts);
    // NEST-21: the service's configuration served as `config`.
    let service = Arc::new(DynamicHub::new("svc").register(dyn_.clone()).with_config_service());
    dyn_.start(&service).await.map_err(|e| anyhow::anyhow!(e))?;
    // KEEL-19: the principal this service dials its peers as — what each
    // keyed peer trusts (`serve_child_ws`'s `trusted`).
    eprintln!("dial principal: {}", dyn_.dial_principal().unwrap_or_else(|| "none (no keyed peer mounts)".into()));
    for p in dyn_.list() {
        eprintln!("peer {}: {}", p.name, if p.up { "up".to_string() } else { format!("down ({})", p.why.unwrap_or_default()) });
    }
    TransportServer::builder(service, |h| Ok(DynamicHub::arc_into_rpc_module(h)?))
        .without_registry()
        .with_websocket(port)
        .with_allowed_hosts([format!("127.0.0.1:{port}"), format!("localhost:{port}")])
        .build()
        .await?
        .serve()
        .await
}
