//! NEST-25 · a shop behind a NAT, dialing in to a host: one outbound
//! WebSocket, its key proven, its activation served on it as
//! `dyn.peer.<name>` at the host for as long as the socket lives — and
//! dialing again, within its backoff, whenever it drops.
//!
//! ```sh
//! cargo run --example dial_shop -- --host wss://host.example/ws --key ~/.plexus/keys/shop.key --name shop \
//!     [--trust key:<host's>] [--known-hosts FILE] [--tls-roots CA.pem]
//! ```
//!
//! With `--trust` the host's key is pinned (the strict mode). Without it the
//! known-hosts file (`$XDG_CONFIG_HOME/plexus/known_hosts`) is read; at first
//! contact the host's key, its fingerprint and the pairing code are shown and
//! nothing is sent or served until you answer `y` — then the key is pinned
//! there. A host whose key is not the one pinned is refused, unasked. While
//! the host's operator has not admitted this key, the shop waits and prints
//! the pairing code they see in `dyn pending`.

use std::path::PathBuf;
use std::time::Duration;

use async_stream::stream;
use futures::Stream;
use plexus_core::plexus::remote_child::pairing::KnownHosts;
use plexus_core::plexus::remote_child::{DialOut, DialState, Exposed, FirstContact};
use serde_json::{json, Value};

/// The shop: what it stocks, and a slow count.
#[derive(Clone)]
pub struct Shop {
    name: String,
}

#[plexus_macros::activation(namespace = "shop", version = "0.1.0", description = "a shop behind a NAT, dialed in")]
impl Shop {
    /// What is on the shelves, and whom it was asked for.
    #[plexus_macros::method]
    async fn items(&self) -> Value {
        let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
        json!({ "shop": self.name, "items": ["flour", "salt", "yeast"], "caller": caller })
    }

    /// Count to `n`, slowly.
    #[plexus_macros::method]
    async fn count(&self, n: u32) -> impl Stream<Item = u32> + Send + 'static {
        stream! {
            for i in 0..n {
                yield i;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

struct Args {
    host: String,
    key: PathBuf,
    name: String,
    trust: Option<String>,
    known_hosts: Option<PathBuf>,
    tls_roots: Option<PathBuf>,
}

fn args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut host, mut key, mut name, mut trust, mut known_hosts, mut tls_roots) = (None, None, None, None, None, None);
    while let Some(a) = it.next() {
        let mut v = || it.next().ok_or(format!("{a} takes a value"));
        match a.as_str() {
            "--host" => host = Some(v()?),
            "--key" => key = Some(PathBuf::from(v()?)),
            "--name" => name = Some(v()?),
            "--trust" => trust = Some(v()?),
            "--known-hosts" => known_hosts = Some(PathBuf::from(v()?)),
            "--tls-roots" => tls_roots = Some(PathBuf::from(v()?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(Args {
        host: host.ok_or("--host wss://HOST/ws is required")?,
        key: key.ok_or("--key FILE (this shop's key, 0600) is required")?,
        name: name.unwrap_or_else(|| "shop".into()),
        trust,
        known_hosts,
        tls_roots,
    })
}

/// First contact: shown, and asked on the terminal; anything but `y` refuses.
async fn ask(c: FirstContact) -> bool {
    eprintln!("dial_shop: first contact with {}", c.url);
    eprintln!("  its key:       {}", c.key);
    eprintln!("  fingerprint:   {}", c.fingerprint);
    if let Some(code) = &c.code {
        eprintln!("  pairing code:  {code}   (the host's operator sees the same code in `dyn pending`)");
    }
    eprint!("Trust this host and pin its key? [y/N] ");
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        matches!(line.trim(), "y" | "Y" | "yes")
    })
    .await
    .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    let a = match args() {
        Ok(a) => a,
        Err(why) => {
            if !why.is_empty() {
                eprintln!("dial_shop: {why}");
            }
            eprintln!("usage: dial_shop --host wss://HOST/ws --key FILE --name NAME [--trust key:<hex>] [--known-hosts FILE] [--tls-roots CA.pem]");
            std::process::exit(2);
        }
    };
    let mut d = DialOut::new(a.host.clone(), &a.key).mount(a.name.clone()).agent(a.name.clone());
    if let Some(t) = &a.trust {
        d = d.trust(t.clone());
    }
    if let Some(r) = &a.tls_roots {
        d = d.tls_roots(r.clone());
    }
    let mut exposed = Exposed::new(d);
    if a.trust.is_none() {
        let Some(file) = a.known_hosts.clone().or_else(KnownHosts::default_path) else {
            eprintln!("dial_shop: no --trust and no known-hosts file (set HOME or --known-hosts)");
            std::process::exit(2);
        };
        exposed = exposed.with_first_contact(file, ask);
    }
    match exposed.principal() {
        Ok(p) => eprintln!("dial_shop: dialing {} as {p}, offering `shop` as `{}`", a.host, a.name),
        Err(why) => {
            eprintln!("dial_shop: {why}");
            std::process::exit(2);
        }
    }
    exposed.serve(Shop { name: a.name.clone() });
    let mut state = exposed.watch();
    let mut said_pending = None;
    let mut said: Option<DialState> = None;
    loop {
        let s = state.borrow_and_update().clone();
        if said.as_ref() != Some(&s) {
            match &s {
                DialState::Mounted { path, relay, .. } => eprintln!("dial_shop: mounted at the host as {path} (its key {relay})"),
                DialState::Down { why } => eprintln!("dial_shop: down ({why}); dialing again"),
                DialState::Refused { why } => {
                    eprintln!("dial_shop: refused: {why}");
                    std::process::exit(1);
                }
                DialState::Stopped => return,
                DialState::Connecting => {}
            }
            said = Some(s);
        }
        tokio::select! {
            changed = state.changed() => if changed.is_err() { return },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                let p = exposed.pending();
                if let Some(code) = p.as_deref().filter(|_| p != said_pending) {
                    eprintln!("dial_shop: waiting for the host's operator — pairing code {code}; they admit it with `dyn admit --code {code}`");
                }
                said_pending = p;
            }
        }
    }
}
