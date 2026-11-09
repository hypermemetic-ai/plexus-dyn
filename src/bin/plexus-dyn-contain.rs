//! DYNAUTH-9: `plexus-dyn-contain [--require] --dir DIR [--deny PATH]…
//! [--env NAME]… -- PROGRAM [ARG]…` — the launcher `dyn` spawns a grown
//! dendrite through: a cleared environment, its own directory, and on Linux
//! a Landlock ruleset denying the host's key and data directories, then
//! `exec PROGRAM`. See `plexus_dyn::contain`.

#[cfg(unix)]
fn main() {
    std::process::exit(plexus_dyn::contain::launcher_main(std::env::args().skip(1).collect()));
}

#[cfg(not(unix))]
fn main() {
    eprintln!("plexus-dyn-contain: a dendrite is spawned through it on unix only");
    std::process::exit(2);
}
