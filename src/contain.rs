//! DYNAUTH-9 (TM-5): a grown dendrite, contained until microVMs.
//!
//! A dendrite is arbitrary code, run as the host's OS user. Until it runs in
//! a microVM, `dyn` spawns it through `plexus-dyn-contain`, a launcher that
//! runs in the child before it becomes the dendrite and:
//!
//! - **clears its environment**: `PATH`, `LANG` and `PLEXUS_CHILD_NAME`
//!   pass, plus each name of [`Containment::env`]; `HOME` and `TMPDIR` are
//!   directories of its own (`<dir>/.home`, `<dir>/.tmp`); nothing else of
//!   the host's environment reaches it;
//! - **starts in its own directory** (`cwd` = the dendrite's directory);
//! - **on Linux, takes a Landlock ruleset** before it executes the
//!   dendrite: everything it may read is granted explicitly, and the
//!   denied paths are carved out — `dyn`'s data directory (every other
//!   dendrite's), `~/.plexus` (keys and sessions), `~/.ssh`, `~/.gnupg`,
//!   `~/.password-store`, the host's own dial key, and each of
//!   [`Containment::deny`]. It writes only inside its own directory (and
//!   `/dev/null`). Where the kernel knows them (ABI 6, 9) it also may not
//!   signal processes outside it, reach abstract UNIX sockets made outside
//!   it, or connect to a UNIX socket by path outside its directory.
//!
//! Where Landlock is not there (another OS, an old kernel, the launcher not
//! found) the dendrite runs with the cleared environment only and a warning
//! is logged — unless [`Containment::require`], which refuses to start it.
//!
//! Not a sandbox: network access is not restricted, and a process of the
//! same user can still be read through what the kernel allows it. `dyn.grow`
//! stays the admin's and host-equivalent trust (TM-5).

use std::path::{Path, PathBuf};

/// The launcher's name, beside the host's executable or on `PATH`.
pub const LAUNCHER: &str = "plexus-dyn-contain";

/// How a dendrite is contained.
#[derive(Debug, Clone)]
pub struct Containment {
    /// Contain dendrites at all (default `true`).
    pub enabled: bool,
    /// Refuse to start a dendrite that cannot be contained by Landlock
    /// (default `false`: start it with a cleared environment and a warning).
    pub require: bool,
    /// The launcher; `None`: `plexus-dyn-contain` beside the host's
    /// executable, else on `PATH`.
    pub launcher: Option<PathBuf>,
    /// More paths no dendrite may read (the host's signing key, a bridge's
    /// sealed store and its key, …), beside the defaults.
    pub deny: Vec<PathBuf>,
    /// Environment variables passed to a dendrite, beyond `PATH`, `LANG` and
    /// `PLEXUS_CHILD_NAME`. A name here must also reach the launcher
    /// (plexus-core's `ChildOptions::env`).
    pub env: Vec<String>,
}

impl Default for Containment {
    fn default() -> Self {
        Self { enabled: true, require: false, launcher: None, deny: Vec::new(), env: Vec::new() }
    }
}

impl Containment {
    /// The launcher to use, if one is found.
    pub fn find_launcher(&self) -> Option<PathBuf> {
        if let Some(l) = &self.launcher {
            return l.is_file().then(|| l.clone());
        }
        let beside = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join(LAUNCHER)));
        if let Some(b) = beside.filter(|b| b.is_file()) {
            return Some(b);
        }
        std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(LAUNCHER)).find(|c| c.is_file()))
    }

    /// The paths denied by default to a dendrite of a host whose data
    /// directory is `data_dir`: that, and the user's key directories.
    pub fn default_deny(data_dir: &Path) -> Vec<PathBuf> {
        let mut out = vec![data_dir.to_path_buf()];
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            for d in [".plexus", ".ssh", ".gnupg", ".password-store"] {
                out.push(home.join(d));
            }
        }
        out
    }

    /// `argv` (the dendrite's command) wrapped to run contained in `dir`,
    /// denying `deny`. `Err`: it cannot be contained and must not start.
    pub fn wrap(&self, dir: &Path, deny: &[PathBuf], argv: Vec<String>) -> Result<Vec<String>, String> {
        if !self.enabled {
            return Ok(argv);
        }
        let mut out = Vec::new();
        match self.find_launcher() {
            Some(l) => {
                out.push(l.display().to_string());
                if self.require {
                    out.push("--require".into());
                }
                out.extend(["--dir".into(), dir.display().to_string()]);
                for d in deny {
                    out.extend(["--deny".into(), d.display().to_string()]);
                }
                for e in &self.env {
                    out.extend(["--env".into(), e.clone()]);
                }
                out.push("--".into());
            }
            None if self.require => {
                return Err(format!("{LAUNCHER} is not beside the service nor on PATH, and containment is required: the dendrite is not started"));
            }
            None => {
                tracing::warn!(target: "plexus::dyn", "{LAUNCHER} not found: the dendrite runs with a cleared environment and no Landlock ruleset (it can read what the host's user can)");
                // The environment cleared all the same, by env(1).
                out.extend(["env".into(), "-i".into(), "-C".into(), dir.display().to_string()]);
                for (k, v) in kept_env(&self.env, dir) {
                    out.push(format!("{k}={v}"));
                }
            }
        }
        out.extend(argv);
        Ok(out)
    }
}

/// What a contained dendrite's environment is: the few names that pass,
/// and its own `HOME` and `TMPDIR`.
fn kept_env(more: &[String], dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = ["PATH", "LANG", "PLEXUS_CHILD_NAME"]
        .iter()
        .map(|k| k.to_string())
        .chain(more.iter().cloned())
        .filter_map(|k| std::env::var(&k).ok().map(|v| (k, v)))
        .collect();
    out.push(("HOME".into(), dir.join(".home").display().to_string()));
    out.push(("TMPDIR".into(), dir.join(".tmp").display().to_string()));
    out
}

/// The launcher: `plexus-dyn-contain [--require] --dir DIR [--deny PATH]…
/// [--env NAME]… -- PROGRAM [ARG]…`. Contains itself, then becomes
/// `PROGRAM`; returns only on failure (its exit code).
#[cfg(unix)]
pub fn launcher_main(args: Vec<String>) -> i32 {
    use std::os::unix::process::CommandExt;
    let mut require = false;
    let mut dir = None;
    let mut deny = Vec::new();
    let mut env = Vec::new();
    let mut it = args.into_iter();
    let program: Vec<String> = loop {
        match it.next().as_deref() {
            Some("--require") => require = true,
            Some("--dir") => dir = it.next().map(PathBuf::from),
            Some("--deny") => deny.extend(it.next().map(PathBuf::from)),
            Some("--env") => env.extend(it.next()),
            Some("--") => break it.collect(),
            other => {
                eprintln!("{LAUNCHER}: unexpected {other:?}; usage: {LAUNCHER} [--require] --dir DIR [--deny PATH]… [--env NAME]… -- PROGRAM [ARG]…");
                return 2;
            }
        }
    };
    let (Some(dir), Some(prog)) = (dir, program.first()) else {
        eprintln!("{LAUNCHER}: --dir and a program are required");
        return 2;
    };
    for d in [dir.join(".home"), dir.join(".tmp")] {
        if let Err(e) = std::fs::create_dir_all(&d) {
            eprintln!("{LAUNCHER}: {}: {e}", d.display());
            return 1;
        }
    }
    let vars = kept_env(&env, &dir);
    match landlock::restrict(&dir, &deny) {
        Ok(said) => eprintln!("{LAUNCHER}: contained: {said}"),
        Err(why) if require => {
            eprintln!("{LAUNCHER}: not contained ({why}) and containment is required: not started");
            return 3;
        }
        Err(why) => eprintln!("{LAUNCHER}: WARNING not contained by Landlock ({why}): the environment is cleared, nothing more"),
    }
    let err = std::process::Command::new(prog).args(&program[1..]).env_clear().envs(vars).current_dir(&dir).exec();
    eprintln!("{LAUNCHER}: {prog}: {err}");
    126
}

#[cfg(target_os = "linux")]
pub(crate) mod landlock {
    use std::path::{Path, PathBuf};

    use landlock::{
        path_beneath_rules, Access, AccessFs, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        Scope, ABI,
    };

    /// The newest ABI this build knows; a kernel with less is met best-effort.
    const ABI_: ABI = ABI::V9;

    /// `p` made absolute and real as far as it exists, the rest appended —
    /// so a path not made yet is still carved out where it would be.
    fn real(p: &Path) -> PathBuf {
        let mut head = p.to_path_buf();
        let mut tail = Vec::new();
        loop {
            if let Ok(r) = head.canonicalize() {
                return tail.into_iter().rev().fold(r, |acc: PathBuf, c| acc.join(c));
            }
            match (head.file_name().map(|f| f.to_os_string()), head.parent().map(Path::to_path_buf)) {
                (Some(f), Some(parent)) => {
                    tail.push(f);
                    head = parent;
                }
                _ => return p.to_path_buf(),
            }
        }
    }

    /// One line of `/proc/self/mountinfo`: the filesystem, the directory of
    /// it that is mounted, and where.
    pub(super) struct Mount {
        pub dev: String,
        pub source: String,
        pub root: PathBuf,
        pub point: PathBuf,
    }

    /// `\040` and its kind, as mountinfo escapes a path.
    pub(super) fn unescape(s: &str) -> PathBuf {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(out))
    }

    fn mounts() -> Vec<Mount> {
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        text.lines()
            .filter_map(|l| {
                let (head, tail) = l.split_once(" - ")?;
                let f: Vec<&str> = head.split(' ').collect();
                let t: Vec<&str> = tail.split(' ').collect();
                Some(Mount { dev: f.get(2)?.to_string(), source: t.get(1)?.to_string(), root: unescape(f.get(3)?), point: unescape(f.get(4)?) })
            })
            .collect()
    }

    /// Every path `d` is reachable by through the mounts: a bind mount (or a
    /// btrfs subvolume mounted twice: `/tmp` of `/var/tmpdisk`, `/var/home`
    /// of `/sysroot/home`) shows the same files at another path, and a
    /// Landlock rule follows the files, not the path.
    pub(super) fn aliases(d: &Path, mounts: &[Mount]) -> Vec<PathBuf> {
        let mut out = vec![d.to_path_buf()];
        let Some(m) = mounts.iter().filter(|m| d.starts_with(&m.point)).max_by_key(|m| m.point.components().count()) else { return out };
        let Ok(rest) = d.strip_prefix(&m.point) else { return out };
        let rel = m.root.join(rest);
        let same_fs = |o: &Mount| o.dev == m.dev || (o.source == m.source && o.source.starts_with("/dev/"));
        for o in mounts.iter().filter(|o| same_fs(o)) {
            if let Ok(under) = rel.strip_prefix(&o.root) {
                let p = o.point.join(under);
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Every path under `/` that is readable: the tree, minus each denied
    /// path, as the fewest whole subtrees — a directory that holds a denied
    /// path is not granted itself; its other entries are. Symbolic links
    /// are skipped (their targets are granted, or not, where they are).
    fn readable(deny: &[PathBuf]) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![PathBuf::from("/")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let p = e.path();
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_symlink() || deny.iter().any(|d| *d == p) {
                    continue;
                }
                if deny.iter().any(|d| d.starts_with(&p)) {
                    if ft.is_dir() {
                        stack.push(p);
                    }
                    continue;
                }
                out.push(p);
            }
        }
        out
    }

    /// Restrict this process (and what it executes): read and execute all
    /// but `deny`; everything in `dir`; write `/dev/null`. `Ok`: what is
    /// enforced, said; `Err`: why nothing is.
    pub fn restrict(dir: &Path, deny: &[PathBuf]) -> Result<String, String> {
        let dir = real(dir);
        let mounts = mounts();
        let deny: Vec<PathBuf> = deny.iter().map(|d| real(d)).collect();
        let shown = deny.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(", ");
        let deny: Vec<PathBuf> = deny.iter().flat_map(|d| aliases(d, &mounts)).collect();
        if deny.iter().any(|d| dir.starts_with(d) && *d == dir) {
            return Err(format!("its own directory {} is denied", dir.display()));
        }
        let read = AccessFs::from_read(ABI_);
        let all = AccessFs::from_all(ABI_);
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(all)
            .and_then(|r| r.scope(Scope::from_all(ABI_)))
            .and_then(|r| r.create())
            .map_err(|e| e.to_string())?;
        let rules = ruleset
            .add_rules(path_beneath_rules(readable(&deny), read))
            .and_then(|r| r.add_rules(path_beneath_rules([&dir], all)))
            .and_then(|r| r.add_rules(path_beneath_rules(["/dev/null"], BitFlags::from(AccessFs::ReadFile) | AccessFs::WriteFile)))
            .map_err(|e| e.to_string())?;
        let status = rules.restrict_self().map_err(|e| e.to_string())?;
        let more = deny.len().saturating_sub(shown.matches(", ").count() + 1);
        let denied = format!("{shown} (and {more} paths the same files are mounted at)");
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(format!("Landlock fully enforced; denied: {denied}")),
            RulesetStatus::PartiallyEnforced => Ok(format!("Landlock partially enforced (an older kernel's ABI); denied: {denied}")),
            RulesetStatus::NotEnforced => Err("Landlock is not supported by this kernel".into()),
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod landlock {
    use std::path::{Path, PathBuf};

    pub fn restrict(_dir: &Path, _deny: &[PathBuf]) -> Result<String, String> {
        Err("Landlock is Linux's".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::landlock::*;
    use std::path::PathBuf;

    fn m(dev: &str, source: &str, root: &str, point: &str) -> Mount {
        Mount { dev: dev.into(), source: source.into(), root: root.into(), point: point.into() }
    }

    #[test]
    fn a_denied_path_is_denied_wherever_it_is_mounted() {
        // As on an ostree machine: /tmp is /var/tmpdisk, /var/home a subvolume.
        let mounts = [
            m("0:30", "composefs", "/", "/"),
            m("0:54", "/dev/nvme0n1p3", "/var", "/var"),
            m("0:54", "/dev/nvme0n1p3", "/var/tmpdisk", "/tmp"),
            m("0:61", "/dev/nvme0n1p3", "/home", "/var/home"),
            m("0:37", "/dev/nvme0n1p3", "/root", "/sysroot"),
            m("0:70", "tmpfs", "/", "/run"),
            m("0:71", "tmpfs", "/", "/dev/shm"),
        ];
        let got = aliases(&PathBuf::from("/tmp/keys"), &mounts);
        assert_eq!(got, [PathBuf::from("/tmp/keys"), PathBuf::from("/var/tmpdisk/keys")]);
        let got = aliases(&PathBuf::from("/var/home/u/.plexus"), &mounts);
        assert_eq!(got, [PathBuf::from("/var/home/u/.plexus")], "the home subvolume is mounted once");
        let got = aliases(&PathBuf::from("/run/secret"), &mounts);
        assert_eq!(got, [PathBuf::from("/run/secret")], "another tmpfs is another filesystem");
    }

    #[test]
    fn mountinfo_paths_are_unescaped() {
        assert_eq!(unescape(r"/a\040b/c\134d"), PathBuf::from("/a b/c\\d"));
        assert_eq!(unescape("/plain"), PathBuf::from("/plain"));
    }
}
