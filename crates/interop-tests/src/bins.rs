//! Locating the Go reference binaries, the Go interop peers and our own Rust binaries.
//!
//! | Implementation | Directories searched | File names tried, in order |
//! |---|---|---|
//! | Go | `$KCPTUN_GO_BIN_DIR`, else `<workspace>/reference/bin` | `<name>_<goos>_<goarch>` (e.g. `kcpecho_darwin_arm64`, as `tools/fetch-reference.sh` builds them), then `kg-<name>` (the lab-arm64 lab naming of `tools/lab/deploy.sh --go`) |
//! | Rust | `$KCPTUN_RS_BIN_DIR`, else `<target>/release` then `<target>/debug` | `kcptun-<name>`, then `kr-<name>` (lab naming) |
//!
//! `<target>` is `$CARGO_TARGET_DIR` (a relative path is assumed to be relative to the
//! workspace root, i.e. cargo was started there; cargo itself resolves it against its own
//! working directory) or
//! `<workspace>/target`. An environment variable that is set (and not empty) replaces the
//! defaults entirely, so a lab run never silently picks up a stale laptop build. Only regular
//! files with an execute bit count.
//!
//! The resolution itself ([`resolve`], [`go_dirs`], [`rust_dirs`], [`go_names`],
//! [`rust_names`]) is pure and unit-tested; [`go_bin`] and [`rust_bin`] feed it the process
//! environment.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// Environment variable naming the directory of the Go binaries.
pub const GO_BIN_DIR_ENV: &str = "KCPTUN_GO_BIN_DIR";
/// Environment variable naming the directory of the Rust binaries.
pub const RS_BIN_DIR_ENV: &str = "KCPTUN_RS_BIN_DIR";

/// Which implementation a binary belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Impl {
    /// The Go reference (kcptun `client`/`server`) or a `tools/gointerop` peer.
    Go,
    /// This repository's Rust build.
    Rust,
}

impl Impl {
    /// Short tag used in test labels: `go` or `rs`.
    pub fn tag(self) -> &'static str {
        match self {
            Impl::Go => "go",
            Impl::Rust => "rs",
        }
    }
}

impl fmt::Display for Impl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// A binary could not be found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinNotFound {
    /// Implementation searched.
    pub implementation: Impl,
    /// Logical name (`kcpecho`, `client`, ...).
    pub name: String,
    /// Every path that was tried, in order.
    pub tried: Vec<PathBuf>,
    /// The environment variable that overrides the search directory.
    pub env_var: &'static str,
    /// Whether that variable was set (then only its directory was searched).
    pub env_set: bool,
}

impl fmt::Display for BinNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.implementation {
            Impl::Go => "Go binary",
            Impl::Rust => "Rust binary",
        };
        writeln!(f, "{what} `{}` not found; tried:", self.name)?;
        for p in &self.tried {
            writeln!(f, "  {}", p.display())?;
        }
        match (self.implementation, self.env_set) {
            (Impl::Go, false) => write!(
                f,
                "Build the Go reference binaries and interop peers with `tools/fetch-reference.sh` \
                 (`tools/fetch-reference.sh --skip-latest --skip-tests` is enough), or point \
                 {} at a directory that holds them.",
                self.env_var
            ),
            (Impl::Go, true) => write!(
                f,
                "{} is set, so only that directory was searched. Unset it to use \
                 reference/bin, or deploy the binaries there (on lab-arm64: \
                 `tools/lab/deploy.sh --go`; locally: `tools/fetch-reference.sh`).",
                self.env_var
            ),
            (Impl::Rust, false) => write!(
                f,
                "Build it with `cargo build --release -p kcptun-{name}` (or a debug build) — or, \
                 for a binary that belongs to another crate, \
                 `cargo build --release -p <crate> --bin kcptun-{name}` (`kcptun-smuxecho` lives \
                 in `kcptun-interop-tests`). You can also point {env} at a directory that holds \
                 it.",
                name = self.name,
                env = self.env_var
            ),
            (Impl::Rust, true) => write!(
                f,
                "{} is set, so only that directory was searched. Unset it to use \
                 target/release and target/debug, or deploy the binary there (on lab-arm64: \
                 `tools/lab/deploy.sh --rust`).",
                self.env_var
            ),
        }
    }
}

impl std::error::Error for BinNotFound {}

/// The workspace root, fixed at compile time (`crates/interop-tests/../..`).
pub fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest)
        .to_path_buf()
}

/// Go's `GOOS` for the running platform (`darwin`, `linux`, ...).
pub fn goos() -> &'static str {
    goos_of(std::env::consts::OS)
}

/// Go's `GOARCH` for the running platform (`arm64`, `amd64`, ...).
pub fn goarch() -> &'static str {
    goarch_of(std::env::consts::ARCH)
}

/// Maps Rust's `std::env::consts::OS` to Go's `GOOS`.
pub fn goos_of(os: &'static str) -> &'static str {
    match os {
        "macos" => "darwin",
        other => other, // linux, windows, freebsd, ... are spelled the same
    }
}

/// Maps Rust's `std::env::consts::ARCH` to Go's `GOARCH`.
pub fn goarch_of(arch: &'static str) -> &'static str {
    match arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        "x86" => "386",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        "loongarch64" => "loong64",
        other => other, // mips, mips64, riscv64, s390x
    }
}

/// Treats an unset or empty variable as unset.
fn non_empty(v: Option<OsString>) -> Option<OsString> {
    v.filter(|v| !v.is_empty())
}

/// Directories searched for Go binaries, given the value of [`GO_BIN_DIR_ENV`].
pub fn go_dirs(env: Option<OsString>, workspace: &Path) -> Vec<PathBuf> {
    match non_empty(env) {
        Some(dir) => vec![PathBuf::from(dir)],
        None => vec![workspace.join("reference").join("bin")],
    }
}

/// Directories searched for Rust binaries, given the values of [`RS_BIN_DIR_ENV`] and
/// `CARGO_TARGET_DIR`.
pub fn rust_dirs(
    env: Option<OsString>,
    cargo_target_dir: Option<OsString>,
    workspace: &Path,
) -> Vec<PathBuf> {
    if let Some(dir) = non_empty(env) {
        return vec![PathBuf::from(dir)];
    }
    let target = match non_empty(cargo_target_dir) {
        Some(t) => workspace.join(t), // an absolute path replaces the workspace prefix
        None => workspace.join("target"),
    };
    vec![target.join("release"), target.join("debug")]
}

/// File names tried for the Go binary `name` on `goos`/`goarch`.
pub fn go_names(name: &str, goos: &str, goarch: &str) -> Vec<String> {
    let exe = std::env::consts::EXE_SUFFIX;
    vec![
        format!("{name}_{goos}_{goarch}{exe}"),
        format!("kg-{name}{exe}"),
    ]
}

/// File names tried for the Rust binary `name`.
pub fn rust_names(name: &str) -> Vec<String> {
    let exe = std::env::consts::EXE_SUFFIX;
    vec![format!("kcptun-{name}{exe}"), format!("kr-{name}{exe}")]
}

/// True if `path` is a regular file (after following links) that can be executed.
pub fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Returns the first `dir/name` (directories outer, names inner) that [`is_executable`],
/// or every candidate path tried.
pub fn resolve(dirs: &[PathBuf], names: &[String]) -> Result<PathBuf, Vec<PathBuf>> {
    let candidates: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|d| names.iter().map(move |n| d.join(n)))
        .collect();
    match candidates.iter().find(|p| is_executable(p)) {
        Some(p) => Ok(p.clone()),
        None => Err(candidates),
    }
}

/// Finds the Go binary `name` (`client`, `server`, `kcpecho`, `smuxecho`, ...) as described
/// in the [module docs](self).
pub fn go_bin(name: &str) -> Result<PathBuf, BinNotFound> {
    let env = std::env::var_os(GO_BIN_DIR_ENV);
    let env_set = non_empty(env.clone()).is_some();
    let dirs = go_dirs(env, &workspace_root());
    resolve(&dirs, &go_names(name, goos(), goarch())).map_err(|tried| BinNotFound {
        implementation: Impl::Go,
        name: name.to_string(),
        tried,
        env_var: GO_BIN_DIR_ENV,
        env_set,
    })
}

/// Finds the Rust binary `name` (`client` or `server`) as described in the
/// [module docs](self).
pub fn rust_bin(name: &str) -> Result<PathBuf, BinNotFound> {
    let env = std::env::var_os(RS_BIN_DIR_ENV);
    let env_set = non_empty(env.clone()).is_some();
    let dirs = rust_dirs(env, std::env::var_os("CARGO_TARGET_DIR"), &workspace_root());
    resolve(&dirs, &rust_names(name)).map_err(|tried| BinNotFound {
        implementation: Impl::Rust,
        name: name.to_string(),
        tried,
        env_var: RS_BIN_DIR_ENV,
        env_set,
    })
}

/// Finds binary `name` of implementation `which`.
pub fn bin(which: Impl, name: &str) -> Result<PathBuf, BinNotFound> {
    match which {
        Impl::Go => go_bin(name),
        Impl::Rust => rust_bin(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, name: &str, exec: bool) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if exec { 0o755 } else { 0o644 };
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = exec;
        p
    }

    #[test]
    fn go_platform_names() {
        assert_eq!(goos_of("macos"), "darwin");
        assert_eq!(goos_of("linux"), "linux");
        assert_eq!(goarch_of("aarch64"), "arm64");
        assert_eq!(goarch_of("x86_64"), "amd64");
        assert_eq!(goarch_of("x86"), "386");
        assert_eq!(goarch_of("riscv64"), "riscv64");
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!((goos(), goarch()), ("darwin", "arm64"));
        }
        if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            assert_eq!((goos(), goarch()), ("linux", "arm64"));
        }
    }

    #[test]
    fn candidate_names_and_dirs() {
        let ws = Path::new("/ws");
        assert_eq!(
            go_names("kcpecho", "darwin", "arm64"),
            ["kcpecho_darwin_arm64", "kg-kcpecho"]
        );
        assert_eq!(rust_names("client"), ["kcptun-client", "kr-client"]);
        assert_eq!(go_dirs(None, ws), [PathBuf::from("/ws/reference/bin")]);
        assert_eq!(
            go_dirs(Some("".into()), ws),
            [PathBuf::from("/ws/reference/bin")],
            "an empty variable counts as unset"
        );
        assert_eq!(
            go_dirs(Some("/lab/bin/go".into()), ws),
            [PathBuf::from("/lab/bin/go")]
        );
        assert_eq!(
            rust_dirs(None, None, ws),
            [
                PathBuf::from("/ws/target/release"),
                PathBuf::from("/ws/target/debug")
            ]
        );
        assert_eq!(
            rust_dirs(None, Some("out".into()), ws),
            [
                PathBuf::from("/ws/out/release"),
                PathBuf::from("/ws/out/debug")
            ]
        );
        assert_eq!(
            rust_dirs(None, Some("/abs/tgt".into()), ws),
            [
                PathBuf::from("/abs/tgt/release"),
                PathBuf::from("/abs/tgt/debug")
            ]
        );
        assert_eq!(
            rust_dirs(Some("/lab/bin/rust".into()), Some("/abs/tgt".into()), ws),
            [PathBuf::from("/lab/bin/rust")]
        );
        // Compile-time path only (tests must not read workspace files: they also run on
        // lab-arm64, where this path does not exist).
        assert_eq!(
            workspace_root().join("crates").join("interop-tests"),
            Path::new(env!("CARGO_MANIFEST_DIR"))
        );
    }

    #[test]
    fn resolve_prefers_platform_name_then_lab_name() {
        let d = tempfile::tempdir().unwrap();
        let dirs = vec![d.path().to_path_buf()];
        let names = go_names("kcpecho", "linux", "arm64");

        let err = resolve(&dirs, &names).unwrap_err();
        assert_eq!(
            err,
            [
                d.path().join("kcpecho_linux_arm64"),
                d.path().join("kg-kcpecho")
            ]
        );

        let lab = touch(d.path(), "kg-kcpecho", true);
        assert_eq!(resolve(&dirs, &names).unwrap(), lab);
        let plat = touch(d.path(), "kcpecho_linux_arm64", true);
        assert_eq!(resolve(&dirs, &names).unwrap(), plat);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_skips_non_executables_and_directories() {
        let d = tempfile::tempdir().unwrap();
        let dirs = vec![d.path().to_path_buf()];
        let names = rust_names("server");
        touch(d.path(), "kcptun-server", false);
        std::fs::create_dir(d.path().join("kr-server")).unwrap();
        assert!(resolve(&dirs, &names).is_err());
        std::fs::remove_dir(d.path().join("kr-server")).unwrap();
        let kr = touch(d.path(), "kr-server", true);
        assert_eq!(resolve(&dirs, &names).unwrap(), kr);
    }

    #[test]
    fn resolve_searches_directories_in_order() {
        let release = tempfile::tempdir().unwrap();
        let debug = tempfile::tempdir().unwrap();
        let dirs = vec![release.path().to_path_buf(), debug.path().to_path_buf()];
        let names = rust_names("client");
        let dbg = touch(debug.path(), "kcptun-client", true);
        assert_eq!(resolve(&dirs, &names).unwrap(), dbg);
        // A lab-named binary in the first directory wins over the second directory.
        let rel = touch(release.path(), "kr-client", true);
        assert_eq!(resolve(&dirs, &names).unwrap(), rel);
    }

    #[test]
    fn not_found_message_is_actionable() {
        let e = BinNotFound {
            implementation: Impl::Go,
            name: "kcpecho".into(),
            tried: vec!["/ws/reference/bin/kcpecho_darwin_arm64".into()],
            env_var: GO_BIN_DIR_ENV,
            env_set: false,
        };
        let s = e.to_string();
        assert!(s.contains("Go binary `kcpecho` not found"), "{s}");
        assert!(s.contains("/ws/reference/bin/kcpecho_darwin_arm64"), "{s}");
        assert!(s.contains("tools/fetch-reference.sh"), "{s}");
        assert!(s.contains("KCPTUN_GO_BIN_DIR"), "{s}");

        let e = BinNotFound {
            implementation: Impl::Rust,
            name: "server".into(),
            tried: vec![],
            env_var: RS_BIN_DIR_ENV,
            env_set: true,
        };
        let s = e.to_string();
        assert!(s.contains("Rust binary `server` not found"), "{s}");
        assert!(s.contains("KCPTUN_RS_BIN_DIR is set"), "{s}");
        let e = BinNotFound {
            env_set: false,
            ..e
        };
        assert!(
            e.to_string()
                .contains("cargo build --release -p kcptun-server")
        );
    }

    #[test]
    fn impl_tags() {
        assert_eq!(Impl::Go.to_string(), "go");
        assert_eq!(Impl::Rust.tag(), "rs");
    }
}
