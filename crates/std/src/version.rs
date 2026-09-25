//! The version the binaries report, and the one thing it switches on.
//!
//! Go sources:
//! - `kcptun/client/main.go:56-57`, `kcptun/server/main.go:61-62`: `var VERSION = "SELFBUILD"`,
//!   replaced at packaging time with `-ldflags "-X main.VERSION=<tag>"`;
//! - `kcptun/client/main.go:59-64`, `kcptun/server/main.go:64-69`: a self-build adds
//!   `log.Lshortfile` to the log flags, "to simplify debugging self-built binaries";
//! - `kcptun/client/main.go:68`, `kcptun/server/main.go:73`: `myApp.Version = VERSION`;
//! - `urfave/cli@v1.22.17 help.go:65,227-229`: `VersionPrinter = printVersion`, which is
//!   `fmt.Fprintf(c.App.Writer, "%v version %v\n", c.App.Name, c.App.Version)`, reached from
//!   `app.go:241` (`ShowVersion`), so `-v` prints `kcptun version SELFBUILD`.
//!
//! The Rust equivalent of the linker flag is the `KCPTUN_VERSION` environment variable at build
//! time (`KCPTUN_VERSION=v20260101 cargo build --release`).

/// `cli.NewApp().Name`, the first word of the `-v` line and of the help's NAME section.
///
/// Both binaries use `kcptun`; only the usage line differs (`client(with SMUX)` /
/// `server(with SMUX)`).
// Go: kcptun/client/main.go:66-67, kcptun/server/main.go:71-72
pub const APP_NAME: &str = "kcptun";

/// The version an unstamped build reports, and the value that turns on `file:line` in the log.
// Go: kcptun/client/main.go:57, kcptun/server/main.go:62
pub const SELFBUILD: &str = "SELFBUILD";

/// Version string printed by `-v` and in the startup log (`version: ...`).
///
/// Set at build time with the `KCPTUN_VERSION` environment variable, like Go's
/// `-ldflags "-X main.VERSION=..."`. Defaults to [`SELFBUILD`], which (as in Go) also enables
/// `file:line` prefixes in log output.
// Go: kcptun/client/main.go:56-57, kcptun/server/main.go:61-62
pub const VERSION: &str = match option_env!("KCPTUN_VERSION") {
    Some(v) => v,
    None => SELFBUILD,
};

/// Whether this build is unstamped, which is what makes log lines carry `file:line`
/// ([`crate::log::default_flags`]).
// Go: kcptun/client/main.go:60, kcptun/server/main.go:65, `if VERSION == "SELFBUILD"`
pub const fn is_selfbuild() -> bool {
    // `str` equality is not available in a const context; compare the bytes instead.
    let (v, want) = (VERSION.as_bytes(), SELFBUILD.as_bytes());
    if v.len() != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if v[i] != want[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The line `-v` / `--version` prints, without its trailing newline.
///
/// `kcptun version SELFBUILD` for an unstamped build. [`crate::cli::App`] prints the same line
/// itself when it handles `--version`; this is the copy the binaries use for a plain `-v` fast
/// path before the flag table exists.
// Go: urfave/cli@v1.22.17 help.go:65,227-229, printVersion
pub fn version_string() -> String {
    format!("{APP_NAME} version {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log;

    /// `kcptun version SELFBUILD`, byte for byte what the Go binaries print for `-v`
    /// (`reference/bin/client_darwin_arm64 -v`).
    #[test]
    fn test_version_string() {
        assert_eq!(version_string(), format!("{APP_NAME} version {VERSION}"));

        // An unstamped build: the only one the test suite is ever run on unless the caller sets
        // KCPTUN_VERSION, in which case only the line's shape can be checked.
        if option_env!("KCPTUN_VERSION").is_none() {
            assert_eq!(VERSION, "SELFBUILD");
            assert_eq!(version_string(), "kcptun version SELFBUILD");
            assert!(is_selfbuild());
        }
    }

    /// `is_selfbuild()` is exactly the condition Go's `main()` uses to add `Lshortfile`.
    #[test]
    fn test_is_selfbuild_drives_log_flags() {
        assert_eq!(is_selfbuild(), VERSION == SELFBUILD);
        let want = if is_selfbuild() {
            log::LSTD_FLAGS | log::LSHORTFILE
        } else {
            log::LSTD_FLAGS
        };
        assert_eq!(log::default_flags(), want);
    }

    /// The app name is what the help and the version line start with.
    #[test]
    fn test_app_name() {
        assert_eq!(APP_NAME, "kcptun");
        assert!(version_string().starts_with("kcptun version "));
    }
}
