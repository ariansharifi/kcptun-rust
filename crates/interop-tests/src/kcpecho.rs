//! Driving the `kcpecho` Go peer (`tools/gointerop/cmd/kcpecho`, see its README): a raw
//! kcp-go echo server and a client that sends the deterministic stream, verifies the echo and
//! prints one JSON report line.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use kcptun_testkit::proc::{Proc, ProcBuilder};
use serde::Deserialize;

/// How long a server may take to print `listening on:`.
pub const SERVER_START_TIMEOUT: Duration = Duration::from_secs(20);

/// The client's JSON report (`clientReport` in kcpecho's `main.go`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KcpEchoReport {
    /// True if the whole stream was echoed back unchanged and nothing failed.
    pub ok: bool,
    /// Bytes sent.
    pub bytes: i64,
    /// Bytes of echo received (and verified up to the first mismatch).
    pub received: i64,
    /// Wall time from dial to the end of the echo.
    pub duration_ms: i64,
    /// SHA-256 of the received echo.
    pub sha256: String,
    /// SHA-256 of the sent stream.
    pub expected_sha256: String,
    /// Effective cipher after kcptun's fallback for unknown names.
    pub crypt: String,
    /// Offset of the first wrong byte, -1 if none.
    pub mismatch_offset: i64,
    /// Go's error text, if any.
    #[serde(default)]
    pub error: Option<String>,
    /// `kcp.DefaultSnmp` with Go's field names.
    pub snmp: serde_json::Map<String, serde_json::Value>,
}

impl KcpEchoReport {
    /// Finds the last line of `output` that parses as a report.
    pub fn from_output(output: &str) -> Option<KcpEchoReport> {
        output
            .lines()
            .rev()
            .filter(|l| l.trim_start().starts_with('{'))
            .find_map(|l| serde_json::from_str(l.trim()).ok())
    }

    /// A counter from [`snmp`](Self::snmp) (e.g. `"BytesSent"`), if present and numeric.
    pub fn snmp_counter(&self, name: &str) -> Option<u64> {
        self.snmp.get(name).and_then(serde_json::Value::as_u64)
    }
}

/// Starts `kcpecho server` listening on `listen` with `args` (for example
/// [`Case::kcpecho_args`](crate::Case::kcpecho_args)), and waits for `listening on:`.
/// Returns the process and the address it printed.
pub fn start_server<I, S>(bin: &Path, listen: SocketAddr, args: I) -> Result<(Proc, String), String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut p = ProcBuilder::new(bin)
        .name("kcpecho-server")
        .arg("server")
        .arg("-listen")
        .arg(listen.to_string())
        .args(args.into_iter().map(Into::into))
        .spawn()
        .map_err(|e| e.to_string())?;
    let line = p
        .wait_for_log_line("listening on:", SERVER_START_TIMEOUT)
        .map_err(|e| e.to_string())?;
    let addr = line
        .split_once("listening on:")
        .map(|(_, a)| a.trim().to_string())
        .unwrap_or_default();
    Ok((p, addr))
}

/// Parameters of one `kcpecho client` run.
#[derive(Clone, Debug)]
pub struct ClientRun {
    /// Server address.
    pub remote: SocketAddr,
    /// Bytes to send.
    pub bytes: u64,
    /// Seed of the deterministic stream.
    pub seed: u64,
    /// kcpecho's own deadline (`-timeout`, seconds).
    pub timeout_secs: u64,
}

impl ClientRun {
    /// A run of `bytes` bytes with seed 1 and a 60 s deadline.
    pub fn new(remote: SocketAddr, bytes: u64) -> Self {
        ClientRun {
            remote,
            bytes,
            seed: 1,
            timeout_secs: 60,
        }
    }

    /// Sets the stream seed.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Sets the deadline.
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

/// Outcome of [`run_client`].
#[derive(Debug)]
pub struct ClientOutcome {
    /// Exit code (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// The parsed report, if the client printed one.
    pub report: Option<KcpEchoReport>,
    /// The whole client log (stdout and stderr).
    pub log: String,
}

/// Runs `kcpecho client` to completion with `args` (for example
/// [`Case::kcpecho_args`](crate::Case::kcpecho_args)). The process is killed if it has not
/// exited 15 s after its own deadline.
pub fn run_client<I, S>(bin: &Path, run: &ClientRun, args: I) -> Result<ClientOutcome, String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut p = ProcBuilder::new(bin)
        .name("kcpecho-client")
        .arg("client")
        .args([
            "-remote".to_string(),
            run.remote.to_string(),
            "-bytes".to_string(),
            run.bytes.to_string(),
            "-seed".to_string(),
            run.seed.to_string(),
            "-timeout".to_string(),
            run.timeout_secs.to_string(),
        ])
        .args(args.into_iter().map(Into::into))
        .spawn()
        .map_err(|e| e.to_string())?;
    let limit = Duration::from_secs(run.timeout_secs.saturating_add(15));
    let status = p.wait_timeout(limit).map_err(|e| e.to_string())?;
    let log = p.log();
    let Some(status) = status else {
        return Err(format!(
            "kcpecho client still running after {limit:?}; log:\n{}",
            p.log_tail()
        ));
    };
    Ok(ClientOutcome {
        exit_code: status.code(),
        report: KcpEchoReport::from_output(&log),
        log,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_from_mixed_output() {
        let out = "kcpecho: SetReadBuffer: something\n\
            {\"ok\":true,\"bytes\":10,\"received\":10,\"duration_ms\":3,\"sha256\":\"ab\",\
            \"expected_sha256\":\"ab\",\"crypt\":\"aes\",\"mismatch_offset\":-1,\
            \"snmp\":{\"BytesSent\":10,\"InErrs\":0}}\n";
        let r = KcpEchoReport::from_output(out).unwrap();
        assert!(r.ok);
        assert_eq!(r.bytes, 10);
        assert_eq!(r.error, None);
        assert_eq!(r.mismatch_offset, -1);
        assert_eq!(r.snmp_counter("BytesSent"), Some(10));
        assert_eq!(r.snmp_counter("Nope"), None);

        let bad = "{\"ok\":false,\"bytes\":10,\"received\":0,\"duration_ms\":3,\"sha256\":\"x\",\
            \"expected_sha256\":\"ab\",\"crypt\":\"aes\",\"mismatch_offset\":-1,\
            \"error\":\"read: timeout\",\"snmp\":{}}";
        let r = KcpEchoReport::from_output(bad).unwrap();
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("read: timeout"));
        assert_eq!(KcpEchoReport::from_output("no json\n{broken"), None);
    }
}
