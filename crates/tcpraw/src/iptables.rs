//! The `iptables`/`ip6tables` rules that suppress the kernel's own TCP traffic, and the slice of
//! [go-iptables](https://github.com/coreos/go-iptables) tcpraw drives them with.
//!
//! tcpraw hands the kernel a real TCP connection with **TTL (hop limit) 1** and then drops
//! everything the kernel sends on that 5-tuple with a `filter/OUTPUT` rule matching TTL 1, so
//! only the segments tcpraw crafts itself reach the wire. Both halves are needed: the TTL keeps
//! the segments from leaving the host if the rule is missing, and the rule keeps the first hop
//! from answering ICMP Time Exceeded.
//!
//! Only rules this process appended are deleted again (`Close`), exactly as Go does, so a
//! pre-existing identical rule an operator installed is left alone.
//!
//! Go reference: `tcpraw@v1.2.32 tcp_linux.go:Dial()`/`Listen()`/`Close()`,
//! `go-iptables@v0.8.0 iptables/{iptables.go,lock.go}`.
//!
//! The module compiles everywhere so that its argument construction stays under test on the
//! development host; only Linux has the binaries it drives.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Which binary a rule goes to, and therefore which match extension it uses.
// Go: go-iptables@v0.8.0 iptables/iptables.go:Protocol
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// `iptables`, rules matching `-m ttl --ttl-eq 1`.
    #[default]
    IPv4,
    /// `ip6tables`, rules matching `-m hl --hl-eq 1`.
    IPv6,
}

/// The binary name `New` looks up for a protocol.
// Go: go-iptables@v0.8.0 iptables/iptables.go:getIptablesCommand()
pub fn iptables_command(proto: Protocol) -> &'static str {
    match proto {
        Protocol::IPv4 => "iptables",
        Protocol::IPv6 => "ip6tables",
    }
}

/// The table and chain every tcpraw rule lives in.
// Go: tcpraw@v1.2.32 tcp_linux.go:Dial() (`ipt.Exists("filter", "OUTPUT", rule...)`)
pub const TABLE: &str = "filter";
/// See [`TABLE`].
pub const CHAIN: &str = "OUTPUT";

/// The `filter/OUTPUT` rule a **dialled** connection installs: drop everything the kernel emits
/// on this exact 5-tuple with TTL (hop limit) 1.
///
/// The operands are Go's, in Go's order, spelled the way Go spells them: `laddr`/`lport` come
/// from `net.SplitHostPort(tcpconn.LocalAddr().String())`, `rip` from `raddr.IP.String()` (so an
/// IPv4-mapped address prints as dotted quad, see [`addr::ip_string`]) and `rport` from
/// `fmt.Sprint(raddr.Port)`.
// Go: tcpraw@v1.2.32 tcp_linux.go:Dial() (the two `rule := []string{…}` literals)
pub fn dial_rule(proto: Protocol, laddr: &str, lport: &str, rip: &str, rport: u16) -> Vec<String> {
    let (module, matcher) = ttl_match(proto);
    vec![
        "-m".into(),
        module.into(),
        matcher.into(),
        "1".into(),
        "-p".into(),
        "tcp".into(),
        "-s".into(),
        laddr.into(),
        "--sport".into(),
        lport.into(),
        "-d".into(),
        rip.into(),
        "--dport".into(),
        rport.to_string(),
        "-j".into(),
        "DROP".into(),
    ]
}

/// The `filter/OUTPUT` rule a **listening** connection installs: drop everything the kernel emits
/// from the listening port with TTL (hop limit) 1.
///
/// Unlike the dialled rule this names no peer: a server does not know its clients in advance,
/// so one rule per protocol covers every accepted connection. `lport` is Go's
/// `fmt.Sprint(laddr.Port)`, the port of the **resolved** listen address rather than the one the
/// kernel assigned; the two differ only for a `:0` listen, which tcpraw cannot serve anyway.
// Go: tcpraw@v1.2.32 tcp_linux.go:Listen() (the two `rule := []string{…}` literals)
pub fn listen_rule(proto: Protocol, lport: u16) -> Vec<String> {
    let (module, matcher) = ttl_match(proto);
    vec![
        "-m".into(),
        module.into(),
        matcher.into(),
        "1".into(),
        "-p".into(),
        "tcp".into(),
        "--sport".into(),
        lport.to_string(),
        "-j".into(),
        "DROP".into(),
    ]
}

/// The TTL match extension of a protocol: `-m ttl --ttl-eq` for IPv4, `-m hl --hl-eq` for IPv6.
fn ttl_match(proto: Protocol) -> (&'static str, &'static str) {
    match proto {
        Protocol::IPv4 => ("ttl", "--ttl-eq"),
        Protocol::IPv6 => ("hl", "--hl-eq"),
    }
}

/// A resolved `iptables` (or `ip6tables`) binary and the capabilities its version has.
// Go: go-iptables@v0.8.0 iptables/iptables.go:IPTables
#[derive(Clone, Debug)]
pub struct IpTables {
    path: PathBuf,
    proto: Protocol,
    has_check: bool,
    has_wait: bool,
    wait_support_second: bool,
    /// Go's `timeout`, always 0 here: `NewWithProtocol` is `New(IPFamily(proto), Timeout(0))`, so
    /// `--wait` is never given a number of seconds and waits forever.
    timeout: i32,
}

impl IpTables {
    /// Looks the binary up in `PATH` and asks it for its version, like Go's
    /// `iptables.NewWithProtocol(proto)`.
    ///
    /// Every caller in tcpraw ignores the error and simply installs no rules (`if ipt, err :=
    /// …; err == nil`), so a host without `iptables` keeps working, with the kernel's own
    /// traffic suppressed by the TTL alone.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:New(), NewWithProtocol()
    pub fn new_with_protocol(proto: Protocol) -> io::Result<IpTables> {
        let path = look_path(iptables_command(proto))?;
        let vstring = iptables_version_string(&path)?;
        let Some((v1, v2, v3)) = extract_iptables_version(&vstring) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to extract iptables version from [{vstring}]"),
            ));
        };
        Ok(IpTables {
            path,
            proto,
            has_check: iptables_has_check_command(v1, v2, v3),
            has_wait: iptables_has_wait_command(v1, v2, v3),
            wait_support_second: iptables_wait_support_second(v1, v2, v3),
            timeout: 0,
        })
    }

    /// A handle onto a binary that does not exist, so every invocation fails to spawn and no
    /// process is ever started. `conn`'s tests use it to build an installed rule that can be
    /// recorded and "removed" without `iptables` and without privileges.
    ///
    /// `has_wait` is on, which keeps `exec` from touching `/var/run/xtables.lock`.
    #[cfg(test)]
    // `conn` is Linux-only, so on every other host this helper has no caller.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn nonexistent_for_test(proto: Protocol) -> IpTables {
        IpTables {
            path: PathBuf::from("/nonexistent/iptables"),
            proto,
            has_check: true,
            has_wait: true,
            wait_support_second: false,
            timeout: 0,
        }
    }

    /// The protocol this handle drives.
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    /// The resolved binary.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The argument list `run` builds, without `argv[0]`: the sub-command, then the rule
    /// specification, then `--wait` when the binary understands it.
    ///
    /// `--wait` goes **after** the rule, which is where go-iptables appends it.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).runWithOutput()
    pub fn args(&self, verb: &str, table: &str, chain: &str, rulespec: &[String]) -> Vec<String> {
        let mut args = vec![
            "-t".to_string(),
            table.to_string(),
            verb.to_string(),
            chain.to_string(),
        ];
        args.extend(rulespec.iter().cloned());
        if self.has_wait {
            args.push("--wait".to_string());
            if self.timeout != 0 && self.wait_support_second {
                args.push(self.timeout.to_string());
            }
        }
        args
    }

    /// Whether the rule is already in the chain (`-C`).
    ///
    /// Exit status 1 means "no such rule" and is reported as `Ok(false)`; anything else is an
    /// error.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).Exists()
    pub fn exists(&self, table: &str, chain: &str, rulespec: &[String]) -> io::Result<bool> {
        if !self.has_check {
            return self.exists_for_old_iptables(table, chain, rulespec);
        }
        match self.run("-C", table, chain, rulespec) {
            Ok(()) => Ok(true),
            Err(err) if err.exit_status == Some(1) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    /// Appends the rule to the end of the chain (`-A`).
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).Append()
    pub fn append(&self, table: &str, chain: &str, rulespec: &[String]) -> io::Result<()> {
        self.run("-A", table, chain, rulespec).map_err(Into::into)
    }

    /// Removes the rule from the chain (`-D`).
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).Delete()
    pub fn delete(&self, table: &str, chain: &str, rulespec: &[String]) -> io::Result<()> {
        self.run("-D", table, chain, rulespec).map_err(Into::into)
    }

    /// `Exists` for binaries older than 1.4.11, which have no `-C`: dump the table with `-S` and
    /// look for the rule as text.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).existsForOldIptables()
    fn exists_for_old_iptables(
        &self,
        table: &str,
        chain: &str,
        rulespec: &[String],
    ) -> io::Result<bool> {
        let mut needle = format!("-A {chain}");
        for arg in rulespec {
            needle.push(' ');
            needle.push_str(arg);
        }
        let mut args = vec!["-t".to_string(), table.to_string(), "-S".to_string()];
        if self.has_wait {
            args.push("--wait".to_string());
            if self.timeout != 0 && self.wait_support_second {
                args.push(self.timeout.to_string());
            }
        }
        let out = self.exec(&args, true).map_err(io::Error::from)?;
        Ok(String::from_utf8_lossy(&out).contains(&needle))
    }

    /// Runs one sub-command over a rule specification.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).run()
    fn run(
        &self,
        verb: &str,
        table: &str,
        chain: &str,
        rulespec: &[String],
    ) -> Result<(), IpTablesError> {
        self.exec(&self.args(verb, table, chain, rulespec), false)
            .map(|_| ())
    }

    /// Spawns the binary, optionally capturing stdout, and turns a non-zero exit into an
    /// [`IpTablesError`] carrying stderr, the way go-iptables wraps `*exec.ExitError`.
    ///
    /// When the binary has no `--wait`, the xtables file lock is taken for the duration of the
    /// call, exactly as go-iptables does.
    // Go: go-iptables@v0.8.0 iptables/iptables.go:(*IPTables).runWithOutput()
    fn exec(&self, args: &[String], capture: bool) -> Result<Vec<u8>, IpTablesError> {
        let _lock = if self.has_wait {
            None
        } else {
            Some(XtablesLock::acquire().map_err(|err| IpTablesError {
                args: self.argv(args),
                exit_status: None,
                msg: err.to_string(),
            })?)
        };

        let output = Command::new(&self.path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(if capture {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| IpTablesError {
                args: self.argv(args),
                exit_status: None,
                msg: err.to_string(),
            })?;

        if output.status.success() {
            return Ok(output.stdout);
        }
        Err(IpTablesError {
            args: self.argv(args),
            // Go reads `WaitStatus.ExitStatus()`, which is -1 for a signalled process; `code()`
            // is `None` there, and the `Display` below prints the same `-1`.
            exit_status: output.status.code(),
            msg: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// The full argument vector, `argv[0]` included, as go-iptables builds it for its error text.
    fn argv(&self, args: &[String]) -> Vec<String> {
        let mut argv = vec![self.path.to_string_lossy().into_owned()];
        argv.extend(args.iter().cloned());
        argv
    }
}

/// A non-zero exit of the `iptables` binary, with the text it wrote to stderr.
// Go: go-iptables@v0.8.0 iptables/iptables.go:Error
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpTablesError {
    /// The command line that failed, `argv[0]` first.
    pub args: Vec<String>,
    /// The exit status, or `None` when the process was signalled or never ran.
    pub exit_status: Option<i32>,
    /// Everything the command wrote to stderr.
    pub msg: String,
}

impl fmt::Display for IpTablesError {
    // Go: `fmt.Sprintf("running %v: exit status %v: %v", e.cmd.Args, e.ExitStatus(), e.msg)`,
    // with Go's `%v` of a []string (`[a b c]`) and its -1 for a signalled process.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "running [{}]", self.args.join(" "))?;
        write!(f, ": exit status {}", self.exit_status.unwrap_or(-1))?;
        write!(f, ": {}", self.msg)
    }
}

impl std::error::Error for IpTablesError {}

impl From<IpTablesError> for io::Error {
    fn from(err: IpTablesError) -> io::Error {
        io::Error::other(err)
    }
}

/// Runs `<path> --version` and returns its standard output.
// Go: go-iptables@v0.8.0 iptables/iptables.go:getIptablesVersionString()
fn iptables_version_string(path: &Path) -> io::Result<String> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "could not get iptables version: exit status {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The three version numbers of an `iptables --version` banner, e.g.
/// `iptables v1.8.10 (nf_tables)`.
///
/// This is Go's `v([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s+\((\w+))?` applied with
/// `FindStringSubmatch`, i.e. the **leftmost** match, hand-rolled so that the crate needs no
/// regex engine. The mode (`legacy`/`nf_tables`) that Go's fourth group captures is only stored
/// on the struct and never read, so it is not returned here.
// Go: go-iptables@v0.8.0 iptables/iptables.go:extractIptablesVersion()
pub fn extract_iptables_version(s: &str) -> Option<(u32, u32, u32)> {
    let bytes = s.as_bytes();
    for start in 0..bytes.len() {
        if bytes[start] != b'v' {
            continue;
        }
        let mut pos = start + 1;
        let mut numbers = [0u32; 3];
        let mut ok = true;
        for (i, slot) in numbers.iter_mut().enumerate() {
            // A separating '.' before the second and third group.
            if i > 0 {
                if bytes.get(pos) != Some(&b'.') {
                    ok = false;
                    break;
                }
                pos += 1;
            }
            let digits_start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos == digits_start {
                ok = false;
                break;
            }
            // Go's `strconv.Atoi` on a group that cannot overflow in practice; a version number
            // beyond u32 saturates rather than failing the whole parse.
            *slot = s[digits_start..pos].parse::<u32>().unwrap_or(u32::MAX);
        }
        if ok {
            return Some((numbers[0], numbers[1], numbers[2]));
        }
    }
    None
}

/// `-C` (check a rule) exists from 1.4.11.
// Go: go-iptables@v0.8.0 iptables/iptables.go:iptablesHasCheckCommand()
fn iptables_has_check_command(v1: u32, v2: u32, v3: u32) -> bool {
    v1 > 1 || (v1 == 1 && v2 > 4) || (v1 == 1 && v2 == 4 && v3 >= 11)
}

/// `--wait` (take the xtables lock in the binary) exists from 1.4.20.
// Go: go-iptables@v0.8.0 iptables/iptables.go:iptablesHasWaitCommand()
fn iptables_has_wait_command(v1: u32, v2: u32, v3: u32) -> bool {
    v1 > 1 || (v1 == 1 && v2 > 4) || (v1 == 1 && v2 == 4 && v3 >= 20)
}

/// `--wait <seconds>` exists from 1.6.0.
// Go: go-iptables@v0.8.0 iptables/iptables.go:iptablesWaitSupportSecond()
fn iptables_wait_support_second(v1: u32, v2: u32, _v3: u32) -> bool {
    v1 > 1 || (v1 == 1 && v2 >= 6)
}

/// Go's `exec.LookPath`: the first executable file named `file` in `PATH`.
// Go: go1.27.1 os/exec/lp_unix.go:LookPath()
fn look_path(file: &str) -> io::Result<PathBuf> {
    if file.contains('/') {
        return Ok(PathBuf::from(file));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        // Go: "Unix shell semantics: path element "" means ".""
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let candidate = dir.join(file);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("exec: {file:?}: executable file not found in $PATH"),
    ))
}

/// Go's `findExecutable`: a regular file with an execute bit the caller might hold.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// The lock go-iptables takes around an `iptables` call when the binary is older than 1.4.20 and
/// cannot take the xtables lock itself with `--wait`.
///
/// Best effort, exactly as in Go: if another process already holds the lock, the call proceeds
/// without it rather than waiting.
// Go: go-iptables@v0.8.0 iptables/lock.go:fileLock
struct XtablesLock {
    /// Held only for its `Drop`: closing the descriptor is what releases the `flock`.
    /// `None` means the lock was already taken and the call runs without it, as in Go.
    #[cfg(unix)]
    _file: Option<std::fs::File>,
}

// Go: go-iptables@v0.8.0 iptables/lock.go:xtablesLockFilePath
#[cfg(unix)]
const XTABLES_LOCK_FILE_PATH: &str = "/var/run/xtables.lock";

impl XtablesLock {
    #[cfg(unix)]
    fn acquire() -> io::Result<XtablesLock> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        // Go opens with `syscall.Open(path, os.O_CREATE, 0600)`, i.e. O_RDONLY|O_CREAT.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CREAT)
            .mode(0o600)
            .open(XTABLES_LOCK_FILE_PATH)?;
        // SAFETY: `flock` only needs a valid, open file descriptor, which `file` owns for the
        // whole call; the lock is released by `Drop` closing it.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(XtablesLock { _file: Some(file) });
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Go: `case syscall.EWOULDBLOCK: return nopUnlocker{}, nil`, run unlocked.
            Some(libc::EWOULDBLOCK) => Ok(XtablesLock { _file: None }),
            _ => Err(err),
        }
    }

    #[cfg(not(unix))]
    fn acquire() -> io::Result<XtablesLock> {
        Ok(XtablesLock {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::addr;

    /// A handle with a known feature set, so the argument builder can be tested without an
    /// `iptables` binary.
    fn handle(has_wait: bool) -> IpTables {
        IpTables {
            path: PathBuf::from("/usr/sbin/iptables"),
            proto: Protocol::IPv4,
            has_check: true,
            has_wait,
            wait_support_second: true,
            timeout: 0,
        }
    }

    /// The IPv4 rule of `Dial`, operand for operand.
    #[test]
    fn dial_rule_v4_matches_go() {
        let rule = dial_rule(Protocol::IPv4, "192.168.1.5", "54321", "203.0.113.9", 29900);
        assert_eq!(
            rule,
            vec![
                "-m",
                "ttl",
                "--ttl-eq",
                "1",
                "-p",
                "tcp",
                "-s",
                "192.168.1.5",
                "--sport",
                "54321",
                "-d",
                "203.0.113.9",
                "--dport",
                "29900",
                "-j",
                "DROP",
            ]
        );
    }

    /// The IPv6 rule differs from the IPv4 one only in the match extension (`hl` for `ttl`).
    #[test]
    fn dial_rule_v6_matches_go() {
        let rule = dial_rule(Protocol::IPv6, "2001:db8::5", "54321", "2001:db8::9", 29900);
        assert_eq!(
            rule,
            vec![
                "-m",
                "hl",
                "--hl-eq",
                "1",
                "-p",
                "tcp",
                "-s",
                "2001:db8::5",
                "--sport",
                "54321",
                "-d",
                "2001:db8::9",
                "--dport",
                "29900",
                "-j",
                "DROP",
            ]
        );
        // Only the two operands differ between the families.
        let v4 = dial_rule(Protocol::IPv4, "a", "1", "b", 2);
        let v6 = dial_rule(Protocol::IPv6, "a", "1", "b", 2);
        assert_eq!(v4.len(), v6.len());
        assert_eq!(
            v4.iter().zip(&v6).filter(|(a, b)| a != b).count(),
            2,
            "{v4:?} vs {v6:?}"
        );
    }

    /// The IPv4 rule of `Listen`, operand for operand: no peer, just the source port.
    #[test]
    fn listen_rule_v4_matches_go() {
        assert_eq!(
            listen_rule(Protocol::IPv4, 29900),
            vec![
                "-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "--sport", "29900", "-j", "DROP"
            ]
        );
    }

    /// The IPv6 `Listen` rule differs only in the match extension.
    #[test]
    fn listen_rule_v6_matches_go() {
        assert_eq!(
            listen_rule(Protocol::IPv6, 29900),
            vec![
                "-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", "29900", "-j", "DROP"
            ]
        );
        let v4 = listen_rule(Protocol::IPv4, 1);
        let v6 = listen_rule(Protocol::IPv6, 1);
        assert_eq!(v4.len(), v6.len());
        assert_eq!(
            v4.iter().zip(&v6).filter(|(a, b)| a != b).count(),
            2,
            "{v4:?} vs {v6:?}"
        );
    }

    /// A `Listen` rule is strictly shorter than a `Dial` one: it matches no addresses and no
    /// destination port, so it covers every peer of that listening port.
    #[test]
    fn listen_rule_names_no_peer() {
        let rule = listen_rule(Protocol::IPv4, 29900);
        assert!(
            !rule
                .iter()
                .any(|a| a == "-s" || a == "-d" || a == "--dport")
        );
        assert!(rule.len() < dial_rule(Protocol::IPv4, "a", "1", "b", 2).len());
    }

    /// The remote address goes in as `net.IP.String()` writes it, so an IPv4-mapped peer is a
    /// dotted quad and never `::ffff:…` (which `iptables` would reject).
    #[test]
    fn dial_rule_uses_go_ip_formatting() {
        let mapped: std::net::IpAddr = "::ffff:203.0.113.9".parse().expect("literal");
        let rule = dial_rule(
            Protocol::IPv4,
            "192.168.1.5",
            "54321",
            &addr::ip_string(mapped),
            29900,
        );
        assert_eq!(rule[11], "203.0.113.9");
    }

    /// `-t filter -C OUTPUT <rule…> --wait`: the sub-command first, the rule next and `--wait`
    /// appended at the end, which is where go-iptables puts it.
    #[test]
    fn args_place_wait_after_the_rule() {
        let rule = dial_rule(Protocol::IPv4, "10.0.0.2", "1234", "10.0.0.3", 29900);

        let with_wait = handle(true).args("-C", TABLE, CHAIN, &rule);
        assert_eq!(&with_wait[..4], &["-t", "filter", "-C", "OUTPUT"]);
        assert_eq!(&with_wait[4..4 + rule.len()], &rule[..]);
        assert_eq!(with_wait.last().map(String::as_str), Some("--wait"));
        assert_eq!(with_wait.len(), 4 + rule.len() + 1);

        // Too old for `--wait`: the argument list ends with the rule and the xtables file lock
        // is taken around the call instead.
        let without = handle(false).args("-A", TABLE, CHAIN, &rule);
        assert_eq!(without.len(), 4 + rule.len());
        assert_eq!(&without[..4], &["-t", "filter", "-A", "OUTPUT"]);

        // Go's timeout is 0 for `NewWithProtocol`, so `--wait` never carries a number.
        assert!(!with_wait.iter().any(|a| a == "0"));
    }

    /// Append and delete use the same rule with `-A` and `-D`, so `Close` removes exactly what
    /// `Dial` added.
    #[test]
    fn append_and_delete_share_the_rule() {
        let rule = dial_rule(Protocol::IPv6, "2001:db8::5", "9", "2001:db8::9", 1);
        let ipt = handle(true);
        let append = ipt.args("-A", TABLE, CHAIN, &rule);
        let delete = ipt.args("-D", TABLE, CHAIN, &rule);
        assert_eq!(append[2], "-A");
        assert_eq!(delete[2], "-D");
        assert_eq!(append[3..], delete[3..]);
    }

    /// The `-S` fallback for binaries without `-C` looks for the rule spelled as `iptables -S`
    /// prints it.
    #[test]
    fn old_iptables_needle_is_the_printed_rule() {
        let rule = dial_rule(Protocol::IPv4, "10.0.0.2", "1234", "10.0.0.3", 29900);
        let mut needle = format!("-A {CHAIN}");
        for arg in &rule {
            needle.push(' ');
            needle.push_str(arg);
        }
        assert_eq!(
            needle,
            "-A OUTPUT -m ttl --ttl-eq 1 -p tcp -s 10.0.0.2 --sport 1234 \
             -d 10.0.0.3 --dport 29900 -j DROP"
        );
    }

    /// Version banners of the binaries in the wild, plus the malformed ones Go rejects.
    #[test]
    fn extract_iptables_version_matches_go() {
        assert_eq!(
            extract_iptables_version("iptables v1.8.10 (nf_tables)\n"),
            Some((1, 8, 10))
        );
        assert_eq!(
            extract_iptables_version("ip6tables v1.4.21 (legacy)\n"),
            Some((1, 4, 21))
        );
        assert_eq!(
            extract_iptables_version("iptables v1.4.7\n"),
            Some((1, 4, 7))
        );
        // Leftmost match, like `FindStringSubmatch`: the "v" that starts a complete triple wins.
        assert_eq!(extract_iptables_version("vv2.0.1"), Some((2, 0, 1)));
        assert_eq!(extract_iptables_version("v1.2 v3.4.5"), Some((3, 4, 5)));
        assert_eq!(extract_iptables_version("iptables v1.8"), None);
        assert_eq!(extract_iptables_version("no version here"), None);
        assert_eq!(extract_iptables_version(""), None);
    }

    /// The three feature predicates, at their boundaries.
    #[test]
    fn feature_predicates_match_go() {
        assert!(!iptables_has_check_command(1, 4, 10));
        assert!(iptables_has_check_command(1, 4, 11));
        assert!(iptables_has_check_command(1, 5, 0));
        assert!(iptables_has_check_command(2, 0, 0));

        assert!(!iptables_has_wait_command(1, 4, 19));
        assert!(iptables_has_wait_command(1, 4, 20));
        assert!(iptables_has_wait_command(1, 5, 0));

        assert!(!iptables_wait_support_second(1, 5, 9));
        assert!(iptables_wait_support_second(1, 6, 0));
    }

    /// The binary name per protocol, and the error text of a failed lookup.
    #[test]
    fn command_lookup() {
        assert_eq!(iptables_command(Protocol::IPv4), "iptables");
        assert_eq!(iptables_command(Protocol::IPv6), "ip6tables");
        let err = look_path("kcptun-no-such-binary-9f3a").expect_err("must not exist");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string()
                .contains("executable file not found in $PATH"),
            "{err}"
        );
    }

    /// go-iptables' error text, which is what reaches a caller that does not ignore it.
    #[test]
    fn error_text_matches_go() {
        let err = IpTablesError {
            args: vec![
                "/usr/sbin/iptables".into(),
                "-t".into(),
                "filter".into(),
                "-C".into(),
                "OUTPUT".into(),
            ],
            exit_status: Some(2),
            msg: "iptables: Bad rule.\n".into(),
        };
        assert_eq!(
            err.to_string(),
            "running [/usr/sbin/iptables -t filter -C OUTPUT]: exit status 2: \
             iptables: Bad rule.\n"
        );
    }
}
