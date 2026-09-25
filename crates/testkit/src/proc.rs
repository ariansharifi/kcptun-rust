//! Spawning external processes (Go reference binaries, Go interop peers, our own binaries) for
//! integration tests.
//!
//! A [`Proc`] writes its stdout and stderr into one temporary log file opened in append mode
//! (every write, including markers added through [`open_append`], lands at the end, so lines
//! interleave as written), is killed and reaped when dropped, can be sent a signal by name
//! ([`Proc::signal`], for step 09.6's `SIGUSR1`/`SIGTERM` cases), and can wait
//! for a log line such as kcptun's `listening on:`. When a test panics while a `Proc` is alive,
//! the drop prints the process log to stderr so failures are diagnosable. Set
//! `KCPTUN_TEST_KEEP_LOGS=1` to keep the log files after the test.
//!
//! [`ProcBuilder::split_output`] captures the two streams into two files instead, for a test that
//! has to tell them apart — kcptun writes its log to stderr but its help, usage errors and the
//! coloured QPP warnings to stdout, and step 09.5's CLI differential compares the two separately.
//!
//! macOS caveat: a child can inherit sockets that other test threads create at the moment of
//! the spawn (no atomic close-on-exec there). Every spawn here runs under
//! [`socket_creation_guard`](crate::socket_creation_guard), and testkit creates its own sockets
//! under it too. Tests elsewhere must bind their fixed-port sockets under that guard as well and
//! must never call `Command::spawn`/`status`/`output` directly (use [`ProcBuilder`]), or a child
//! may keep their ports busy. testkit servers close connections with `shutdown(2)`, which works
//! even if a child holds a copy. Linux is not affected.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How often log files and exit status are polled while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Bytes of log shown in error messages.
const LOG_TAIL: usize = 4096;
/// Environment variable that keeps log files after the process is dropped.
pub const KEEP_LOGS_ENV: &str = "KCPTUN_TEST_KEEP_LOGS";

/// Builder for a [`Proc`].
#[derive(Clone, Debug)]
pub struct ProcBuilder {
    program: PathBuf,
    name: String,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    env_remove: Vec<OsString>,
    cwd: Option<PathBuf>,
    split: bool,
}

impl ProcBuilder {
    /// Starts building a process running `program`. Its file name is the default display name.
    pub fn new(program: impl AsRef<Path>) -> Self {
        let program = program.as_ref().to_path_buf();
        let name = program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "proc".to_string());
        ProcBuilder {
            program,
            name,
            args: Vec::new(),
            envs: Vec::new(),
            env_remove: Vec::new(),
            cwd: None,
            split: false,
        }
    }

    /// Sets the name used in log file names and messages.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Adds one argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Adds several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Sets an environment variable (the rest of the environment is inherited).
    pub fn env(mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> Self {
        self.envs
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Removes an inherited environment variable.
    pub fn env_remove(mut self, key: impl AsRef<OsStr>) -> Self {
        self.env_remove.push(key.as_ref().to_owned());
        self
    }

    /// Sets the working directory.
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Captures stdout and stderr into **two** files instead of one, so
    /// [`Proc::stdout_text`] and [`Proc::stderr_text`] can be compared separately.
    ///
    /// The merged views ([`Proc::log`], [`Proc::log_tail`] and everything that waits for a log
    /// line) then read stdout followed by stderr rather than the interleaving of the two, which
    /// is why this is opt-in.
    pub fn split_output(mut self) -> Self {
        self.split = true;
        self
    }

    /// Spawns the process with stdin closed and stdout/stderr captured to a temporary log.
    pub fn spawn(self) -> io::Result<Proc> {
        let log = Self::log_file(&self.name, "")?;
        let err_log = if self.split {
            Some(Self::log_file(&self.name, "-err")?)
        } else {
            None
        };
        let stdout = log.as_file().try_clone()?;
        let stderr = match &err_log {
            Some(err) => err.as_file().try_clone()?,
            None => log.as_file().try_clone()?,
        };
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for k in &self.env_remove {
            cmd.env_remove(k);
        }
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
        let spawned = {
            let _fd = crate::fd_lock(); // see FD_LOCK: no testkit socket leaks into the child
            cmd.spawn()
        };
        let child = spawned.map_err(|e| {
            io::Error::new(e.kind(), format!("spawn {}: {e}", self.program.display()))
        })?;
        Ok(Proc {
            child,
            name: self.name,
            log: Some(log),
            err_log,
            status: None,
        })
    }

    /// A temporary, append-mode log file named after the process.
    fn log_file(name: &str, suffix: &str) -> io::Result<tempfile::NamedTempFile> {
        tempfile::Builder::new()
            .prefix(&format!("kcptun-test-{}-", sanitize(name)))
            .suffix(&format!("{suffix}.log"))
            // O_APPEND: the child and open_append writers never overwrite each other.
            .append(true)
            .tempfile()
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Errors from waiting on a [`Proc`].
#[derive(Debug)]
pub enum ProcError {
    /// The wanted log line did not appear in time.
    Timeout {
        /// Process name.
        name: String,
        /// What was waited for.
        waiting_for: String,
        /// Tail of the log.
        log_tail: String,
    },
    /// The process exited before the wanted log line appeared.
    Exited {
        /// Process name.
        name: String,
        /// Exit status.
        status: ExitStatus,
        /// What was waited for.
        waiting_for: String,
        /// Tail of the log.
        log_tail: String,
    },
    /// An I/O error while polling.
    Io(io::Error),
}

impl fmt::Display for ProcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcError::Timeout {
                name,
                waiting_for,
                log_tail,
            } => write!(
                f,
                "{name}: timed out waiting for {waiting_for}; log tail:\n{log_tail}"
            ),
            ProcError::Exited {
                name,
                status,
                waiting_for,
                log_tail,
            } => write!(
                f,
                "{name}: exited ({status}) while waiting for {waiting_for}; log tail:\n{log_tail}"
            ),
            ProcError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProcError {}

impl From<io::Error> for ProcError {
    fn from(e: io::Error) -> Self {
        ProcError::Io(e)
    }
}

/// A running child process; killed and reaped on drop. See the [module docs](self).
#[derive(Debug)]
pub struct Proc {
    child: Child,
    name: String,
    log: Option<tempfile::NamedTempFile>,
    /// The second capture file of [`ProcBuilder::split_output`]; `None` when both streams share
    /// [`log`](Self::log).
    err_log: Option<tempfile::NamedTempFile>,
    status: Option<ExitStatus>,
}

impl Proc {
    /// Shorthand for [`ProcBuilder::new`].
    pub fn builder(program: impl AsRef<Path>) -> ProcBuilder {
        ProcBuilder::new(program)
    }

    /// Display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// OS process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Path of the log file holding stdout and stderr.
    pub fn log_path(&self) -> &Path {
        match &self.log {
            Some(l) => l.path(),
            None => Path::new(""),
        }
    }

    /// Path of the file holding stderr, when the streams were
    /// [split](ProcBuilder::split_output); otherwise [`log_path`](Self::log_path).
    pub fn stderr_path(&self) -> &Path {
        match &self.err_log {
            Some(l) => l.path(),
            None => self.log_path(),
        }
    }

    /// The whole log so far (lossy UTF-8). With the streams
    /// [split](ProcBuilder::split_output) this is stdout followed by stderr, not their
    /// interleaving.
    pub fn log(&self) -> String {
        match &self.err_log {
            Some(_) => self.stdout_text() + &self.stderr_text(),
            None => self.stdout_text(),
        }
    }

    /// Everything the process has written to stdout. Without
    /// [`split_output`](ProcBuilder::split_output) that is both streams, in one file.
    pub fn stdout_text(&self) -> String {
        read_lossy(self.log_path())
    }

    /// Everything the process has written to stderr. Without
    /// [`split_output`](ProcBuilder::split_output) that is both streams, in one file.
    pub fn stderr_text(&self) -> String {
        read_lossy(self.stderr_path())
    }

    /// The last few KB of the log.
    pub fn log_tail(&self) -> String {
        let log = self.log();
        let mut start = log.len().saturating_sub(LOG_TAIL);
        while !log.is_char_boundary(start) {
            start += 1;
        }
        log[start..].to_string()
    }

    /// Exit status if the process has exited (non-blocking).
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    /// True while the process has not exited.
    pub fn is_running(&mut self) -> bool {
        matches!(self.try_wait(), Ok(None))
    }

    /// Waits up to `timeout` for the process to exit.
    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.try_wait()? {
                return Ok(Some(s));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Kills the process (SIGKILL on Unix) and reaps it. Does nothing if it already exited.
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
        if let Some(s) = self.try_wait()? {
            return Ok(s);
        }
        // An exit between try_wait and kill makes kill fail with InvalidInput; wait still works.
        let _ = self.child.kill();
        let s = self.child.wait()?;
        self.status = Some(s);
        Ok(s)
    }

    /// Sends a signal to the process, naming it as `kill(1)` does (`TERM`, `INT`, `USR1`, …).
    ///
    /// Unlike [`kill`](Self::kill) this neither waits nor reaps: the caller decides what the
    /// process is supposed to do about the signal (step 09.6 watches `SIGUSR1` produce a log line
    /// and `SIGTERM` end the process).
    ///
    /// `std` offers no safe `kill(2)` and this crate denies `unsafe` outside
    /// [`cpu`](crate::cpu) (docs/porting-guide.md §5), so the signal is sent by `kill(1)` — the
    /// same route `kcptun_std::signal`'s own tests take. Sending to a process that has already
    /// been reaped is refused instead of risking a recycled pid.
    #[cfg(unix)]
    pub fn signal(&mut self, signal: &str) -> io::Result<()> {
        if let Some(status) = self.try_wait()? {
            return Err(io::Error::other(format!(
                "{}: already exited ({status}), cannot send SIG{signal}",
                self.name
            )));
        }
        let mut cmd = Command::new("kill");
        cmd.arg(format!("-{signal}"))
            .arg(self.pid().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Spawn under the guard (see FD_LOCK), wait outside it: the lock is never held across a
        // wait.
        let spawned = {
            let _fd = crate::fd_lock();
            cmd.spawn()
        };
        let status = spawned?.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "kill -{signal} {}: {status}",
                self.pid()
            )));
        }
        Ok(())
    }

    /// Checks the log once: the first complete line (or, once the process has exited, the
    /// trailing partial line) for which `pred` holds.
    fn scan(
        &mut self,
        pred: &mut dyn FnMut(&str) -> bool,
    ) -> io::Result<(Option<String>, Option<ExitStatus>)> {
        // Read the status first: if the process has exited, everything it wrote is in the log.
        let status = self.try_wait()?;
        let log = self.log();
        let complete = if status.is_some() {
            log.as_str()
        } else {
            log.rfind('\n').map_or("", |i| &log[..=i])
        };
        let found = complete.lines().find(|l| pred(l)).map(str::to_string);
        Ok((found, status))
    }

    /// Waits until a log line satisfies `pred` and returns it.
    pub fn wait_for_log(
        &mut self,
        what: &str,
        timeout: Duration,
        mut pred: impl FnMut(&str) -> bool,
    ) -> Result<String, ProcError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.scan(&mut pred)? {
                (Some(line), _) => return Ok(line),
                (None, Some(status)) => return Err(self.exited(status, what)),
                (None, None) if Instant::now() >= deadline => return Err(self.timed_out(what)),
                (None, None) => std::thread::sleep(POLL_INTERVAL),
            }
        }
    }

    /// Waits until a log line contains `pattern` (e.g. `"listening on:"`) and returns it.
    pub fn wait_for_log_line(
        &mut self,
        pattern: &str,
        timeout: Duration,
    ) -> Result<String, ProcError> {
        self.wait_for_log(&format!("{pattern:?}"), timeout, |l| l.contains(pattern))
    }

    /// Async version of [`wait_for_log`](Self::wait_for_log) that sleeps with tokio instead of
    /// blocking the thread.
    pub async fn wait_for_log_async(
        &mut self,
        what: &str,
        timeout: Duration,
        mut pred: impl FnMut(&str) -> bool,
    ) -> Result<String, ProcError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.scan(&mut pred)? {
                (Some(line), _) => return Ok(line),
                (None, Some(status)) => return Err(self.exited(status, what)),
                (None, None) if Instant::now() >= deadline => return Err(self.timed_out(what)),
                (None, None) => tokio::time::sleep(POLL_INTERVAL).await,
            }
        }
    }

    /// Async version of [`wait_for_log_line`](Self::wait_for_log_line).
    pub async fn wait_for_log_line_async(
        &mut self,
        pattern: &str,
        timeout: Duration,
    ) -> Result<String, ProcError> {
        self.wait_for_log_async(&format!("{pattern:?}"), timeout, |l| l.contains(pattern))
            .await
    }

    fn exited(&self, status: ExitStatus, what: &str) -> ProcError {
        ProcError::Exited {
            name: self.name.clone(),
            status,
            waiting_for: what.to_string(),
            log_tail: self.log_tail(),
        }
    }

    fn timed_out(&self, what: &str) -> ProcError {
        ProcError::Timeout {
            name: self.name.clone(),
            waiting_for: what.to_string(),
            log_tail: self.log_tail(),
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.kill();
        if std::thread::panicking() {
            eprintln!(
                "---- log of {} (pid {}, {}) ----\n{}\n---- end of log ----",
                self.name,
                self.child.id(),
                self.log_path().display(),
                self.log_tail()
            );
        }
        if std::env::var_os(KEEP_LOGS_ENV).is_some_and(|v| v == "1") {
            for log in [self.log.take(), self.err_log.take()].into_iter().flatten() {
                match log.keep() {
                    Ok((_, path)) => eprintln!("kept log of {}: {}", self.name, path.display()),
                    Err(e) => eprintln!("could not keep log of {}: {e}", self.name),
                }
            }
        }
    }
}

/// Opens `path` for appending, for callers that want to add markers to a log.
pub fn open_append(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new().append(true).open(path)
}

/// The contents of `path` as lossy UTF-8; empty when it cannot be read.
fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    const T: Duration = Duration::from_secs(10);

    fn sh(script: &str) -> ProcBuilder {
        ProcBuilder::new("/bin/sh")
            .name("sh test")
            .args(["-c", script, "sh"])
    }

    fn alive(pid: u32) -> bool {
        // Spawns directly (not via ProcBuilder), so it must hold the guard itself: an unguarded
        // spawn can inherit sockets that parallel tests are creating (see FD_LOCK).
        let _fd = crate::fd_lock();
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn waits_for_line_on_stderr_and_captures_both_streams() {
        let mut p = sh("echo starting; echo 'listening on: 127.0.0.1:5000' >&2; exec sleep 30")
            .spawn()
            .unwrap();
        let line = p.wait_for_log_line("listening on:", T).unwrap();
        assert_eq!(line, "listening on: 127.0.0.1:5000");
        assert!(p.is_running());
        assert_eq!(p.log(), "starting\nlistening on: 127.0.0.1:5000\n");
        assert!(
            p.log_path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("kcptun-test-sh_test-")
        );
        let custom = p
            .wait_for_log("a line starting with 'st'", T, |l| l.starts_with("st"))
            .unwrap();
        assert_eq!(custom, "starting");
    }

    #[test]
    fn split_output_keeps_the_two_streams_apart() {
        let mut p = sh("echo to-stdout; echo to-stderr >&2; exit 7")
            .split_output()
            .spawn()
            .unwrap();
        assert_eq!(p.wait_timeout(T).unwrap().unwrap().code(), Some(7));
        assert_eq!(p.stdout_text(), "to-stdout\n");
        assert_eq!(p.stderr_text(), "to-stderr\n");
        assert_ne!(p.log_path(), p.stderr_path());
        // The merged view is stdout then stderr, and both files go away with the process.
        assert_eq!(p.log(), "to-stdout\nto-stderr\n");
        let (out, err) = (p.log_path().to_path_buf(), p.stderr_path().to_path_buf());
        drop(p);
        assert!(!out.exists() && !err.exists(), "log files not removed");
    }

    #[test]
    fn without_split_both_streams_share_one_file() {
        let mut p = sh("echo to-stdout; echo to-stderr >&2; exit 0")
            .spawn()
            .unwrap();
        assert!(p.wait_timeout(T).unwrap().is_some());
        assert_eq!(p.log_path(), p.stderr_path());
        assert_eq!(p.stdout_text(), "to-stdout\nto-stderr\n");
        assert_eq!(p.stdout_text(), p.stderr_text());
    }

    #[test]
    fn passes_args_env_and_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = sh("echo \"$KCPTUN_TK_A|$1|$2|$(pwd -P)|${HOME:-unset}\"; exec sleep 30")
            .args(["x", "y z"])
            .env("KCPTUN_TK_A", "va")
            .env_remove("HOME")
            .current_dir(dir.path())
            .spawn()
            .unwrap();
        let line = p.wait_for_log_line("va|", T).unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        assert_eq!(line, format!("va|x|y z|{}|unset", cwd.display()));
    }

    #[test]
    fn kill_on_drop() {
        let p = sh("echo up; exec sleep 30").spawn().unwrap();
        let pid = p.pid();
        let path = p.log_path().to_path_buf();
        assert!(alive(pid));
        drop(p);
        assert!(!alive(pid), "process {pid} still alive after drop");
        assert!(!path.exists(), "log file not removed");
    }

    #[test]
    fn early_exit_is_reported_with_log() {
        let mut p = sh("echo 'fatal: bad flag'; exit 3").spawn().unwrap();
        let e = p.wait_for_log_line("listening on:", T).unwrap_err();
        match &e {
            ProcError::Exited {
                status, log_tail, ..
            } => {
                assert_eq!(status.code(), Some(3));
                assert!(log_tail.contains("fatal: bad flag"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(e.to_string().contains("exited"));
        assert!(!p.is_running());
    }

    #[test]
    fn partial_last_line_counts_after_exit() {
        let mut p = sh("printf 'no newline'").spawn().unwrap();
        assert_eq!(p.wait_for_log_line("newline", T).unwrap(), "no newline");
    }

    #[test]
    fn timeout_is_reported() {
        let mut p = sh("echo quiet; exec sleep 30").spawn().unwrap();
        let e = p
            .wait_for_log_line("never", Duration::from_millis(100))
            .unwrap_err();
        assert!(matches!(e, ProcError::Timeout { .. }), "{e:?}");
        assert!(e.to_string().contains("timed out waiting for \"never\""));
        assert!(e.to_string().contains("quiet"));
    }

    #[test]
    fn explicit_kill_and_wait() {
        let mut p = sh("exec sleep 30").spawn().unwrap();
        assert_eq!(p.wait_timeout(Duration::from_millis(20)).unwrap(), None);
        let s = p.kill().unwrap();
        assert!(!s.success());
        assert_eq!(p.try_wait().unwrap(), Some(s));
        let mut q = sh("exit 0").spawn().unwrap();
        assert!(q.wait_timeout(T).unwrap().unwrap().success());
        assert!(q.kill().unwrap().success());
    }

    #[test]
    fn signal_reaches_a_handler_and_can_terminate() {
        // `sleep` runs in the foreground, so the shell runs the trap when it returns; the short
        // interval keeps the wait below quick. The loop is bounded (30 s) so the child ends on
        // its own even if both the kill and the kill-on-drop were to fail.
        let mut p =
            sh("trap 'echo got-usr1' USR1; echo up; for _ in $(seq 600); do sleep 0.05; done")
                .spawn()
                .unwrap();
        p.wait_for_log_line("up", T).unwrap();

        p.signal("USR1").unwrap();
        assert_eq!(p.wait_for_log_line("got-usr1", T).unwrap(), "got-usr1");
        assert!(p.is_running(), "SIGUSR1 must not end the process");

        p.signal("TERM").unwrap();
        let status = p.wait_timeout(T).unwrap().expect("exited on SIGTERM");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(15),
            "expected death by SIGTERM, got {status:?}"
        );

        // A reaped process is not signalled again: its pid may belong to someone else by now.
        let e = p.signal("TERM").unwrap_err();
        assert!(e.to_string().contains("already exited"), "{e}");
    }

    #[test]
    fn missing_binary_names_program() {
        let e = ProcBuilder::new("/nonexistent/kcptun-nope")
            .spawn()
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("/nonexistent/kcptun-nope"));
    }

    #[test]
    fn open_append_adds_markers() {
        // The child keeps writing after the marker; with a shared non-append offset its next
        // write would overwrite the marker.
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("go");
        let mut p = sh(
            "echo before; while [ ! -e \"$1\" ]; do sleep 0.01; done; echo after; exec sleep 30",
        )
        .arg(&flag)
        .spawn()
        .unwrap();
        p.wait_for_log_line("before", T).unwrap();
        let mut f = open_append(p.log_path()).unwrap();
        writeln!(f, "== marker ==").unwrap();
        std::fs::write(&flag, b"").unwrap();
        p.wait_for_log_line("after", T).unwrap();
        assert_eq!(p.log(), "before\n== marker ==\nafter\n");
    }

    #[tokio::test]
    async fn async_wait() {
        let mut p = sh("sleep 0.05; echo 'listening on: [::1]:1'; exec sleep 30")
            .spawn()
            .unwrap();
        let line = p.wait_for_log_line_async("listening on:", T).await.unwrap();
        assert!(line.ends_with("[::1]:1"));
    }
}
