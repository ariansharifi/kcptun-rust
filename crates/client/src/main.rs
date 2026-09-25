//! kcptun client: Rust port of `reference/kcptun/client/main.go` and `client/dial.go`.
//!
//! The order of everything here is Go's: the flag table and the `-c` overlay, the `conn <= 0`
//! fatal, the `ratelimit` fix-up, the `-log` redirect, `ApplyMode`, the listener, the startup log
//! block, the QPP and `scavengettl` warnings, the smux check, key derivation, the SNMP logger,
//! pprof, the scavenger, and finally the accept loop.
//!
//! ```text
//! TCP/unix accept -> [QPP] -> smux stream -> [CompStream] -> UDPSession -> UDP/tcpraw
//!                       ^ one smux session per -conn slot, round-robin
//! ```
//!
//! **Memory.** No per-connection or per-stream buffer is allocated up front. The copy buffers
//! come from the process-wide pool only once a direction has data (DECISIONS D17), and the
//! smux → TCP direction takes none at all: it drains received frames straight into the local
//! socket (`kcptun_std::pipe::HalfCloseWrite::FRAME_SOURCE`).
//!
//! **Locks.** The accept loop owns `muxes` outright and the scavenger owns its own list; the only
//! thing they share is the bounded channel between them. A `wait_conn` that blocks the accept
//! loop for minutes therefore cannot hold anything the scavenger needs (pitfall list of
//! step 09).
#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use kcptun_kcp::crypt::PacketCrypt;
use kcptun_kcp::{PacketConn, UdpSession};
use kcptun_smux::{Session, SmuxConn};
use kcptun_std::cli::{Context, RunOutcome, SystemEnv, filepath_base};
use kcptun_std::comp::CompStream;
use kcptun_std::config::{self, ClientConfig};
use kcptun_std::kcpconn::KcpConn;
use kcptun_std::mainutil::{GoAddr, QppPad, check_qpp, qpp_pad, setsockopt_error};
use kcptun_std::multiport::{MultiPort, MultiPortError};
use kcptun_std::pipe::{HalfCloseWrite, pipe};
use kcptun_std::smuxio::SmuxStream;
use kcptun_std::{crypt, goaddr, log, logf, logln, multiport, pprof, runtime, signal, smuxcfg};
use tokio::sync::mpsc;
use tokio::time::Instant;

mod listen;

use listen::{LocalConn, LocalListener};

/// How often the scavenger walks its list of expiring sessions.
// Go: kcptun/client/main.go:53 — `scavengePeriod = 5`
const SCAVENGE_PERIOD: Duration = Duration::from_secs(5);

/// How many expiring sessions the accept loop may hand the scavenger before it has to wait.
// Go: kcptun/client/main.go:404 — `make(chan timedSession, 128)`
const SCAVENGER_BACKLOG: usize = 128;

/// How long `wait_conn` waits before dialling again.
// Go: kcptun/client/main.go:506 — `time.Sleep(time.Second)`
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------

fn main() {
    // D34: the Go runtime raises the open-file soft limit to the hard limit in a `syscall`
    // package `init()`, before `main`; nothing does that for a Rust binary, so a container
    // started with Docker's common soft-1024 default ran this port at 1024 descriptors while a
    // Go kcptun beside it had 1048576. First thing in `main`, before the tokio runtime opens
    // any of its own. Silent and unconditional, exactly as in Go.
    kcptun_kcp::rlimit::raise_nofile();
    // Go: `log.SetFlags(log.LstdFlags | log.Lshortfile)` when VERSION == "SELFBUILD". The
    // logger of this port starts with exactly those flags (`log::default_flags()`), so there is
    // nothing to set here.
    let runtime = log::check_error(runtime::build());
    runtime.block_on(run());
}

/// Go's `main()` body: build the app, run it, and let the action do the work.
// Go: kcptun/client/main.go:main()
async fn run() {
    // Go: kcptun/std/signal.go:init() installs the handlers before main's body runs. Here it
    // needs the runtime, so it happens first inside it.
    if let Err(err) = signal::install() {
        // D30: the errno is spelled from Go's table, like every other syscall failure here.
        // (Go's `signal.Notify` cannot fail, so this line has no Go counterpart at all.)
        logln!("signal:", config::go_error_text(&err));
    }
    // Go: kcptun/std/atexit_linux.go:postProcess() — tcpraw's iptables rules are undone on
    // SIGINT/SIGTERM. Go compiles the call in unconditionally (and to an empty body off Linux),
    // so it is registered here whether or not `--tcp` is on; with no fake-TCP connection it
    // finds nothing to do. `run()` and the `log` fatal paths below run the same hooks, so a
    // normal exit cleans up too. Nothing can clean up after `SIGKILL`, in this port or in Go.
    signal::register_iptables_reset();
    // A panic is an exit path too, and `panic = "abort"` (D24) gives the unwinder no chance to
    // run anything: the panic *hook*, which this installs, is the last thing that runs before
    // the abort. Go has the same hole and does not fill it (step 10.4).
    signal::run_exit_hooks_on_panic();
    // Go: kcp-go/v5@v5.6.66 kcp.go:refTime — set at package init, so `currentMs()` counts from
    // process start rather than from the first KCP session.
    kcptun_kcp::clock::init_ref_time();

    let argv: Vec<String> = std::env::args().collect();
    // Go: urfave defaults App.HelpName to filepath.Base(os.Args[0]).
    let app = config::client_app(filepath_base(argv.first().map_or("", String::as_str)));
    let run = app.run(&argv, &SystemEnv);

    // Go writes help, version and usage errors to App.Writer (os.Stdout) and ExitCoder errors to
    // cli.ErrWriter (os.Stderr).
    if !run.stdout.is_empty() {
        print!("{}", run.stdout);
    }
    if !run.stderr.is_empty() {
        eprint!("{}", run.stderr);
    }
    let c = match run.outcome {
        RunOutcome::Action(c) => c,
        // Deviation V06: a usage error exits 2 here, 0 in Go.
        RunOutcome::Exit(code) => std::process::exit(code),
    };

    // Go: `myApp.Run(os.Args)` returns the action's error, which main ignores.
    action(&c).await;

    // The action returns only when there is nothing left to serve (a bad `-remoteaddr`, say).
    // Go's `postProcess` runs on the signal path alone and leaves tcpraw's rules behind here;
    // this port runs the exit hooks on every path it controls (step 10.4).
    signal::post_process();
}

/// Go's `myApp.Action`.
// Go: kcptun/client/main.go:myApp.Action
async fn action(c: &Context) {
    let mut config = ClientConfig::from_context(c);

    // Go: `if c.String("c") != "" { checkError(parseJSONConfig(&config, c.String("c"))) }`.
    let config_file = c.string("c");
    if !config_file.is_empty() {
        log::check_error(config::parse_json_config(&mut config, &config_file));
    }

    // Go: `if config.Conn <= 0 { log.Fatal("conn must be greater than 0") }`.
    if let Err(msg) = config.check_conn() {
        log::fatal(&msg);
    }

    // Go: `if config.RateLimit < 0 { log.Printf(...); config.RateLimit = 0 }`.
    if let Some(msg) = config.base.normalize_rate_limit() {
        logf!("{msg}");
    }

    // Redirect logs when the user supplied a dedicated log file. Go keeps the file open for the
    // life of the process (`defer f.Close()` in main), and so does `set_output_file`.
    if !config.base.log.is_empty() {
        log::check_error(log::set_output_file(&config.base.log));
    }

    // Apply mode presets using the shared configuration helper.
    config.base.apply_mode();

    // Deviation V23: process-wide, and set before anything dials or listens. Off by default,
    // which means a peer may answer from an address other than the one we send to.
    kcptun_kcp::set_strict_source(config.base.strict_source);

    log_version();
    // Go creates the listener between the `version:` line and the rest of the block, so a bind
    // failure prints exactly those two lines.
    let listener = log::check_error(listen_local(&config.local_addr));
    log_startup(&config, &listener.addr_string());

    // Go: `if config.QPP { suggestions, err := std.ValidateQPPParams(...); ... }`.
    let qpp_count = check_qpp(&config.base);

    // Ensure scavenger TTL does not exceed the auto-expire window.
    for msg in scavenge_warnings(&config) {
        log::color_red(msg);
    }

    // Guard against negotiating unsupported smux protocol versions.
    // Go: `if config.SmuxVer > maxSmuxVer { log.Fatal("unsupported smux version:", ...) }`.
    if let Err(msg) = config.base.check_smux_ver() {
        log::fatal(&msg);
    }
    // Deviation V07: a shard count Go silently turns into undecodable Leopard parity. Go has no
    // such check on either side; the server rejects it at startup, and so does this, rather than
    // dialling a session whose parity no peer can use.
    if let Err(msg) = config.base.check_fec() {
        log::fatal(&msg);
    }

    // Derive the shared session key from the pre-shared secret.
    logln!("initiating key derivation");
    let pass = crypt::derive_pass(&config.base.key);
    logln!("key derivation done");
    let selected = crypt::select_block_crypt(&config.base.crypt, &pass);
    if let Some(warning) = &selected.warning {
        // Go logs this inside SelectBlockCrypt, with log.Printf.
        logf!("{warning}");
    }
    let block = selected.block;
    config.base.crypt = selected.method.to_string();

    // Start the SNMP logger if the feature is enabled.
    // Go: `go std.SnmpLogger(config.SnmpLog, config.SnmpPeriod)`.
    tokio::spawn(kcptun_std::snmp::snmp_logger(
        config.base.snmp_log.clone(),
        config.base.snmp_period,
    ));

    // Start the pprof server if the feature is enabled (D23).
    pprof::start(config.base.pprof);

    // Hand back the memory a burst needed once the process goes quiet, which is what Go's
    // runtime scavenger does for the Go binaries (plan 12.3, `kcptun_kcp::memory`). Nothing to
    // configure: it only acts on a process that has moved bytes and then stopped.
    tokio::spawn(kcptun_kcp::memory::trim_when_idle_default());

    // `numconn := uint16(config.Conn)`, with the truncation to zero refused — see `conn_u16`.
    // Go's cast is at client/main.go:410, *above* the `qpp.NewQPP` call at 417-420, so with both
    // `-conn 65536` and `-QPPCount 65536` it is the `-conn` guard that speaks first.
    let numconn = match conn_u16(config.conn) {
        Ok(n) => n,
        Err(msg) => log::fatal(&msg),
    };

    // Instantiate a shared QPP pad if the feature is enabled.
    let qpp = qpp_pad(&config.base, qpp_count);

    let config = Arc::new(config);

    // Go's `dial()` keeps `multiPort` and `block` in package scope; here one dialer holds both,
    // and the accept loop hands it to every `wait_conn`.
    let dialer = Arc::new(Dialer::new(config, block));

    // Go picks the compressed or the plain connection per session (`if config.NoComp`); it is a
    // process-wide setting, so the whole loop is built once for the type it selects.
    if dialer.config.base.no_comp {
        serve(listener, dialer, qpp, numconn, |conn| conn).await;
    } else {
        serve(listener, dialer, qpp, numconn, CompStream::new).await;
    }
}

/// Go's `log.Println("version:", VERSION)`, which comes before the listener.
// Go: kcptun/client/main.go:316
fn log_version() {
    logln!("version:", kcptun_std::VERSION);
}

/// The startup block, in Go's order and wording.
///
/// `listen_addr` is `listener.Addr()`, the address the socket really bound — `[::]:12948` for
/// `-l :12948`, not the flag text.
// Go: kcptun/client/main.go:334-360
fn log_startup(config: &ClientConfig, listen_addr: &str) {
    let base = &config.base;
    logln!("smux version:", base.smux_ver);
    logln!("listening on:", listen_addr);
    logln!("encryption:", base.crypt);
    logln!("QPP:", base.qpp);
    logln!("QPP Count:", base.qpp_count);
    logln!(
        "nodelay parameters:",
        base.no_delay,
        base.interval,
        base.resend,
        base.no_congestion
    );
    logln!("remote address:", config.remote_addr);
    logln!("sndwnd:", base.snd_wnd, "rcvwnd:", base.rcv_wnd);
    logln!("compression:", !base.no_comp);
    logln!("mtu:", base.mtu);
    logln!("ratelimit:", base.rate_limit);
    logln!(
        "datashard:",
        base.data_shard,
        "parityshard:",
        base.parity_shard
    );
    logln!("acknodelay:", base.ack_nodelay);
    logln!("dscp:", base.dscp);
    logln!("sockbuf:", base.sock_buf);
    logln!("smuxbuf:", base.smux_buf);
    logln!("framesize:", base.frame_size);
    logln!("streambuf:", base.stream_buf);
    logln!("keepalive:", base.keep_alive);
    logln!("conn:", config.conn);
    logln!("autoexpire:", config.auto_expire);
    logln!("scavengettl:", config.scavenge_ttl);
    logln!("snmplog:", base.snmp_log);
    logln!("snmpperiod:", base.snmp_period);
    logln!("quiet:", base.quiet);
    logln!("tcp:", base.tcp);
    logln!("pprof:", base.pprof); // Deviation V23: only printed when it is on, so the default banner stays Go's, line for
    // line. The default itself (accept from any source) is the deviation, and README and
    // docs/DECISIONS.md carry it.
    if base.strict_source {
        logln!("strictsource:", base.strict_source);
    }
}

/// The two red lines Go prints when an expired tunnel may outlive its replacement.
// Go: kcptun/client/main.go:374-377
fn scavenge_warnings(config: &ClientConfig) -> &'static [&'static str] {
    if config.auto_expire != 0 && config.scavenge_ttl > config.auto_expire {
        return &[
            "WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.",
            "Try limiting scavengettl to a smaller value.",
        ];
    }
    &[]
}

/// The `numconn := uint16(config.Conn)` cast, with the value that divides by zero refused.
///
/// **Deviation V19.** Go narrows `-conn` to a `uint16` and then indexes with
/// `rr % numconn`, so a multiple of 65536 — which passes the `config.Conn <= 0` check — makes
/// `numconn` **0** and panics with `integer divide by zero` at the *first accepted connection*
/// (reproduced with `reference/bin/client_darwin_arm64 -conn 65536`, which prints the whole
/// startup block and then a runtime panic once a client connects). The cast is kept otherwise
/// bit-exact: `-conn 65537` runs one tunnel here exactly as it does in Go.
// Go: kcptun/client/main.go:410 — `numconn := uint16(config.Conn)`
fn conn_u16(conn: i64) -> Result<u16, String> {
    let numconn = conn as u16;
    if numconn == 0 {
        return Err(format!(
            "conn {conn} does not fit in uint16: kcptun would truncate it to 0"
        ));
    }
    Ok(numconn)
}

// ---------------------------------------------------------------------------------------
// The local listener
// ---------------------------------------------------------------------------------------

/// Go's listener block: a unix socket when `-l` is not a `host:port`, a TCP listener otherwise.
///
/// The error is what `checkError` prints: a `*net.AddrError`/`*net.DNSError` from the resolver,
/// or the `*net.OpError` of the failing `bind`.
// Go: kcptun/client/main.go:317-332
fn listen_local(local_addr: &str) -> Result<LocalListener, String> {
    // Go: `if _, _, err := net.SplitHostPort(config.LocalAddr); err != nil { isUnix = true }`.
    if goaddr::is_host_port(local_addr) {
        listen::listen_tcp(local_addr)
    } else {
        listen::listen_unix(local_addr)
    }
}

// ---------------------------------------------------------------------------------------
// The accept loop
// ---------------------------------------------------------------------------------------

/// One smux session with the moment it stops being handed new streams.
// Go: kcptun/client/main.go:560 — `type timedSession struct`
struct TimedSession<C: SmuxConn> {
    session: Arc<Session<C>>,
    expiry_date: Instant,
}

// `derive(Clone)` would demand `C: Clone`; only the two handles are cloned.
impl<C: SmuxConn> Clone for TimedSession<C> {
    fn clone(&self) -> Self {
        TimedSession {
            session: Arc::clone(&self.session),
            expiry_date: self.expiry_date,
        }
    }
}

/// Go's scavenger goroutine plus the accept loop, for the connection type `-nocomp` selects.
///
/// Go creates `chScavenger` unconditionally and starts the goroutine only when `autoexpire > 0`;
/// nothing is ever sent on the channel otherwise, which is what `None` means here. Neither the
/// channel nor the goroutine writes a log line, so building them here — inside the function the
/// connection type monomorphises — keeps Go's observable order.
// Go: kcptun/client/main.go:404-444
async fn serve<C, F>(
    listener: LocalListener,
    dialer: Arc<Dialer>,
    qpp: Option<Arc<QppPad>>,
    numconn: u16,
    upper: F,
) where
    C: SmuxConn,
    F: Fn(KcpConn) -> C + Copy,
{
    let config = Arc::clone(&dialer.config);
    let scavenger_tx = if config.auto_expire > 0 {
        let (tx, rx) = mpsc::channel::<TimedSession<C>>(SCAVENGER_BACKLOG);
        tokio::spawn(scavenger(rx, config.scavenge_ttl, SCAVENGE_PERIOD));
        Some(tx)
    } else {
        None
    };

    // Go: `muxes := make([]timedSession, numconn)` — the zero value has a nil session, which is
    // `None` here.
    let mut muxes: Vec<Option<TimedSession<C>>> = (0..numconn).map(|_| None).collect();
    // rr tracks which pre-established session should carry the next client so short-lived TCP
    // dials do not hammer the same UDP tunnel.
    let mut rr: u16 = 0;

    loop {
        let (p1, p1_addr) = match listener.accept().await {
            Ok(conn) => conn,
            // Go: log.Fatalf("%+v", err)
            Err(err) => log::fatal(&err),
        };
        let idx = usize::from(rr % numconn);

        // Refresh the selected session if it is missing, closed, or past its TTL.
        let refresh = match &muxes[idx] {
            None => true,
            Some(mux) => {
                mux.session.is_closed()
                    || (config.auto_expire > 0 && Instant::now() > mux.expiry_date)
            }
        };
        if refresh {
            let session = dialer.wait_conn(upper).await;
            let mux = TimedSession {
                session,
                expiry_date: go_deadline(Instant::now(), config.auto_expire),
            };
            muxes[idx] = Some(mux.clone());
            // only track TTL when auto-expiration is enabled
            if let Some(tx) = &scavenger_tx {
                // Go blocks here once 128 sessions are queued; so does this. A send error means
                // the scavenger returned, which it never does while the channel is open — and Go
                // has no log line for it, so nothing is printed.
                let _ = tx.send(mux).await;
            }
        }
        let session = match &muxes[idx] {
            Some(mux) => Arc::clone(&mux.session),
            // Unreachable: the slot was just filled.
            None => continue,
        };

        // Serve the accepted client in its own task to keep the accept loop responsive.
        match p1 {
            LocalConn::Tcp(p1) => {
                tokio::spawn(handle_client(
                    qpp.clone(),
                    Arc::clone(&config),
                    session,
                    p1,
                    p1_addr,
                ));
            }
            #[cfg(unix)]
            LocalConn::Unix(p1) => {
                tokio::spawn(handle_client(
                    qpp.clone(),
                    Arc::clone(&config),
                    session,
                    p1,
                    p1_addr,
                ));
            }
        }
        rr = rr.wrapping_add(1);
    }
}

/// `t.Add(time.Duration(seconds) * time.Second)`, for the negative counts Go accepts.
fn go_deadline(t: Instant, seconds: i64) -> Instant {
    let (d, forward) = match seconds.checked_abs() {
        Some(abs) => (Duration::from_secs(abs.unsigned_abs()), seconds >= 0),
        // i64::MIN seconds is far beyond any representable instant either way.
        None => (Duration::MAX, false),
    };
    let moved = if forward {
        t.checked_add(d)
    } else {
        t.checked_sub(d)
    };
    moved.unwrap_or(t)
}

/// Closes sessions handed over by the accept loop once their TTL has run out.
///
/// `period` is Go's `scavengePeriod` constant; it is a parameter so the tests do not have to
/// wait five seconds.
// Go: kcptun/client/main.go:scavenger()
async fn scavenger<C: SmuxConn>(
    mut ch: mpsc::Receiver<TimedSession<C>>,
    scavenge_ttl: i64,
    period: Duration,
) {
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // tokio's first tick completes immediately; Go's `time.NewTicker` fires only after `period`.
    ticker.tick().await;

    // Pre-allocate with reasonable capacity to reduce slice growth overhead
    let mut session_list: Vec<TimedSession<C>> = Vec::with_capacity(16);
    // Go's `chScavenger` is never closed, so its receive arm is always live. Here the accept
    // loop owns the sender: if it ever went away the arm would complete instantly forever, so
    // it is switched off instead and the ticker keeps draining what is already in the list.
    let mut receiving = true;
    loop {
        tokio::select! {
            item = ch.recv(), if receiving => {
                match item {
                    Some(item) => session_list.push(TimedSession {
                        expiry_date: go_deadline(item.expiry_date, scavenge_ttl),
                        session: item.session,
                    }),
                    None => receiving = false,
                }
            }
            _ = ticker.tick() => {
                // Reuse slice capacity to avoid allocation
                let mut new_list = Vec::with_capacity(session_list.len());
                for s in session_list.drain(..) {
                    if s.session.is_closed() {
                        logln!(
                            "scavenger: session normally closed:",
                            GoAddr(s.session.local_addr())
                        );
                    } else if Instant::now() > s.expiry_date {
                        // Go logs the address after the close; `local_addr` is the value the
                        // session was built with either way.
                        let _ = s.session.close().await;
                        logln!(
                            "scavenger: session closed due to ttl:",
                            GoAddr(s.session.local_addr())
                        );
                    } else {
                        new_list.push(s);
                    }
                }
                session_list = new_list;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Dialling
// ---------------------------------------------------------------------------------------

/// Everything `dial()` needs, including the once-parsed `-remoteaddr`.
///
/// Go keeps `multiPort`, `multiPortParseError` and `multiPortOnce` as package-level variables of
/// `client/dial.go`, so the address is parsed on the first dial and reused for the life of the
/// process. There is exactly one `Dialer` per process for the same reason — `action` builds it
/// and the accept loop holds it — but scoping the `sync.Once` to the value instead of to the
/// program keeps the tests independent (a `static` would make every case after the first dial
/// the first case's address).
// Go: kcptun/client/dial.go:38-42
struct Dialer {
    /// The configuration `createConn` and `dial` read.
    config: Arc<ClientConfig>,
    /// The packet crypto, Go's `block kcp.BlockCrypt` parameter.
    block: Option<PacketCrypt>,
    /// Go's `multiPortOnce.Do(...)` result: the parse, or the error every dial repeats.
    multi_port: OnceLock<Result<MultiPort, MultiPortError>>,
}

impl Dialer {
    fn new(config: Arc<ClientConfig>, block: Option<PacketCrypt>) -> Dialer {
        Dialer {
            config,
            block,
            multi_port: OnceLock::new(),
        }
    }

    /// Go's `dial()`: pick a port out of `-remoteaddr` and bring up the KCP session.
    // Go: kcptun/client/dial.go:dial()
    async fn dial(&self) -> Result<Arc<UdpSession>, String> {
        let config = &self.config;
        // Parse the multiPort definition only once.
        let multi_port = self
            .multi_port
            .get_or_init(|| multiport::parse(&config.remote_addr));

        // Abort when the multiPort definition is invalid.
        let multi_port = match multi_port {
            Ok(mp) => mp,
            Err(err) => return Err(err.to_string()),
        };

        // Pick a random destination port within the configured range.
        let remote_addr = random_remote_addr(multi_port)?;

        // Use tcpraw to emulate a TCP transport when requested.
        if config.base.tcp {
            return self.dial_tcpraw(&remote_addr).await;
        }

        // Otherwise fall back to the standard UDP dialing path.
        let block = self.block.clone();
        let data_shard = config.base.data_shard as isize;
        let parity_shard = config.base.parity_shard as isize;
        // `dial_with_options` resolves the name with the blocking resolver (Go's
        // `ResolveUDPAddr` does too, on a goroutine that can park); running it on a worker
        // thread would stall every other task on that worker for the length of a DNS lookup.
        tokio::task::spawn_blocking(move || {
            UdpSession::dial_with_options(&remote_addr, block, data_shard, parity_shard)
        })
        .await
        // A `JoinError` is a panic in the resolver, which has no Go counterpart and no errno.
        .map_err(|err| err.to_string())?
        // Go's `kcp.DialWithOptions` fails either in `net.ResolveUDPAddr` (a `*net.AddrError` or
        // `*net.DNSError`, whose text `kcptun_kcp::addr` reproduces and which carries no errno)
        // or in `net.ListenUDP` (a syscall). The errno half is spelled from Go's table (D30).
        .map_err(|err| config::go_error_text(&err))
    }

    /// The `--tcp` half of `dial()`: a KCP session carried by fake TCP.
    ///
    /// Go's branch, step for step, including every `errors.Wrap` message and every `conn.Close()`
    /// on the way out. The session is built with `ownConn = true`, so closing it closes the
    /// tcpraw connection, which is what removes that connection's `filter/OUTPUT` rules.
    ///
    /// Off Linux `kcptun_tcpraw::dial` fails with Go's own `os not supported` before anything
    /// else happens, so the whole branch reduces to the one log line Go prints there.
    ///
    /// **An upstream bug this port does not reproduce (Deviation V22).** kcp-go's
    /// `defaultReadLoop` filters inbound datagrams by *Go type* as well as by
    /// address: `src` is a `*net.UDPAddr` whenever the session's remote is one, and then every
    /// packet whose `addr.(*net.UDPAddr)` assertion fails is counted as `InErrs` and dropped
    /// (`readloop.go:73-78`). A tcpraw connection reports its peers as `*net.TCPAddr`
    /// (`tcp_linux.go:189-191`), and `dial.go` hands `NewConn4` the `*net.UDPAddr` resolved
    /// here — so the pinned Go client receives **nothing** over `--tcp`, in v5.6.66 and in the
    /// current upstream alike (older kcp-go compared `addr.String()`, which works). Measured against the
    /// vendored v5.6.66 with a UDP socket that reports its peers as `*net.TCPAddr`: `read=""
    /// err=timeout`, `InErrs 0 -> 9`, where the same socket unwrapped echoes `hello` with no
    /// `InErrs`. This port carries one address type, so its filter compares addresses only
    /// (`kcptun_kcp`'s `SourceFilter`) and the session works. The server side is unaffected
    /// either way: a listener's monitor loop has no such assertion.
    // Go: kcptun/client/dial.go:65-88
    async fn dial_tcpraw(&self, remote_addr: &str) -> Result<Arc<UdpSession>, String> {
        let config = &self.config;

        // Go: `conn, err := tcpraw.Dial("tcp", remoteAddr)`, wrapped as "tcpraw.Dial()". The
        // `*net.OpError`s of `net.DialIP`/`net.DialTCP` are already spelled by `kcptun_tcpraw`;
        // the rest (`net.Interfaces()`, `getsockname`) arrive as bare errnos, spelled from Go's
        // own table rather than by Rust's `Display` (D30).
        let conn: Arc<dyn PacketConn> = Arc::new(
            kcptun_tcpraw::dial("tcp", remote_addr)
                .await
                .map_err(|err| format!("tcpraw.Dial(): {}", config::go_error_text(&err)))?,
        );

        // Go: `udpaddr, err := net.ResolveUDPAddr("udp", remoteAddr)`, whose error is returned
        // bare (`errors.WithStack`). As on the UDP path, the resolver runs on a blocking task:
        // `-remoteaddr` may well be a name, and a parked tokio worker is not replaced.
        let owned = remote_addr.to_string();
        let resolved = tokio::task::spawn_blocking(move || {
            kcptun_kcp::addr::resolve_udp_addr("udp", &owned)
        })
        .await
        .map_err(|err| err.to_string())
        .and_then(|result| result.map_err(|err| err.to_string()))
        // Go keeps the resolved `*net.UDPAddr` as the session's remote and lets the socket layer
        // encode it per family on every send; `dial_with_options` stores it the same way, so a
        // v4 remote prints as a dotted quad in the `smux version: … on connection:` line.
        .and_then(|udpaddr| {
            udpaddr
                .to_socket_addr(!udpaddr.is_ipv4())
                .map_err(|err| err.to_string())
        });
        let remote = match resolved {
            Ok(remote) => remote,
            Err(err) => {
                // Go: `conn.Close()` before returning.
                let _ = conn.close();
                return Err(err);
            }
        };

        // Go: `binary.Read(rand.Reader, binary.LittleEndian, &convid)`, wrapped as "read convid".
        // Unlike kcp-go's own dial, which ignores this error, `client/dial.go` fails the dial.
        let mut bytes = [0u8; 4];
        if let Err(err) = getrandom::fill(&mut bytes) {
            let _ = conn.close();
            return Err(format!("read convid: {err}"));
        }
        let convid = u32::from_le_bytes(bytes);

        // Go: `kcp.NewConn4(convid, udpaddr, block, config.DataShard, config.ParityShard, true,
        // conn)` — `true` is `ownConn`, so the session owns the fake-TCP connection.
        match UdpSession::new_conn(
            convid,
            remote,
            self.block.clone(),
            config.base.data_shard as isize,
            config.base.parity_shard as isize,
            true,
            Arc::clone(&conn),
        ) {
            Ok(session) => Ok(session),
            Err(err) => {
                let _ = conn.close();
                Err(format!("kcp.NewConn4(): {err}"))
            }
        }
    }
}

/// `fmt.Sprintf("%v:%v", multiPort.Host, minPort + rand % (maxPort-minPort+1))`.
///
/// The port is drawn **per dial**, i.e. per new session, not once per process, so `-conn 4`
/// against a port range spreads over the range. Go reads eight bytes from `crypto/rand`; so does
/// this (DECISIONS D14: conv ids and random ports come from the OS RNG).
// Go: kcptun/client/dial.go:56-63
fn random_remote_addr(multi_port: &MultiPort) -> Result<String, String> {
    let mut bytes = [0u8; 8];
    // Go: `binary.Read(rand.Reader, binary.LittleEndian, &randport)`, whose error it returns.
    getrandom::fill(&mut bytes).map_err(|err| err.to_string())?;
    let randport = u64::from_le_bytes(bytes);
    // `parse` guarantees min_port <= max_port <= 65535, so neither the span nor the sum wraps.
    let span = multi_port.max_port - multi_port.min_port + 1;
    let port = multi_port.min_port + randport % span;
    Ok(format!("{}:{}", multi_port.host, port))
}

impl Dialer {
    /// Brings up one KCP session with every tunable applied and upgrades it into an smux
    /// session.
    // Go: kcptun/client/main.go:createConn()
    async fn create_conn<C, F>(&self, upper: F) -> Result<Session<C>, String>
    where
        C: SmuxConn,
        F: Fn(KcpConn) -> C,
    {
        let base = &self.config.base;
        let kcpconn = self.dial().await.map_err(|err| format!("dial(): {err}"))?;

        kcpconn.set_stream_mode(true);
        kcpconn.set_write_delay(false);
        kcpconn.set_no_delay(
            base.no_delay as isize,
            base.interval as isize,
            base.resend as isize,
            base.no_congestion as isize,
        );
        kcpconn.set_window_size(base.snd_wnd as isize, base.rcv_wnd as isize);
        kcpconn.set_mtu(base.mtu as isize);
        kcpconn.set_ack_no_delay(base.ack_nodelay);
        // Go: kcpconn.SetRateLimit(uint32(config.RateLimit)) — the same low 32 bits.
        kcpconn.set_rate_limit(base.rate_limit as u32);

        // Go passes `config.SockBuf` (an int) straight to `SetReadBuffer`; `usize` cannot carry a
        // negative one, so it becomes 0. Both reach `setsockopt` and both kernels treat them alike
        // (see the same note in the server), so the log line is the same either way.
        let sock_buf = usize::try_from(base.sock_buf).unwrap_or(0);
        // Go's `*net.OpError.Net` is the network the socket was created with, and
        // `kcp.DialWithOptions` uses `net.ListenUDP("udp4", nil)` for an IPv4 remote — so the
        // client says `set udp4 0.0.0.0:…` where the server says `set udp …`. The session's
        // remote is stored in the family of that socket (`dial_with_options`), so `is_ipv4()`
        // answers the same question `kcptun_kcp::addr::dial_network` does.
        // Go: kcp-go/v5@v5.6.66 sess.go:1434-1439
        let network = if kcpconn.remote_addr().is_ipv4() {
            "udp4"
        } else {
            "udp"
        };
        if let Err(err) = kcpconn.set_dscp(base.dscp as i32) {
            logln!(
                "SetDSCP:",
                setsockopt_error(network, kcpconn.local_addr().ok(), &err)
            );
        }
        if let Err(err) = kcpconn.set_read_buffer(sock_buf) {
            logln!(
                "SetReadBuffer:",
                setsockopt_error(network, kcpconn.local_addr().ok(), &err)
            );
        }
        if let Err(err) = kcpconn.set_write_buffer(sock_buf) {
            logln!(
                "SetWriteBuffer:",
                setsockopt_error(network, kcpconn.local_addr().ok(), &err)
            );
        }

        logln!(
            "smux version:",
            base.smux_ver,
            "on connection:",
            GoAddr(kcpconn.local_addr().ok()),
            "->",
            GoAddr(Some(kcpconn.remote_addr()))
        );

        let smux_config = match smuxcfg::build_smux_config(
            base.smux_ver,
            base.smux_buf,
            base.stream_buf,
            base.frame_size,
            base.keep_alive,
        ) {
            Ok(cfg) => cfg,
            Err(err) => {
                let _ = kcpconn.close();
                return Err(format!("BuildSmuxConfig(): {err}"));
            }
        };

        let conn = upper(KcpConn::new(kcpconn));
        kcptun_smux::client(conn, Some(smux_config.into()))
            .map_err(|err| format!("createConn(): {err}"))
    }

    /// Keeps dialling until a healthy smux session becomes available.
    // Go: kcptun/client/main.go:waitConn()
    async fn wait_conn<C, F>(&self, upper: F) -> Arc<Session<C>>
    where
        C: SmuxConn,
        F: Fn(KcpConn) -> C + Copy,
    {
        loop {
            match self.create_conn(upper).await {
                Ok(session) => return Arc::new(session),
                Err(err) => {
                    logln!("re-connecting:", err);
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Proxying
// ---------------------------------------------------------------------------------------

/// Tunnels one accepted TCP/unix client through an smux stream.
// Go: kcptun/client/main.go:handleClient()
async fn handle_client<P1, C>(
    qpp: Option<Arc<QppPad>>,
    config: Arc<ClientConfig>,
    session: Arc<Session<C>>,
    p1: P1,
    p1_addr: String,
) where
    P1: HalfCloseWrite + Unpin,
    C: SmuxConn,
{
    let quiet = config.base.quiet;

    // Transport layer: accept the inbound socket and clean it up on exit (`p1` is dropped on
    // every path below, which closes it as Go's `defer p1.Close()` does).
    let p2 = match session.open_stream().await {
        Ok(p2) => p2,
        Err(err) => {
            if !quiet {
                // Go: `log.Println(err)`. smux hands back the KCP socket's own error when the
                // session died on one, so its errno is spelled from Go's table (D30); smux's own
                // messages pass through unchanged.
                logln!(config::smux_error_text(&err));
            }
            return;
        }
    };

    let s2 = SmuxStream::new(p2);
    // Go: fmt.Sprintf("%v(%d)", p2.RemoteAddr(), p2.ID())
    let stream_id = format!("{}({})", GoAddr(s2.remote_addr()), s2.id());
    if !quiet {
        logln!("stream opened", "in:", p1_addr, "out:", stream_id);
    }

    // Begin piping data bidirectionally between the socket and the smux stream. Both ends are
    // closed when it returns, as Go's Pipe closes them.
    let (err1, err2) = match qpp {
        #[cfg(feature = "qpp")]
        Some(pad) => {
            // Replace the smux side with a QPP-wrapped port (Go: std.NewQPPPort).
            let s2 = kcptun_std::qpp::QppStream::new(s2, pad, config.base.key.as_bytes());
            pipe(p1, s2, config.base.close_wait).await
        }
        #[cfg(not(feature = "qpp"))]
        Some(pad) => match *pad {},
        None => pipe(p1, s2, config.base.close_wait).await,
    };

    // Report non-EOF errors so operators can diagnose failing streams. `pipe` reports a clean
    // end of stream as `Ok(())`, which is Go's `errors.Is(err, io.EOF)` arm.
    if !quiet {
        for err in [err1, err2] {
            if let Err(err) = err {
                // D30: `err` is a read/write failure on one of the two halves — the inbound
                // TCP socket (`p1`), or the smux stream over KCP, whose errno the
                // `kcptun_smux::Error` -> `io::Error` conversion carries across. Either way
                // the errno is spelled from Go's table. Go's is a `*net.OpError` and still
                // carries the `read tcp <local>-><remote>: read:` prefix this port does not
                // build (09.1).
                logln!(
                    "pipe:",
                    config::go_error_text(&err),
                    "in:",
                    p1_addr,
                    "out:",
                    stream_id
                );
            }
        }
        // Go: `defer logln("stream closed", ...)`, which runs after the two lines above.
        logln!("stream closed", "in:", p1_addr, "out:", stream_id);
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
