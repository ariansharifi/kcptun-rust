//! kcptun server: Rust port of `reference/kcptun/server/main.go`.
//!
//! The order of everything here is Go's: the flag table and the `-c` overlay, the `ratelimit`
//! fix-up, the `-log` redirect, `ApplyMode`, the startup log block, the QPP and smux checks, key
//! derivation, the SNMP logger and pprof, then one KCP listener per port of `-l` and an accept
//! loop per listener.
//!
//! ```text
//! KCP listener -> UDPSession -> [CompStream] -> smux server -> stream -> [QPP] -> pipe -> target
//! ```
//!
//! **Memory.** No per-connection or per-stream buffer is allocated up front. The copy buffers
//! come from the process-wide pool only once a direction has data (DECISIONS D17), and the
//! smux → target direction takes none at all: it drains received frames straight into the
//! target socket, which is what Go's `Copy` does through `io.WriterTo`
//! (`kcptun_std::pipe::HalfCloseWrite::FRAME_SOURCE`).
#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use kcptun_kcp::{Listener, PacketConn};
use kcptun_smux::{SmuxConn, Stream};
use kcptun_std::cli::{Context, RunOutcome, SystemEnv, filepath_base};
use kcptun_std::comp::CompStream;
use kcptun_std::config::{self, ServerConfig};
use kcptun_std::kcpconn::KcpConn;
// The QPP pad and the `net.OpError` texts are shared with the client binary, which needs every
// one of them (`kcptun_std::mainutil`).
use kcptun_std::mainutil::{GoAddr, QppPad, check_qpp, op_error, qpp_pad, setsockopt_error};
use kcptun_std::pipe::{HalfCloseWrite, pipe};
use kcptun_std::smuxio::SmuxStream;
use kcptun_std::{crypt, goaddr, log, logf, logln, multiport, pprof, runtime, signal, smuxcfg};
use tokio::net::TcpStream;

/// How long `handleMux` waits for the target connection before giving up.
// Go: kcptun/server/main.go:493 — `const dialTimeout = 10 * time.Second`
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the target is a TCP address or a unix socket path.
// Go: kcptun/server/main.go:56-59 — `const ( TGT_UNIX = iota; TGT_TCP )`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TargetType {
    Unix,
    Tcp,
}

// ---------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------

fn main() {
    // Go: `log.SetFlags(log.LstdFlags | log.Lshortfile)` when VERSION == "SELFBUILD". The
    // logger of this port starts with exactly those flags (`log::default_flags()`), so there is
    // nothing to set here.
    let runtime = log::check_error(runtime::build());
    runtime.block_on(run());
}

/// Go's `main()` body: build the app, run it, and let the action do the work.
// Go: kcptun/server/main.go:main()
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
    let app = config::server_app(filepath_base(argv.first().map_or("", String::as_str)));
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

    // The action returns only when there is nothing left to serve (a bad `-l`, say). Go's
    // `postProcess` runs on the signal path alone and leaves tcpraw's rules behind here; this
    // port runs the exit hooks on every path it controls (step 10.4).
    signal::post_process();
}

/// Go's `myApp.Action`.
// Go: kcptun/server/main.go:myApp.Action
async fn action(c: &Context) {
    let mut config = ServerConfig::from_context(c);

    // Go: `if c.String("c") != "" { checkError(parseJSONConfig(&config, c.String("c"))) }`.
    let config_file = c.string("c");
    if !config_file.is_empty() {
        log::check_error(config::parse_json_config(&mut config, &config_file));
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

    log_startup(&config);

    // Go: `if config.QPP { suggestions, err := std.ValidateQPPParams(...); ... }`.
    let qpp_count = check_qpp(&config.base);

    // Guard against negotiating unsupported smux protocol versions.
    // Go: `if config.SmuxVer > maxSmuxVer { log.Fatal("unsupported smux version:", ...) }`.
    if let Err(msg) = config.base.check_smux_ver() {
        log::fatal(&msg);
    }
    // Deviation V07: a shard count Go silently turns into undecodable Leopard parity.
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

    // Instantiate a shared QPP pad if the feature is enabled.
    let qpp = qpp_pad(&config.base, qpp_count);

    let config = Arc::new(config);

    // Parse the listen address which may contain a port range.
    let mp = match multiport::parse(&config.listen) {
        Ok(mp) => mp,
        Err(err) => {
            // Go: `log.Println(err); return err` — the action's error, which main ignores.
            logln!(err);
            return;
        }
    };

    // Spawn an accept loop per listener and track each task, Go's WaitGroup.
    let mut listeners = Vec::new();

    // Create listeners for every port inside the configured range.
    for port in mp.min_port..=mp.max_port {
        let listen_addr = format!("{}:{}", mp.host, port);

        // Optionally expose a tcpraw listener alongside UDP.
        if config.base.tcp {
            match tcpraw_listen(&listen_addr).await {
                Ok(conn) => {
                    logf!("Listening on: {listen_addr}/tcp");
                    let lis = log::check_error(Listener::serve_conn(
                        block.clone(),
                        config.base.data_shard as isize,
                        config.base.parity_shard as isize,
                        conn,
                    ));
                    listeners.push(tokio::spawn(serve_listener(
                        lis,
                        qpp.clone(),
                        Arc::clone(&config),
                    )));
                }
                // Go: `log.Println(err)` over whatever `tcpraw.Listen` refused with. The one a
                // `--tcp` server actually meets is the `*net.OpError` of `net.ListenTCP`, which
                // `addr::listen_op_error` has already spelled; the rest (`net.Interfaces()`, the
                // raw-socket `socket`/`bind`) arrive as bare errnos, spelled from Go's own table
                // rather than by Rust's `Display` (D30).
                Err(err) => logln!(config::go_error_text(&err)),
            }
        }

        // Always stand up the UDP listener; this is the default transport.
        logf!("Listening on: {listen_addr}/udp");
        let lis = log::check_error(
            Listener::listen_with_options(
                &listen_addr,
                block.clone(),
                config.base.data_shard as isize,
                config.base.parity_shard as isize,
            )
            .map_err(|err| listen_error(&listen_addr, &err)),
        );
        listeners.push(tokio::spawn(serve_listener(
            lis,
            qpp.clone(),
            Arc::clone(&config),
        )));
    }

    // Go: wg.Wait()
    for task in listeners {
        let _ = task.await;
    }
}

/// The startup block, in Go's order and wording.
// Go: kcptun/server/main.go:299-322
fn log_startup(config: &ServerConfig) {
    let base = &config.base;
    logln!("version:", kcptun_std::VERSION);
    logln!("smux version:", base.smux_ver);
    logln!("listening on:", config.listen);
    logln!("target:", config.target);
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
    logln!("snmplog:", base.snmp_log);
    logln!("snmpperiod:", base.snmp_period);
    logln!("pprof:", base.pprof);
    logln!("quiet:", base.quiet);
    logln!("tcp:", base.tcp); // Deviation V23: only printed when it is on, so the default banner stays Go's, line for
    // line. The default itself (accept from any source) is the deviation, and README and
    // docs/DECISIONS.md carry it.
    if base.strict_source {
        logln!("strictsource:", base.strict_source);
    }
}

/// The tcpraw listener `--tcp` asks for: a fake-TCP transport alongside the UDP one.
///
/// Go calls `tcpraw.Listen("tcp", listenAddr)` and, when it fails, logs the error and carries on
/// with UDP only — a failure here is never fatal. Off Linux the call cannot succeed: Go builds a
/// stub whose `Listen` returns `os not supported`, and so does `kcptun_tcpraw`, so `--tcp` logs
/// that one line there and the UDP listener still comes up.
///
/// On Linux it needs `CAP_NET_RAW` for the raw sockets; the `filter/OUTPUT` rules are best
/// effort (see `kcptun_tcpraw::listen`), and closing the connection removes them.
// Go: kcptun/server/main.go:370-379 — `if conn, err := tcpraw.Listen("tcp", listenAddr); err == nil`
async fn tcpraw_listen(listen_addr: &str) -> io::Result<Arc<dyn PacketConn>> {
    let conn = kcptun_tcpraw::listen("tcp", listen_addr).await?;
    Ok(Arc::new(conn))
}

/// The text a failed `kcp.ListenWithOptions` carries into `checkError`.
///
/// Go's `ListenWithOptions` does two things that can fail. `net.ResolveUDPAddr` returns a
/// `*net.AddrError` or `*net.DNSError` whose text (`address x: missing port in address`,
/// `lookup x: no such host`) `kcptun_kcp::addr` already reproduces verbatim, so it is passed
/// through. `net.ListenUDP` returns a `*net.OpError` — `listen udp <addr>: bind: <errno>` — built
/// from the **resolved** `*net.UDPAddr`, not from the flag text, which is why the address is
/// resolved again here (only on this fatal path; `-l localhost:29900` prints `127.0.0.1:29900`
/// the way Go does). Only the syscall failure carries an errno, which is what tells the two
/// apart: every error `kcptun_kcp::addr`'s resolver builds is a plain message.
///
/// The syscall is named `bind` because that is the one that fails in practice (`address already
/// in use`, `permission denied`, `cannot assign requested address`); a `socket` or `setsockopt`
/// failure inside the same call would be named differently by Go.
// Go: kcp-go/v5@v5.6.66 sess.go:1381-1389, go1.27.1 net/net.go:(*OpError).Error()
fn listen_error(listen_addr: &str, err: &io::Error) -> String {
    if err.raw_os_error().is_none() {
        return err.to_string();
    }
    let addr = kcptun_kcp::addr::resolve_udp_addr("udp", listen_addr)
        .map_or_else(|_| listen_addr.to_string(), |a| a.to_string());
    op_error("listen", "udp", Some(&addr), "bind", err)
}

// ---------------------------------------------------------------------------------------
// Accept loops
// ---------------------------------------------------------------------------------------

/// Drains incoming KCP conversations from `lis` and dispatches each one to [`handle_mux`].
// Go: kcptun/server/main.go:serveListener()
async fn serve_listener(lis: Arc<Listener>, qpp: Option<Arc<QppPad>>, config: Arc<ServerConfig>) {
    // Go passes `config.SockBuf` (an int) straight to `SetReadBuffer`; `usize` cannot carry a
    // negative one, so it becomes 0. Both values reach `setsockopt(SO_RCVBUF)` and both kernels
    // treat them alike, so the log lines are the same either way (measured on both hosts):
    // macOS rejects `-1` and `0` with `EINVAL`, and Linux accepts both without error (a negative
    // `int` is read as a huge `u32` and clamped to `net.core.rmem_max`, `0` is raised to
    // `SOCK_MIN_RCVBUF`). Only the buffer Linux ends up with differs, and nothing reports it.
    let sock_buf = usize::try_from(config.base.sock_buf).unwrap_or(0);
    if let Err(err) = lis.set_dscp(config.base.dscp as i32) {
        logln!("SetDSCP:", setsockopt_error("udp", lis.addr().ok(), &err));
    }
    if let Err(err) = lis.set_read_buffer(sock_buf) {
        logln!(
            "SetReadBuffer:",
            setsockopt_error("udp", lis.addr().ok(), &err)
        );
    }
    if let Err(err) = lis.set_write_buffer(sock_buf) {
        logln!(
            "SetWriteBuffer:",
            setsockopt_error("udp", lis.addr().ok(), &err)
        );
    }

    // Drain incoming KCP conversations, configure each one, and hand it off to handle_mux in a
    // new task so the listener keeps accepting.
    loop {
        let conn = match lis.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                // Go: log.Printf("%+v", err). A read error off the socket carries an errno,
                // spelled from Go's table (D30); Go's own is wrapped in a `*net.OpError` this
                // port does not build (09.1), so only the errno half matches.
                logf!("{}", config::go_error_text(&err));
                // Go's `continue` spins at 100% CPU once the listener is dead, re-logging the
                // same terminal error forever. Nothing in this binary closes a listener, so the
                // branch is unreachable in the ported program; parking instead of spinning
                // keeps Go's observable behaviour (the task never returns, so the process never
                // exits) without the busy loop.
                if lis.is_closed() || lis.read_error().is_set() {
                    std::future::pending::<()>().await;
                }
                continue;
            }
        };
        logln!("remote address:", conn.remote_addr());
        conn.set_stream_mode(true);
        conn.set_write_delay(false);
        conn.set_no_delay(
            config.base.no_delay as isize,
            config.base.interval as isize,
            config.base.resend as isize,
            config.base.no_congestion as isize,
        );
        conn.set_mtu(config.base.mtu as isize);
        conn.set_window_size(config.base.snd_wnd as isize, config.base.rcv_wnd as isize);
        conn.set_ack_no_delay(config.base.ack_nodelay);
        // Go: conn.SetRateLimit(uint32(config.RateLimit)) — the same low 32 bits.
        conn.set_rate_limit(config.base.rate_limit as u32);

        let conn = KcpConn::new(conn);
        if config.base.no_comp {
            tokio::spawn(handle_mux(qpp.clone(), conn, Arc::clone(&config)));
        } else {
            tokio::spawn(handle_mux(
                qpp.clone(),
                CompStream::new(conn),
                Arc::clone(&config),
            ));
        }
    }
}

/// Drives a single KCP session: accepts smux streams and forwards each one to the target.
// Go: kcptun/server/main.go:handleMux()
async fn handle_mux<C: SmuxConn>(qpp: Option<Arc<QppPad>>, conn: C, config: Arc<ServerConfig>) {
    // Determine whether the upstream target is TCP or a UNIX socket path.
    let target_type = if goaddr::is_host_port(&config.target) {
        TargetType::Tcp
    } else {
        TargetType::Unix
    };
    logln!(
        "smux version:",
        config.base.smux_ver,
        "on connection:",
        GoAddr(conn.local_addr()),
        "->",
        GoAddr(conn.remote_addr())
    );

    let smux_config = match smuxcfg::build_smux_config(
        config.base.smux_ver,
        config.base.smux_buf,
        config.base.stream_buf,
        config.base.frame_size,
        config.base.keep_alive,
    ) {
        Ok(cfg) => cfg,
        Err(err) => {
            logln!(err);
            let _ = conn.close().await;
            return;
        }
    };

    // Create the smux server session.
    let mux = match kcptun_smux::server(conn, Some(smux_config.into())) {
        Ok(mux) => mux,
        Err(err) => {
            // Go returns here without closing conn; the configuration was already verified, so
            // this is unreachable either way.
            logln!(err);
            return;
        }
    };

    // Accept and handle smux streams until the session terminates.
    loop {
        let stream = match mux.accept_stream().await {
            Ok(stream) => stream,
            Err(err) => {
                // Go: `log.Println(err)`. smux hands back the KCP socket's own error when the
                // session died on one, so its errno is spelled from Go's table (D30); smux's own
                // messages pass through unchanged.
                logln!(config::smux_error_text(&err));
                break;
            }
        };

        tokio::spawn(serve_stream(
            qpp.clone(),
            Arc::clone(&config),
            target_type,
            stream,
        ));
    }

    // Go: defer mux.Close()
    let _ = mux.close().await;
}

/// Dials the target for one accepted stream and hands both ends to [`handle_client`].
// Go: kcptun/server/main.go:handleMux()'s per-stream goroutine
async fn serve_stream(
    qpp: Option<Arc<QppPad>>,
    config: Arc<ServerConfig>,
    target_type: TargetType,
    p1: Stream,
) {
    let target = config.target.as_str();
    match target_type {
        TargetType::Tcp => match tokio::time::timeout(DIAL_TIMEOUT, dial_tcp(target)).await {
            Ok(Ok(p2)) => {
                // Go turns Nagle off on every TCP connection it dials; tokio does not, and
                // Nagle on the target socket would add delay the Go server never has. The
                // error is dropped there too.
                // Go: net/tcpsock_posix.go:newTCPConn() — `setNoDelay(fd, true)`
                let _ = p2.set_nodelay(true);
                let addr = p2
                    .peer_addr()
                    .map_or_else(|_| target.to_string(), |a| a.to_string());
                handle_client(qpp, p1, p2, addr, &config).await;
            }
            Ok(Err(err)) => fail_stream(p1, &err).await,
            Err(_) => fail_stream(p1, &dial_error("tcp", target, None)).await,
        },
        #[cfg(unix)]
        TargetType::Unix => {
            match tokio::time::timeout(DIAL_TIMEOUT, tokio::net::UnixStream::connect(target)).await
            {
                // Go's RemoteAddr for a dialled unix socket is the path it dialled.
                Ok(Ok(p2)) => handle_client(qpp, p1, p2, target.to_string(), &config).await,
                Ok(Err(err)) => fail_stream(p1, &dial_error("unix", target, Some(&err))).await,
                Err(_) => fail_stream(p1, &dial_error("unix", target, None)).await,
            }
        }
        #[cfg(not(unix))]
        TargetType::Unix => {
            // Deviation V09: no unix-domain sockets off unix.
            let _ = qpp;
            fail_stream(p1, &format!("dial unix {target}: os not supported")).await;
        }
    }
}

/// Go's `net.DialTimeout("tcp", target, …)`, minus the timeout (the caller supplies it).
///
/// The resolution is done here rather than left to `TcpStream::connect` because Go's
/// `*net.OpError` carries the **resolved** address: `-t localhost:12948` fails with
/// `dial tcp [::1]:12948: connect: connection refused`, not with the target as it was typed. Like
/// Go's `dialSerial` this tries the addresses in turn and reports the first failure.
///
/// A resolver failure is a `*net.OpError` with a `nil` `Addr` wrapping a `*net.DNSError`, which
/// `OpError.Error()` prints as `dial tcp: lookup <host>: …`. `std` cannot tell the resolver's
/// failure modes apart, so the text after `lookup <host>: ` is the platform's message rather than
/// Go's `no such host`/`server misbehaving` — the only part of this that is not Go's exactly.
// Go: go1.27.1 net/dial.go:DialTimeout(), net/dial.go:dialSerial(), net/net.go:(*OpError).Error()
async fn dial_tcp(target: &str) -> Result<TcpStream, String> {
    let addrs = match tokio::net::lookup_host(target).await {
        Ok(addrs) => addrs,
        Err(err) => {
            let host = goaddr::split_host_port(target).map_or(target, |(host, _)| host);
            return Err(format!(
                "dial tcp: lookup {host}: {}",
                config::go_error_text(&err)
            ));
        }
    };

    let mut first: Option<String> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if first.is_none() {
                    first = Some(dial_error("tcp", &addr.to_string(), Some(&err)));
                }
            }
        }
    }
    // Go: `dialSerial` with an empty address list — unreachable, the resolver errors instead.
    Err(first.unwrap_or_else(|| "dial tcp: missing address".to_string()))
}

/// Go's `log.Println(err); p1.Close()` when the target could not be dialled.
// Go: kcptun/server/main.go:504-508
async fn fail_stream(p1: Stream, err: &str) {
    logln!(err);
    let _ = p1.close().await;
}

/// The text Go's `net.DialTimeout` failure carries into `log.Println(err)`.
///
/// Go hands back a `*net.OpError`, whose `Error()` is `dial <net> <addr>: <op>: <errno>` — or
/// `dial <net> <addr>: i/o timeout` when the deadline ran out (`err = None` here). The errno is
/// spelled Go's way by [`config::go_error_text`]. `address` is the address Go's `OpError` holds:
/// the resolved one from [`dial_tcp`], or the target as typed on the timeout path (where Go's is
/// resolved too, so a hostname target reads differently — a DNS-plus-10s case 09.5 skips).
// Go: net/net.go:OpError.Error(), reached from kcptun/server/main.go:505
fn dial_error(network: &str, address: &str, err: Option<&io::Error>) -> String {
    match err {
        Some(err) => op_error("dial", network, Some(address), "connect", err),
        None => format!("dial {network} {address}: i/o timeout"),
    }
}

/// Relays traffic between an smux stream and the target, optionally through QPP.
// Go: kcptun/server/main.go:handleClient()
async fn handle_client<P2>(
    qpp: Option<Arc<QppPad>>,
    p1: Stream,
    p2: P2,
    p2_addr: String,
    config: &ServerConfig,
) where
    P2: HalfCloseWrite + Unpin,
{
    let quiet = config.base.quiet;
    let s1 = SmuxStream::new(p1);
    // Go: fmt.Sprintf("%v(%d)", p1.RemoteAddr(), p1.ID())
    let stream_id = format!("{}({})", GoAddr(s1.remote_addr()), s1.id());
    if !quiet {
        logln!("stream opened", "in:", stream_id, "out:", p2_addr);
    }

    // Begin piping data bidirectionally between the upstream and downstream ends. Both ends are
    // closed when it returns, as Go's Pipe closes them.
    let (err1, err2) = match qpp {
        #[cfg(feature = "qpp")]
        Some(pad) => {
            // Optionally wrap the smux side with QPP obfuscation (Go: std.NewQPPPort).
            let s1 = kcptun_std::qpp::QppStream::new(s1, pad, config.base.key.as_bytes());
            pipe(s1, p2, config.base.close_wait).await
        }
        #[cfg(not(feature = "qpp"))]
        Some(pad) => match *pad {},
        None => pipe(s1, p2, config.base.close_wait).await,
    };

    // Report non-EOF errors so operators can diagnose failing streams. `pipe` reports a clean
    // end of stream as `Ok(())`, which is Go's `errors.Is(err, io.EOF)` arm.
    if !quiet {
        for err in [err1, err2] {
            if let Err(err) = err {
                // D30: `err` is a read/write failure on one of the two halves — the outbound
                // TCP socket to `-t` (`p2`), or the smux stream over KCP, whose errno the
                // `kcptun_smux::Error` -> `io::Error` conversion carries across. Either way
                // the errno is spelled from Go's table. Go's is a `*net.OpError` and still
                // carries the `read tcp <local>-><remote>: read:` prefix this port does not
                // build (09.1).
                logln!(
                    "pipe:",
                    config::go_error_text(&err),
                    "in:",
                    stream_id,
                    "out:",
                    p2_addr
                );
            }
        }
        logln!("stream closed", "in:", stream_id, "out:", p2_addr);
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
