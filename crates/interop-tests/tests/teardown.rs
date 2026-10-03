//! Leak regression tests of the proxy pipe's teardown (deviation V24, DECISIONS D35): the real
//! `kcptun-client` and `kcptun-server` binaries (either implementation), with every socket each
//! process holds counted before and after each case.
//!
//! v0.2.1 leaked the TCP side of finished connections in both binaries: `FIN-WAIT-2` sockets
//! with megabytes unread, `CLOSE-WAIT` sockets, and `TCP_CLOSE` sockets whose descriptor stayed
//! open (invisible to `ss`), until the host's `tcp_mem` was spent. Each case here drives one way
//! a connection ends, then asserts that every Rust process is back to the baseline it held before
//! the case (its listener and UDP sockets) within the bound of the mechanism that ends the pipe:
//! the same descriptor count, no TCP connection in any state on the test ports (so no
//! `FIN-WAIT-2` and no `CLOSE-WAIT`), and no dead socket. See
//! `kcptun_interop_tests::teardown` for the baseline and the bounds, and
//! `kcptun_testkit::sockets` for how a dead socket is told on each platform.
//!
//! | Test | Case | Asserted on |
//! |---|---|---|
//! | `e2e_teardown_1_target_closes_while_the_app_sends` | 1: the target closes mid-transfer, the application keeps sending | client: closes the local socket, never leaves it in `FIN-WAIT-2`; server |
//! | `e2e_teardown_1_target_resets_while_the_app_sends` | 1 with an RST from the target | client, server |
//! | `e2e_teardown_2_app_resets_into_a_stalled_target` | 2: the target never reads, the window fills, the application resets | client (probe, then its grace), server (stall rule) |
//! | `e2e_teardown_3_server_killed_while_streams_are_blocked` | 3: two streams blocked on stalled targets, the server is killed | client: every local socket of the session; after a restarted server and one round trip, exactly its baseline (the dead session's UDP socket released) |
//! | `e2e_teardown_4_1_app_closes_while_the_target_sends` | 4, mirror of 1: the application closes mid-download, the target keeps sending | server: closes the target socket; client |
//! | `e2e_teardown_4_2_target_resets_into_a_stalled_app` | 4, mirror of 2: the application never reads, the window fills, the target resets | server (probe, then its grace), client (stall rule) |
//! | `e2e_teardown_4_3_client_killed_while_streams_are_blocked` | 4, mirror of 3: two downloads blocked on applications that never read, the client is killed | server: every target socket of the session |
//! | `e2e_teardown_starved_session_frees_its_stalled_streams` | `-smuxbuf == -streambuf`, `-conn 1`: two stalled downloads spend the session's receive buffer, so no FIN can be read; the targets reset | server (probe, grace), client (starvation rule) |
//! | `e2e_teardown_1_at_the_default_closewait` | 1 with both binaries' default `-closewait` (client 0, server 30) | client, server |
//! | `e2e_teardown_4_1_at_the_default_closewait` | 4.1 with the defaults: the server holds the target for its 30 s grace, then lets go | client, server |
//! | `interop_teardown_1_rust_client_go_server` | 5: case 1, Rust client, Go server | Rust client |
//! | `interop_teardown_2_rust_client_go_server` | 5: case 2, Rust client, Go server | Rust client |
//! | `interop_teardown_3_rust_client_go_server` | 5: case 3, Rust client, Go server killed | Rust client |
//! | `interop_teardown_1_go_client_rust_server` | 5: case 1, Go client, Rust server | Rust server |
//! | `interop_teardown_2_go_client_rust_server` | 5: case 2, Go client, Rust server: the documented Go leak (below) | Rust server holds its one live connection |
//! | `interop_teardown_3_go_client_rust_server` | 5: case 3 needs a Rust survivor, so it runs mirrored (4.3): the Go client is killed | Rust server: every target socket of the session |
//!
//! In a mixed pairing only the Rust process is asserted on; what the Go process holds is logged.
//! Go kcptun 2026 (`reference/bin`) keeps its own form of the leak: its half-close `Pipe` on
//! smux v1.5.55 parks a writer on window credit without ever waking it for the peer's FIN or for
//! a reset of its own source socket. So a Go client never notices a local RST while it is parked
//! on credit, never ends the stream, and the Rust server rightly keeps the target for as long as
//! the stream lives: `interop_teardown_2_go_client_rust_server` asserts exactly that expectation
//! instead of a teardown.
//!
//! The windows (see `teardown::Window`) carry a lower bound where a timer ends the pipe, which is
//! what shows *which* grace applied: the cases run with `-closewait` 2 on the client and 3 on the
//! server (`Graces::EXPLICIT`), except the two default runs. A measured time outside its window
//! fails the case and names the mechanism that was expected.
//!
//! Every case holds `e2e::serial_guard` for its whole body, is bounded by a timeout, and needs
//! the binaries, hence `#[ignore]`. The cases that wait for the stall rule (30 s) or for the smux
//! keepalive (up to 60 s) are the slow ones; the whole file takes about eight minutes.
//!
//! macOS (the socket probe runs `lsof`):
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! KCPTUN_GO_BIN_DIR=$PWD/reference/bin \
//!   cargo test -p kcptun-interop-tests --test teardown -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Linux (the probe reads `/proc`; the Go binaries are found as `<name>_linux_<arch>`). The same
//! command, or, on a host without a toolchain, a cross-built test binary:
//!
//! ```sh
//! cargo zigbuild --release --target aarch64-unknown-linux-gnu -p kcptun-client -p kcptun-server
//! # `cargo zigbuild` is `cargo build`: `--test` builds the test binary without running it.
//! cargo zigbuild --target aarch64-unknown-linux-gnu -p kcptun-interop-tests --test teardown
//! # copy target/aarch64-unknown-linux-gnu/debug/deps/teardown-<hash>, the two Rust binaries and
//! # reference/bin/{client,server}_linux_arm64 to the host, then:
//! KCPTUN_RS_BIN_DIR=<dir of kcptun-client> KCPTUN_GO_BIN_DIR=<dir of client_linux_arm64> \
//!   ./teardown-<hash> --ignored --nocapture --test-threads 1
//! ```
//!
//! `--test-threads 1` only keeps the output in order: the cases serialise themselves.
//! `KCPTUN_TEST_KEEP_LOGS=1` keeps the binaries' logs.

use std::time::{Duration, Instant};

use kcptun_interop_tests::e2e::serial_guard;
use kcptun_interop_tests::teardown::{
    Behaviour, Buffers, End, FILL_LAG, FILL_QUIET, Graces, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT,
    PERSIST_PROBE, Pairing, Rig, RigSpec, Role, SLACK, WATCH, Window, fill_until_blocked,
    keep_sending, read_then_close, reset, socket_stall,
};
use kcptun_testkit::sockets::TcpState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bytes the target reads before it ends the connection, in case 1.
const CUT_AFTER: u64 = 256 * 1024;

/// Bytes the application reads of a download before it closes, in case 4.1.
const READ_BEFORE_CLOSE: u64 = 256 * 1024;

/// The receive buffer of an application that never reads: small, so the stream behind it
/// blocks after a few KiB.
const APP_RCVBUF: u32 = 16 * 1024;

/// Streams blocked at once in the kill and starvation cases.
const STREAMS: usize = 2;

/// Bytes of the round trip that brings a new session up after the server's restart in case 3.
const RECOVERY_ECHO: usize = 4096;

/// How long a pipeline may take to fill.
const FILL_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs one case: serialised against every other end-to-end case, and bounded so a hang fails
/// the test (and drops the rig, which kills both processes) instead of blocking forever.
async fn case(timeout: Duration, body: impl Future<Output = ()>) {
    let _serial = serial_guard().await;
    let started = Instant::now();
    if tokio::time::timeout(timeout, body).await.is_err() {
        panic!("teardown case timed out after {timeout:?}");
    }
    eprintln!("case done in {:.1} s", started.elapsed().as_secs_f64());
}

/// Connects `n` applications whose targets stall, and writes into each until the tunnel behind
/// it is full.
async fn fill_uploads(rig: &Rig, n: usize) -> Vec<TcpStream> {
    let mut apps = Vec::new();
    for _ in 0..n {
        apps.push(rig.connect_app(None).await);
    }
    rig.target
        .accepted(n, FILL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut fills = tokio::task::JoinSet::new();
    for (i, mut app) in apps.into_iter().enumerate() {
        fills.spawn(async move {
            let filled = fill_until_blocked(&mut app, FILL_QUIET).await;
            (i, app, filled)
        });
    }
    let mut apps = Vec::new();
    while let Some(joined) = fills.join_next().await {
        let (i, app, filled) = joined.expect("fill task");
        assert!(
            filled.error.is_none(),
            "app {i}: the upload failed after {} B instead of blocking: {:?}",
            filled.bytes,
            filled.error
        );
        eprintln!(
            "app {i}: the tunnel took {} B before it blocked",
            filled.bytes
        );
        apps.push(app);
    }
    apps
}

/// Connects `n` applications that never read, to targets that flood, and waits until every
/// flood has blocked.
async fn fill_downloads(rig: &Rig, n: usize) -> Vec<TcpStream> {
    let mut apps = Vec::new();
    for _ in 0..n {
        apps.push(rig.connect_app(Some(APP_RCVBUF)).await);
    }
    let sent = rig
        .target
        .flooded(n, FILL_QUIET, FILL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    eprintln!("targets: {n} floods blocked after {sent} B in all");
    apps
}

/// Logs what each application sees now: data, EOF, a reset, or nothing yet.
async fn report_apps(apps: &mut [TcpStream]) {
    for (i, app) in apps.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        let seen = match tokio::time::timeout(Duration::from_millis(200), app.read(&mut buf)).await
        {
            Ok(Ok(0)) => "EOF".to_string(),
            Ok(Ok(_)) => "data".to_string(),
            Ok(Err(e)) => format!("error: {e}"),
            Err(_) => "nothing yet".to_string(),
        };
        eprintln!("app {i} reads: {seen}");
    }
}

/// Logs the state of both processes, e.g. right before the triggering event.
async fn observe_both(rig: &Rig, note: &str) {
    rig.observe(Role::Client, note).await;
    rig.observe(Role::Server, note).await;
}

/// Fails if a Rust process that should still run has exited or panicked.
fn expect_alive(rig: &mut Rig, roles: &[Role]) {
    for &role in roles {
        if rig.watched(role).which == kcptun_interop_tests::Impl::Rust {
            rig.expect_alive(role);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Case bodies
// ---------------------------------------------------------------------------------------

/// Case 1: the target reads [`CUT_AFTER`] bytes and ends the connection with `end` while the
/// application keeps sending.
///
/// The v0.2.1 client half-closed its local socket when the stream's FIN came and then waited
/// forever for credit the server would never grant, leaving the socket in `FIN-WAIT-2` with
/// everything the application sent after it unread. Now the server's pipe ends at once (the
/// target's end fails both of its directions) or at most after its grace; its FIN reaches the
/// client, whose pipe ends after the client's grace and closes the local socket.
async fn target_ends_while_the_app_sends(spec: RigSpec, end: End) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Cut {
        after: CUT_AFTER,
        end,
    });
    let app = rig.connect_app(None).await;
    let mut sender = keep_sending(app);
    let cut = rig
        .target
        .cut(FILL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let server = Window::new(
        "the target's end fails both server directions at once (at most the server's grace)",
        Duration::ZERO,
        g.server() + SLACK,
    );
    let client = Window::new(
        "the server's teardown sends the stream's FIN, then the client's grace",
        g.client(),
        g.server() + g.client() + SLACK,
    );
    tokio::join!(
        rig.expect_back(Role::Client, cut, &client, false),
        rig.expect_back(Role::Server, cut, &server, false),
    );

    match tokio::time::timeout(Duration::from_secs(5), &mut sender).await {
        Ok(Ok(sent)) => eprintln!(
            "app: wrote {} B, then {} {:.2} s after the cut",
            sent.bytes,
            sent.error,
            sent.at.saturating_duration_since(cut).as_secs_f64()
        ),
        Ok(Err(e)) => panic!("sender task: {e}"),
        Err(_) => eprintln!("app: still blocked writing: the client never closed its socket"),
    }
    sender.abort();
    rig.report();
    expect_alive(&mut rig, &[Role::Client, Role::Server]);
}

/// Case 2: the target never reads, the application writes until the tunnel is full, then
/// resets its connection.
///
/// The client's direction from the local socket is parked on window credit, so it does not read
/// the socket and would never see the RST; its probe does, within one watch period, and the
/// client's grace follows. The server's direction into the target is parked on a reader that
/// will never read again; once the client's FIN has arrived, the stall rule ends it
/// `max(-closewait, 30 s)` after the last byte moved.
async fn app_resets_into_a_stalled_target(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Stall);
    let mut apps = fill_uploads(&rig, 1).await;
    observe_both(&rig, "full, before the reset").await;
    let app = apps.pop().expect("one app");
    let reset_at = reset(app).unwrap_or_else(|e| panic!("reset: {e}"));

    let client = Window::new(
        "the client's probe sees the reset within one watch period, then the client's grace",
        g.client(),
        g.client() + WATCH + SLACK,
    );
    let stall = socket_stall(g.server());
    let server = Window::new(
        "stall rule: the client's FIN has arrived and nothing has moved for \
         max(server closewait, 30 s)",
        stall.saturating_sub(FILL_QUIET + FILL_LAG),
        (g.client() + WATCH).max(PERSIST_PROBE + stall) + WATCH + SLACK,
    );
    tokio::join!(
        rig.expect_back(Role::Client, reset_at, &client, false),
        rig.expect_back(Role::Server, reset_at, &server, false),
    );
    rig.expect_logged(Role::Client, &["pipe:", "reset"]);
    rig.expect_logged(Role::Server, &["pipe:", "i/o timeout"]);
    rig.report();
    expect_alive(&mut rig, &[Role::Client, Role::Server]);
}

/// Case 3: [`STREAMS`] uploads blocked on stalled targets, then the server is killed.
///
/// Nothing reaches the client any more, not even an RST: it notices through the smux keepalive
/// (the session closes on the first 30 s tick that finds no frame since the previous one), and
/// then every read and write on the session's streams fails, which ends both directions of every
/// pipe at once. Every local socket of the session must be closed then. The client may end with
/// fewer descriptors than its baseline: the dead session's UDP socket may go with it.
///
/// It does not go yet: the client lets go of a dead session's pool slot, and with it the
/// session's UDP socket, on the next accepted connection. So the case goes on: a restarted
/// server, one round trip, and the client must be back to exactly its baseline, the old
/// session's socket gone and the new session's in its place.
async fn server_killed_while_streams_are_blocked(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Stall);
    let mut apps = fill_uploads(&rig, STREAMS).await;
    observe_both(&rig, "full, before the kill").await;
    let killed = rig.kill(Role::Server);

    let client = Window::new(
        "smux keepalive: the session dies 20-60 s after the server (whose last ping was at most \
         10 s before the kill), then both directions of every pipe fail at once",
        KEEPALIVE_TIMEOUT - KEEPALIVE_INTERVAL,
        2 * KEEPALIVE_TIMEOUT + g.client() + SLACK,
    );
    rig.expect_back(Role::Client, killed, &client, true).await;
    report_apps(&mut apps).await;
    drop(apps);

    // The next connection replaces the dead session.
    rig.tunnel
        .start_server()
        .await
        .unwrap_or_else(|e| panic!("restart the server: {e}"));
    rig.target
        .set_behaviour(Behaviour::EchoOnce { len: RECOVERY_ECHO });
    let mut app = rig.connect_app(None).await;
    let payload = vec![0x24u8; RECOVERY_ECHO];
    app.write_all(&payload)
        .await
        .unwrap_or_else(|e| panic!("round trip after the restart: write: {e}"));
    let mut echo = vec![0u8; RECOVERY_ECHO];
    app.read_exact(&mut echo)
        .await
        .unwrap_or_else(|e| panic!("round trip after the restart: read: {e}"));
    assert_eq!(echo, payload, "round trip after the restart");
    drop(app);
    let done = Instant::now();
    let recovered = Window::new(
        "the accept dropped the dead session's pool slot, then the round trip's own pipe ended \
         (both of its ends closed: the shorter grace)",
        Duration::ZERO,
        g.client().max(g.server()) + SLACK,
    );
    rig.expect_back(Role::Client, done, &recovered, false).await;
    rig.report();
    expect_alive(&mut rig, &[Role::Client]);
}

/// Case 4.1, the mirror of 1: the application reads part of a download and closes while the
/// target keeps sending.
///
/// The v0.2.1 server half-closed the target socket on the stream's FIN and then waited forever
/// for credit the client would never grant: `FIN-WAIT-2` with the target's data unread. Now the
/// client's pipe ends at once (the application's close fails both of its directions), its FIN
/// reaches the server, and the server's pipe ends after the server's grace.
async fn app_closes_while_the_target_sends(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Flood);
    let app = rig.connect_app(None).await;
    let closed = read_then_close(app, READ_BEFORE_CLOSE)
        .await
        .unwrap_or_else(|e| panic!("download: {e}"));

    let client = Window::new(
        "the application's close fails both client directions at once (at most the client's \
         grace)",
        Duration::ZERO,
        g.client() + SLACK,
    );
    let server = Window::new(
        "the client's teardown sends the stream's FIN, then the server's grace",
        g.server(),
        g.client() + g.server() + SLACK,
    );
    tokio::join!(
        rig.expect_back(Role::Client, closed, &client, false),
        rig.expect_back(Role::Server, closed, &server, false),
    );
    rig.report();
    expect_alive(&mut rig, &[Role::Client, Role::Server]);
}

/// Case 4.2, the mirror of 2: the application never reads, the target floods until the tunnel
/// is full, then resets.
///
/// The server's direction from the target is parked on credit; its probe sees the RST within
/// one watch period, and the server's grace follows. The client's direction into the
/// application is parked on a reader that never reads; once the server's FIN has arrived, the
/// stall rule ends it `max(-closewait, 30 s)` after the last byte moved.
async fn target_resets_into_a_stalled_app(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Flood);
    let apps = fill_downloads(&rig, 1).await;
    observe_both(&rig, "full, before the reset").await;
    let reset_at = rig.target.end_all(End::Reset);

    let server = Window::new(
        "the server's probe sees the target's reset within one watch period, then the server's \
         grace",
        g.server(),
        g.server() + WATCH + SLACK,
    );
    let stall = socket_stall(g.client());
    let client = Window::new(
        "stall rule: the server's FIN has arrived and nothing has moved for \
         max(client closewait, 30 s)",
        stall.saturating_sub(FILL_QUIET + FILL_LAG),
        (g.server() + WATCH).max(PERSIST_PROBE + stall) + WATCH + SLACK,
    );
    tokio::join!(
        rig.expect_back(Role::Client, reset_at, &client, false),
        rig.expect_back(Role::Server, reset_at, &server, false),
    );
    rig.expect_logged(Role::Server, &["pipe:", "reset"]);
    rig.expect_logged(Role::Client, &["pipe:", "i/o timeout"]);
    drop(apps);
    rig.report();
    expect_alive(&mut rig, &[Role::Client, Role::Server]);
}

/// Case 4.3, the mirror of 3: [`STREAMS`] downloads blocked on applications that never read,
/// then the client is killed. The server notices through the smux keepalive and must close every
/// target socket of the session.
async fn client_killed_while_streams_are_blocked(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Flood);
    let apps = fill_downloads(&rig, STREAMS).await;
    observe_both(&rig, "full, before the kill").await;
    let killed = rig.kill(Role::Client);

    let server = Window::new(
        "smux keepalive: the session dies 20-60 s after the client (whose last ping was at most \
         10 s before the kill), then both directions of every pipe fail at once",
        KEEPALIVE_TIMEOUT - KEEPALIVE_INTERVAL,
        2 * KEEPALIVE_TIMEOUT + g.server() + SLACK,
    );
    rig.expect_back(Role::Server, killed, &server, false).await;
    drop(apps);
    rig.report();
    expect_alive(&mut rig, &[Role::Server]);
}

/// `-smuxbuf == -streambuf` (production runs 16 MiB for both), `-conn 1`: [`STREAMS`] downloads
/// on applications that never read spend the client session's whole receive buffer, after which
/// its session reads no frame of any stream: no data, no `cmdUPD`, no `cmdFIN`, no keepalive.
/// Then the targets reset.
///
/// The server's pipes see the RSTs and end after the server's grace. The FINs they send cannot be
/// read by the client, so nothing but the starvation rule ends the client's pipes: a parked
/// direction whose stream starves its session, with nothing moved for `max(-closewait, 30 s)`.
/// Cutting the starving stream returns its tokens, the session reads again, and a stream that
/// was not starving itself then gets its FIN and follows.
async fn starved_session_frees_its_stalled_streams(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Flood);
    let apps = fill_downloads(&rig, STREAMS).await;
    observe_both(&rig, "starved, before the reset").await;
    let reset_at = rig.target.end_all(End::Reset);

    let server = Window::new(
        "the server's probes see the targets' resets within one watch period, then the server's \
         grace",
        g.server(),
        g.server() + WATCH + SLACK,
    );
    let stall = socket_stall(g.client());
    // Whether the second stream goes with the first depends on how the two floods happened to
    // share the session buffer. A stream holding a quarter of it counts as starving, so with an
    // even share both are cut together, one stall after the reset. With an uneven one the smaller
    // stream is not to blame and is left alone: it hears its FIN only once the first stream's
    // tokens are back, and the stall clock starts at that signal (v0.2.3), so it goes one stall
    // later.
    let client = Window::new(
        "starvation rule: no FIN can be read, the starving stream is cut once nothing has moved \
         for max(client closewait, 30 s); the other stream goes with it if it holds a quarter of \
         the session buffer, otherwise one stall after its FIN becomes readable",
        stall.saturating_sub(FILL_QUIET + FILL_LAG),
        2 * (PERSIST_PROBE + stall + 2 * WATCH) + g.client() + SLACK,
    );
    tokio::join!(
        rig.expect_back(Role::Client, reset_at, &client, false),
        rig.expect_back(Role::Server, reset_at, &server, false),
    );
    rig.expect_logged(Role::Client, &["pipe:", "i/o timeout"]);
    drop(apps);
    rig.report();
    expect_alive(&mut rig, &[Role::Client, Role::Server]);
}

/// Case 2 with the Go client, the documented expectation rather than a teardown (module docs).
///
/// The Go client's direction from the local socket is parked in smux's `writeV2`, waiting for
/// credit, and nothing in Go 2026 wakes it for a reset of the socket it no longer reads. So the
/// Go client never ends the stream, and the Rust server, whose stream neither ended nor starves
/// its session, rightly keeps its pipe to the stalled target: once a Rust client would have been
/// back to its baseline, the Rust server still holds exactly that one connection, established,
/// with nothing half-closed and nothing dead.
async fn go_client_misses_the_reset(spec: RigSpec) {
    let g = spec.graces;
    let mut rig = Rig::start(spec).await;
    rig.target.set_behaviour(Behaviour::Stall);
    let mut apps = fill_uploads(&rig, 1).await;
    observe_both(&rig, "full, before the reset").await;
    let app = apps.pop().expect("one app");
    let reset_at = reset(app).unwrap_or_else(|e| panic!("reset: {e}"));

    // Past the point where a Rust client is back to its baseline in case 2.
    tokio::time::sleep_until((reset_at + g.client() + WATCH + SLACK).into()).await;
    let client = rig
        .observe(
            Role::Client,
            "not asserted: a Go client keeps the reset socket and the stream",
        )
        .await;
    if let Some(client) = client {
        eprintln!(
            "go client: {} dead socket(s) held, {} connection(s)",
            client.dead.len(),
            client.connections()
        );
    }
    let server = rig
        .observe(Role::Server, "expected: still piping to the stalled target")
        .await
        .expect("a sample of the Rust server");
    let base = &rig.watched(Role::Server).base;
    assert_eq!(
        server.fds(),
        base.fds() + 1,
        "the Rust server holds its baseline plus the one target connection: {}",
        server.summary()
    );
    assert_eq!(server.connections(), 1, "{}", server.summary());
    assert_eq!(
        server.in_state(TcpState::Established),
        1,
        "the target connection is live, not half-closed: {}",
        server.summary()
    );
    assert!(server.dead.is_empty(), "{}", server.summary());
    rig.report();
    expect_alive(&mut rig, &[Role::Server]);
}

// ---------------------------------------------------------------------------------------
// Rust <-> Rust
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_1_target_closes_while_the_app_sends() {
    case(
        Duration::from_secs(120),
        target_ends_while_the_app_sends(RigSpec::new(Pairing::RUST), End::Close),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_1_target_resets_while_the_app_sends() {
    case(
        Duration::from_secs(120),
        target_ends_while_the_app_sends(RigSpec::new(Pairing::RUST), End::Reset),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~40 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_2_app_resets_into_a_stalled_target() {
    case(
        Duration::from_secs(180),
        app_resets_into_a_stalled_target(RigSpec::new(Pairing::RUST)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~70 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_3_server_killed_while_streams_are_blocked() {
    case(
        Duration::from_secs(240),
        server_killed_while_streams_are_blocked(RigSpec::new(Pairing::RUST)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_4_1_app_closes_while_the_target_sends() {
    case(
        Duration::from_secs(120),
        app_closes_while_the_target_sends(RigSpec::new(Pairing::RUST)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~40 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_4_2_target_resets_into_a_stalled_app() {
    case(
        Duration::from_secs(180),
        target_resets_into_a_stalled_app(RigSpec::new(Pairing::RUST)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~70 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_4_3_client_killed_while_streams_are_blocked() {
    case(
        Duration::from_secs(240),
        client_killed_while_streams_are_blocked(RigSpec::new(Pairing::RUST)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~40 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_starved_session_frees_its_stalled_streams() {
    case(
        Duration::from_secs(180),
        starved_session_frees_its_stalled_streams(
            RigSpec::new(Pairing::RUST).buffers(Buffers::STARVING),
        ),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_1_at_the_default_closewait() {
    case(
        Duration::from_secs(150),
        target_ends_while_the_app_sends(
            RigSpec::new(Pairing::RUST).graces(Graces::DEFAULTS),
            End::Close,
        ),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~35 s); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_teardown_4_1_at_the_default_closewait() {
    case(
        Duration::from_secs(150),
        app_closes_while_the_target_sends(RigSpec::new(Pairing::RUST).graces(Graces::DEFAULTS)),
    )
    .await;
}

// ---------------------------------------------------------------------------------------
// Rust <-> Go
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_1_rust_client_go_server() {
    case(
        Duration::from_secs(120),
        target_ends_while_the_app_sends(RigSpec::new(Pairing::RUST_CLIENT_GO_SERVER), End::Close),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~40 s); needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_2_rust_client_go_server() {
    case(
        Duration::from_secs(180),
        app_resets_into_a_stalled_target(RigSpec::new(Pairing::RUST_CLIENT_GO_SERVER)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~70 s); needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_3_rust_client_go_server() {
    case(
        Duration::from_secs(240),
        server_killed_while_streams_are_blocked(RigSpec::new(Pairing::RUST_CLIENT_GO_SERVER)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_1_go_client_rust_server() {
    case(
        Duration::from_secs(120),
        target_ends_while_the_app_sends(RigSpec::new(Pairing::GO_CLIENT_RUST_SERVER), End::Close),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_2_go_client_rust_server() {
    case(
        Duration::from_secs(120),
        go_client_misses_the_reset(RigSpec::new(Pairing::GO_CLIENT_RUST_SERVER)),
    )
    .await;
}

/// Case 3 kills the server, which here is the Rust side, so it runs mirrored: the Go client is
/// killed and the Rust server must let go of every target socket of the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~70 s); needs the Rust binaries and the Go reference binaries (KCPTUN_GO_BIN_DIR)"]
async fn interop_teardown_3_go_client_rust_server() {
    case(
        Duration::from_secs(240),
        client_killed_while_streams_are_blocked(RigSpec::new(Pairing::GO_CLIENT_RUST_SERVER)),
    )
    .await;
}
