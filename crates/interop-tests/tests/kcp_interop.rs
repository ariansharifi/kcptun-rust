//! Rust ↔ Go interoperability of the KCP session layer (Step 05.8).
//!
//! Every case runs the same echo in both directions against the real Go peer
//! (`tools/gointerop/cmd/kcpecho`, kcp-go v5.6.66 linked at the pinned version):
//!
//! | Test | Client | Server |
//! |---|---|---|
//! | `..._rust_client_go_server_*` | `kcptun_kcp::UdpSession` in this process | `kcpecho server` |
//! | `..._go_client_rust_server_*` | `kcpecho client` | `kcptun_kcp::Listener` in this process |
//!
//! The client sends the deterministic stream of testkit's `PrngStream` (Go's
//! `rand.NewPCG(seed, 0)`), the server echoes it, and the client verifies every byte and reports
//! the SHA-256 of what came back. Both sides compare against the *same* expected hash, so a
//! silent divergence in framing, FEC or crypto cannot pass.
//!
//! Coverage:
//!
//! - **crypt sweep**: all 15 `-crypt` methods at kcptun's defaults (FEC 10/3, MTU 1350, windows
//!   128/512, mode fast), both directions: 30 runs;
//! - **pairwise matrix**: FEC `{10/3, 0/0, 3/2}` × ack-nodelay `{off, on}` × MTU
//!   `{1350, 1400, 500}` × windows `{128/512, 1024/1024, 8192/8192}` × crypt
//!   `{aes, aes-128-gcm, salsa20}`, expanded with [`pairwise_indices`] so every pair of values of
//!   any two dimensions appears: 10 cases, both directions;
//! - **lossy relay**: `aes` + FEC 10/3 and `xor` without FEC, through a testkit
//!   [`Relay`](kcptun_testkit::relay::Relay) at 1 % and 5 % loss with reordering, both directions;
//!   FEC recovery and KCP retransmission are asserted through `DEFAULT_SNMP`.
//!
//! All of them are `#[ignore]` because they need the Go binaries of `tools/fetch-reference.sh`:
//!
//! ```sh
//! cargo test -p kcptun-interop-tests -- --ignored            # laptop
//! tools/lab/deploy.sh --go                                   # lab-arm64
//! tools/lab/remote-test.sh -p kcptun-interop-tests -- --ignored
//! ```
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_LOCK serialises whole test bodies, like kcptun-kcp's SNMP_TEST_LOCK"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use kcptun_interop_tests::go_bin;
use kcptun_interop_tests::kcpecho::{self, ClientRun, KcpEchoReport};
use kcptun_interop_tests::matrix::pairwise_indices;
use kcptun_interop_tests::{
    CRYPT_MODES, KcpCase, RustClientReport, RustClientRun, RustEchoServer, run_rust_client,
};
use kcptun_kcp::snmp::{DEFAULT_SNMP, SnmpSnapshot};
use kcptun_testkit::ports;
use kcptun_testkit::relay::{Relay, RelayConfig, RelayStats};
use kcptun_testkit::servers::PrngStream;

/// Bytes echoed per case on a clean path: enough for many KCP windows, several hundred FEC
/// groups and a few thousand datagrams, still well under a second on loopback.
const BYTES: u64 = 2 * 1024 * 1024;

/// Bytes echoed per case through the lossy relay (retransmission makes these runs much slower).
const LOSSY_BYTES: u64 = 1024 * 1024;

/// Deadline of one clean run, on both peers.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Deadline of one lossy run.
const LOSSY_TIMEOUT: Duration = Duration::from_secs(180);

/// How long a Rust echo server waits on an idle session before reaping it (`kcpecho`'s `-idle`).
const IDLE: Duration = Duration::from_secs(60);

/// `DEFAULT_SNMP` is process-global: the tests that read counter deltas take this lock for
/// writing, every other test takes it for reading. Same convention as `kcptun-kcp`'s
/// `SNMP_TEST_LOCK`.
static SNMP_LOCK: RwLock<()> = RwLock::new(());

fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
    SNMP_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> std::sync::RwLockWriteGuard<'static, ()> {
    SNMP_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

fn kcpecho_bin() -> PathBuf {
    go_bin("kcpecho").unwrap_or_else(|e| panic!("{e}"))
}

/// What one direction of one case produced.
struct Outcome {
    /// `true` if every byte came back unchanged.
    ok: bool,
    /// SHA-256 of what the client received.
    sha256: String,
    /// SHA-256 of what it sent.
    expected_sha256: String,
    /// Bytes verified.
    received: u64,
    /// Wall time of the run.
    duration_ms: u128,
    /// Whatever the failing side said.
    error: Option<String>,
    /// Extra context printed on failure (the Go log, or the Rust report).
    detail: String,
    /// Relay counters, when the run went through one.
    relay: Option<RelayStats>,
}

impl Outcome {
    #[track_caller]
    fn assert_ok(&self, what: &str, expected_bytes: u64) {
        assert!(
            self.ok,
            "[{what}] failed: {:?}\n{}",
            self.error, self.detail
        );
        assert_eq!(self.received, expected_bytes, "[{what}] bytes verified");
        assert_eq!(self.sha256, self.expected_sha256, "[{what}] echo hash");
        assert_eq!(self.error, None, "[{what}]");
    }
}

impl From<RustClientReport> for Outcome {
    fn from(r: RustClientReport) -> Outcome {
        Outcome {
            ok: r.ok,
            sha256: r.sha256.clone(),
            expected_sha256: r.expected_sha256.clone(),
            received: r.received,
            duration_ms: r.duration_ms,
            error: r.error.clone(),
            detail: format!("rust client report: {r:?}"),
            relay: None,
        }
    }
}

/// Turns the Go client's JSON report plus its exit status and log into an [`Outcome`].
fn go_outcome(
    exit_code: Option<i32>,
    report: Option<KcpEchoReport>,
    log: String,
    expected_sha256: String,
) -> Outcome {
    match report {
        Some(r) => Outcome {
            ok: r.ok && exit_code == Some(0) && r.mismatch_offset == -1,
            sha256: r.sha256.clone(),
            expected_sha256: r.expected_sha256.clone(),
            received: r.received.max(0) as u64,
            duration_ms: r.duration_ms.max(0) as u128,
            error: r.error.clone(),
            detail: format!("go client exit {exit_code:?}, report {r:?}\nlog:\n{log}"),
            relay: None,
        },
        None => Outcome {
            ok: false,
            sha256: String::new(),
            expected_sha256,
            received: 0,
            duration_ms: 0,
            error: Some("the Go client printed no JSON report".into()),
            detail: format!("go client exit {exit_code:?}\nlog:\n{log}"),
            relay: None,
        },
    }
}

/// Starts the relay in front of `upstream` if `cfg` asks for one, and returns the address the
/// client should use.
async fn maybe_relay(
    upstream: SocketAddr,
    cfg: Option<RelayConfig>,
) -> (Option<Relay>, SocketAddr) {
    match cfg {
        None => (None, upstream),
        Some(cfg) => {
            let relay = Relay::start(upstream, cfg).await.expect("start the relay");
            let addr = relay.addr();
            (Some(relay), addr)
        }
    }
}

/// Rust `UdpSession` client → (relay) → Go `kcpecho server`.
async fn rust_client_go_server(
    case: &KcpCase,
    bytes: u64,
    seed: u64,
    timeout: Duration,
    relay_cfg: Option<RelayConfig>,
) -> Outcome {
    let bin = kcpecho_bin();
    let listen = ports::allocate(1).addr(0);
    let args = case.kcpecho_args();
    let (_server, printed) =
        tokio::task::spawn_blocking(move || kcpecho::start_server(&bin, listen, &args))
            .await
            .expect("the server task")
            .unwrap_or_else(|e| panic!("[{case}] kcpecho server: {e}"));
    assert_eq!(printed, listen.to_string(), "[{case}] server address");

    let (relay, remote) = maybe_relay(listen, relay_cfg).await;
    let run = RustClientRun::new(remote, bytes)
        .seed(seed)
        .timeout(timeout);
    let report = run_rust_client(&run, case).await;
    let mut outcome = Outcome::from(report);
    outcome.relay = relay.as_ref().map(Relay::stats);
    outcome
}

/// Go `kcpecho client` → (relay) → Rust `Listener`.
async fn go_client_rust_server(
    case: &KcpCase,
    bytes: u64,
    seed: u64,
    timeout: Duration,
    relay_cfg: Option<RelayConfig>,
) -> Outcome {
    let bin = kcpecho_bin();
    let listen = ports::allocate(1).addr(0);
    let server = RustEchoServer::start(listen, case, Some(IDLE))
        .unwrap_or_else(|e| panic!("[{case}] rust listener: {e}"));
    assert_eq!(server.addr(), listen, "[{case}] listener address");

    let (relay, remote) = maybe_relay(listen, relay_cfg).await;
    let args = case.kcpecho_args();
    let run = ClientRun::new(remote, bytes)
        .seed(seed)
        .timeout_secs(timeout.as_secs());
    let out = tokio::task::spawn_blocking(move || kcpecho::run_client(&bin, &run, &args))
        .await
        .expect("the client task")
        .unwrap_or_else(|e| panic!("[{case}] kcpecho client: {e}"));

    let mut outcome = go_outcome(
        out.exit_code,
        out.report,
        out.log,
        PrngStream::sha256_hex(seed, bytes),
    );
    outcome.relay = relay.as_ref().map(Relay::stats);
    server.close();
    outcome
}

/// Runs one case in both directions and checks the echo, with a distinct seed per direction so a
/// crossed-over hash cannot pass.
async fn both_directions(case: &KcpCase, seed: u64) {
    let expected = PrngStream::sha256_hex(seed, BYTES);

    let out = rust_client_go_server(case, BYTES, seed, TIMEOUT, None).await;
    out.assert_ok(&format!("rs->go {case}"), BYTES);
    assert_eq!(out.expected_sha256, expected, "[rs->go {case}] stream hash");
    let rs_ms = out.duration_ms;

    let seed = seed.wrapping_add(1_000_000);
    let expected = PrngStream::sha256_hex(seed, BYTES);
    let out = go_client_rust_server(case, BYTES, seed, TIMEOUT, None).await;
    out.assert_ok(&format!("go->rs {case}"), BYTES);
    assert_eq!(out.expected_sha256, expected, "[go->rs {case}] stream hash");

    eprintln!(
        "ok [{case}] rs->go {rs_ms} ms, go->rs {} ms",
        out.duration_ms
    );
}

// ---------------------------------------------------------------------------------------------
// Crypt sweep: every -crypt method at kcptun's defaults
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
async fn interop_kcp_crypt_modes_both_directions() {
    let _snmp = snmp_read();
    for (i, crypt) in CRYPT_MODES.iter().enumerate() {
        let case = KcpCase::new().crypt(*crypt);
        both_directions(&case, 3_000 + i as u64).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Pairwise matrix over FEC, ack-nodelay, MTU and windows
// ---------------------------------------------------------------------------------------------

/// FEC shard counts under test: kcptun's default, FEC off, and a small group.
const FECS: [(u32, u32); 3] = [(10, 3), (0, 0), (3, 2)];
/// `-acknodelay`.
const ACKNODELAY: [bool; 2] = [false, true];
/// `-mtu`: kcptun's default, the kcp-go test value, and one small enough to fragment everything.
const MTUS: [u32; 3] = [1350, 1400, 500];
/// `-sndwnd`/`-rcvwnd`: kcptun's client defaults, its server defaults, and a large pair.
const WINDOWS: [(u32, u32); 3] = [(128, 512), (1024, 1024), (8192, 8192)];
/// `-crypt` in the matrix: a CFB block cipher, the AEAD (whose `set_mtu` also subtracts
/// `aead.Overhead()`, so it is the one cipher whose MTU arithmetic differs) and a stream cipher.
// Go: kcp-go/v5@v5.6.66 sess.go:SetMtu()
const MATRIX_CRYPTS: [&str; 3] = ["aes", "aes-128-gcm", "salsa20"];

/// The five matrix dimensions, expanded pairwise: every pair of values of any two dimensions
/// appears in at least one case (3 × 2 × 3 × 3 × 3 = 162 combinations in [`MATRIX_CASES`] = 10
/// cases).
fn matrix_cases() -> Vec<KcpCase> {
    let levels = [
        FECS.len(),
        ACKNODELAY.len(),
        MTUS.len(),
        WINDOWS.len(),
        MATRIX_CRYPTS.len(),
    ];
    pairwise_indices(&levels)
        .into_iter()
        .map(|row| {
            let (ds, ps) = FECS[row[0]];
            let (sndwnd, rcvwnd) = WINDOWS[row[3]];
            KcpCase::new()
                .fec(ds, ps)
                .acknodelay(ACKNODELAY[row[1]])
                .mtu(MTUS[row[2]])
                .windows(sndwnd, rcvwnd)
                .crypt(MATRIX_CRYPTS[row[4]])
        })
        .collect()
}

/// How many cases [`matrix_cases`] expands to. Asserted, so a change to `pairwise_indices` or to
/// the dimensions above cannot silently shrink the suite.
const MATRIX_CASES: usize = 10;

/// Not `#[ignore]`: the expansion needs no Go binary, and the suite's size is worth guarding.
#[test]
fn the_matrix_expands_to_the_expected_cases() {
    let cases = matrix_cases();
    assert_eq!(cases.len(), MATRIX_CASES);
    // Pairwise means every value of every dimension appears at least once.
    for (ds, ps) in FECS {
        assert!(
            cases.iter().any(|c| (c.ds, c.ps) == (ds, ps)),
            "fec {ds}/{ps}"
        );
    }
    for mtu in MTUS {
        assert!(cases.iter().any(|c| c.mtu == mtu), "mtu {mtu}");
    }
    for (snd, rcv) in WINDOWS {
        assert!(
            cases.iter().any(|c| (c.sndwnd, c.rcvwnd) == (snd, rcv)),
            "windows {snd}/{rcv}"
        );
    }
    for crypt in MATRIX_CRYPTS {
        assert!(cases.iter().any(|c| c.crypt == crypt), "crypt {crypt}");
    }
    assert!(cases.iter().any(|c| c.acknodelay));
    assert!(cases.iter().any(|c| !c.acknodelay));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
async fn interop_kcp_matrix_both_directions() {
    let _snmp = snmp_read();
    let cases = matrix_cases();
    assert_eq!(cases.len(), MATRIX_CASES, "pairwise expansion");
    eprintln!("kcp interop matrix: {} cases x 2 directions", cases.len());
    for (i, case) in cases.iter().enumerate() {
        both_directions(case, 4_000 + i as u64).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Lossy relay: FEC recovery and retransmission against the real Go state machine
// ---------------------------------------------------------------------------------------------

/// A relay that drops `loss` of the datagrams in both directions and holds 2 % of them back by
/// 30 ms so they are overtaken.
fn lossy(seed: u64, loss: f64) -> RelayConfig {
    RelayConfig::new(seed).loss(loss).reorder(0.02, 30)
}

fn snapshot() -> SnmpSnapshot {
    DEFAULT_SNMP.copy()
}

/// A closed session's read loop, tx pipeline and updater can still be one iteration behind, and a
/// straggler that decodes one more FEC packet moves the process-global `DEFAULT_SNMP`. Landing
/// between a `before` and an `after` it would corrupt that window's deltas, exactly what
/// `kcptun_kcp::session::go_tests::SETTLE` documents. Waited before every `snapshot()` that opens
/// a window, so `assert_eq!(recovered, 0)` in the no-FEC cases cannot see the previous run's tail.
const SETTLE: Duration = Duration::from_millis(250);

/// Waits [`SETTLE`]; see there.
async fn settle() {
    tokio::time::sleep(SETTLE).await;
}

/// Retransmissions recorded between two snapshots. `RetransSegs` is already the total: kcp-go
/// adds `lostSegs + fastRetransSegs + earlyRetransSegs` to it in one go, so the three finer
/// counters must not be added on top.
// Go: kcp-go/v5@v5.6.66 kcp.go:953-971 (`flush`, "counter updates")
fn retransmits(before: &SnmpSnapshot, after: &SnmpSnapshot) -> u64 {
    after.retrans_segs - before.retrans_segs
}

#[track_caller]
fn assert_relay_dropped(out: &Outcome, what: &str) {
    let stats = out.relay.expect("the run went through a relay");
    assert!(
        stats.lost() > 0,
        "[{what}] the relay dropped nothing: {stats:?}"
    );
    assert!(
        stats.up.reordered + stats.down.reordered > 0,
        "[{what}] the relay reordered nothing: {stats:?}"
    );
}

/// Both directions of one case through a lossy relay, asserting the echo still arrives whole and
/// that the Rust side really had to repair the path.
async fn lossy_both_directions(case: &KcpCase, seed: u64, loss: f64) {
    let fec = case.ds > 0;
    let tag = format!("{case} loss={loss}");

    settle().await;
    let before = snapshot();
    let out = rust_client_go_server(
        case,
        LOSSY_BYTES,
        seed,
        LOSSY_TIMEOUT,
        Some(lossy(seed, loss)),
    )
    .await;
    out.assert_ok(&format!("rs->go {tag}"), LOSSY_BYTES);
    assert_relay_dropped(&out, &format!("rs->go {tag}"));
    let after = snapshot();
    let recovered = after.fec_recovered - before.fec_recovered;
    let retrans = retransmits(&before, &after);
    if fec {
        assert!(
            recovered > 0,
            "[rs->go {tag}] FEC recovered nothing; relay {:?}",
            out.relay
        );
    } else {
        assert_eq!(recovered, 0, "[rs->go {tag}] no FEC was configured");
        assert!(
            retrans > 0,
            "[rs->go {tag}] nothing was retransmitted; relay {:?}",
            out.relay
        );
    }
    eprintln!(
        "ok [rs->go {tag}] {} ms, FEC recovered {recovered}, retransmitted {retrans}, relay {:?}",
        out.duration_ms, out.relay
    );

    let seed = seed.wrapping_add(1_000_000);
    settle().await;
    let before = snapshot();
    let out = go_client_rust_server(
        case,
        LOSSY_BYTES,
        seed,
        LOSSY_TIMEOUT,
        Some(lossy(seed, loss)),
    )
    .await;
    out.assert_ok(&format!("go->rs {tag}"), LOSSY_BYTES);
    assert_relay_dropped(&out, &format!("go->rs {tag}"));
    let after = snapshot();
    let recovered = after.fec_recovered - before.fec_recovered;
    let retrans = retransmits(&before, &after);
    if fec {
        assert!(
            recovered > 0,
            "[go->rs {tag}] FEC recovered nothing; relay {:?}",
            out.relay
        );
    } else {
        assert_eq!(recovered, 0, "[go->rs {tag}] no FEC was configured");
        assert!(
            retrans > 0,
            "[go->rs {tag}] nothing was retransmitted; relay {:?}",
            out.relay
        );
    }
    eprintln!(
        "ok [go->rs {tag}] {} ms, FEC recovered {recovered}, retransmitted {retrans}, relay {:?}",
        out.duration_ms, out.relay
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs reference/bin (tools/fetch-reference.sh); minutes of lossy traffic"]
async fn interop_kcp_lossy_relay_both_directions() {
    // Reads `DEFAULT_SNMP` deltas, so no other Rust session may run at the same time. The
    // readers that just released the lock may still be retiring background tasks; see `SETTLE`.
    let _snmp = snmp_write();
    settle().await;
    let cases = [
        // FEC repairs the loss.
        KcpCase::new().crypt("aes").fec(10, 3),
        // No FEC: KCP's ARQ has to.
        KcpCase::new().crypt("xor").fec(0, 0),
    ];
    for (i, case) in cases.iter().enumerate() {
        for (j, loss) in [0.01, 0.05].into_iter().enumerate() {
            lossy_both_directions(case, 5_000 + (i * 10 + j) as u64, loss).await;
        }
    }
}
