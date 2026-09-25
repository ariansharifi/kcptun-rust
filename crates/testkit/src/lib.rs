//! Test utilities shared by the kcptun-rust crates. Not published; other crates use it as a
//! dev-dependency only.
//!
//! | Module | Purpose |
//! |---|---|
//! | [`vectors`](mod@vectors) | golden vectors from `tools/govectors` ([`vectors!`], [`assert_hex_eq!`]) |
//! | [`rng`] | this crate's own deterministic PRNGs (Go `math/rand/v2` PCG, SplitMix64) |
//! | [`clock`] | [`VirtualClock`], a shared manual millisecond clock |
//! | [`cpu`] | CPU time of this process and of its reaped children (`getrusage`) |
//! | [`netsim`] | [`Link`], an in-memory lossy datagram link on virtual time |
//! | [`relay`] | [`Relay`], a real-time lossy UDP relay in front of a live peer |
//! | [`servers`] | TCP echo / sink / source servers with SHA-256 checks |
//! | [`proc`] | spawning binaries with captured logs, kill on drop |
//! | [`ports`] | free consecutive port blocks in `[22000, 29000)` |
//!
//! This crate must not depend on any other kcptun crate (they dev-depend on it; a dependency
//! back would build a second copy of their types). See [`clock`] for how the virtual clock
//! plugs into `kcptun_kcp::Clock`.
//!
//! `unsafe` is denied, with one documented exception the crate root cannot `forbid`: the two
//! `getrusage(2)` calls in [`cpu`], which have no safe wrapper in `std`
//! (docs/porting-guide.md §5).
#![deny(unsafe_code)]

pub mod clock;
pub mod cpu;
pub mod netsim;
pub mod ports;
pub mod proc;
pub mod relay;
pub mod rng;
pub mod servers;
pub mod vectors;

pub use clock::VirtualClock;
pub use netsim::{Link, LinkConfig};
pub use relay::{Relay, RelayConfig};

/// Serialises socket creation with child-process spawning.
///
/// On macOS, std and tokio create sockets and only then mark them close-on-exec (there is no
/// atomic `SOCK_CLOEXEC`), and `Command::spawn` uses `posix_spawn`, which inherits every fd not
/// yet marked. A child spawned by one test thread can therefore inherit a socket another thread
/// is creating at that instant and keep its port busy for the child's lifetime. Holding this
/// lock around socket creation (port probes, server listeners) and around every spawn rules
/// that out. Linux creates sockets with `SOCK_CLOEXEC` atomically, so there the lock is merely
/// redundant.
static FD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes the process-wide lock that serialises socket creation with child spawning (see the
/// `FD_LOCK` notes in the source).
///
/// testkit takes it itself for its port probes, server listeners and [`proc`] spawns. Tests in
/// other crates that bind sockets on fixed ports (for example a Rust listener on a
/// [`ports::allocate`]d port) while other test threads spawn processes must bind under this
/// guard, and must spawn only through [`proc::ProcBuilder`] (never `Command::spawn`/`status`
/// directly), or a child may inherit the socket on macOS. Hold it only for the bind or spawn
/// itself, never across an `.await` or a wait. Poisoning is ignored: the lock protects no data.
pub fn socket_creation_guard() -> std::sync::MutexGuard<'static, ()> {
    FD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Crate-internal short name for [`socket_creation_guard`].
pub(crate) fn fd_lock() -> std::sync::MutexGuard<'static, ()> {
    socket_creation_guard()
}
