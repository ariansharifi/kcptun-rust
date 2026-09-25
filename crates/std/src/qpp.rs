//! kcptun's Quantum Permutation Pad port: parameter validation and the stream wrapper that
//! obfuscates one smux stream (plan step 07.3, `docs/WIRE-FORMAT.md` §9).
//!
//! Go: `kcptun/std/qpp.go` — `ValidateQPPParams()` and `QPPPort`. The call sites are
//! `client/main.go:536` and `server/main.go:526`, both `std.NewQPPPort(p, _Q_, []byte(config.Key))`:
//! the pad and the two PRNG seeds come from the **raw `-key` string**, never from the PBKDF2
//! `pass` the KCP layer derives (see the pitfalls in step 07).
//!
//! ```text
//! client                                  server
//!   TCP  <-> pipe <-> QppStream <-> smux stream <-> QppStream <-> pipe <-> TCP
//!                     ^ fresh wprng/rprng per stream, both seeded with the raw key
//! ```
//!
//! Every stream gets its own pair of [`Rand`]s, so the byte at stream position `p` is masked
//! with the same pad on both ends regardless of how the network chops the data up. That is why
//! this wrapper can sit on an async socket at all: encryption depends on the position in the
//! stream, not on the size of a read or a write.
//!
//! Two things differ from Go and are deliberate:
//!
//! 1. **Deviation V04** — Go's `QPPPort` has no `CloseWrite`, so `std.Pipe`'s type assertion
//!    fails and it falls back to a full `Close`, which can truncate the reverse direction.
//!    [`QppStream`] forwards the half-close ([`HalfCloseWrite::poll_close_write`]).
//! 2. Go encrypts **in the caller's buffer** (`r.pad.EncryptWithPRNG(p, r.wprng)` mutates `p`
//!    before handing it to the connection). A Rust `poll_write` gets `&[u8]`, so the ciphertext
//!    is built in an owned scratch buffer; see [`QppStream::poll_write`] for what that means for
//!    short writes.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use kcptun_qpp::{qpp_minimum_pads, qpp_minimum_seed_length};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::pipe::HalfCloseWrite;

/// Re-exported so that callers building the process-wide pad (`qpp.NewQPP([]byte(config.Key),
/// uint16(config.QPPCount))` in Go's `main`) and the per-stream generators need no direct
/// dependency on the GPL-3.0 crate.
pub use kcptun_qpp::{QuantumPermutationPad, Rand, create_prng};

// Go: kcptun/std/qpp.go:qppPower
/// The permutation dimension kcptun uses everywhere: 8 qubits, i.e. permutations of 256 bytes.
pub const QPP_POWER: u8 = 8;

/// Checks the `-QPPCount` / `-key` pair, returning Go's warnings or its one fatal error.
///
/// The error is returned when `count <= 0`; kcptun then `log.Fatal`s. The warnings are printed
/// in red and the process keeps running, so the `Ok` case can carry an empty vector or up to
/// three lines, in Go's order: key size, pad count, pad count not coprime with 8.
///
/// `count` is [`i64`] because [`BaseConfig::qpp_count`](crate::config::BaseConfig::qpp_count)
/// is (Go's `int`).
///
/// ```
/// # use kcptun_std::qpp::validate_qpp_params;
/// assert_eq!(validate_qpp_params(0, "k"), Err("QPPCount must be greater than 0 when QPP is enabled".to_string()));
/// assert!(validate_qpp_params(61, &"x".repeat(211)).expect("valid").is_empty());
/// ```
// Go: kcptun/std/qpp.go:ValidateQPPParams()
pub fn validate_qpp_params(count: i64, key: &str) -> Result<Vec<String>, String> {
    if count <= 0 {
        return Err("QPPCount must be greater than 0 when QPP is enabled".to_string());
    }

    let mut warnings = Vec::new();

    // Go: qpp.QPPMinimumSeedLength(qppPower) — 211 bytes for 8 qubits.
    let min_seed_length = qpp_minimum_seed_length(QPP_POWER);
    if key.len() < min_seed_length {
        warnings.push(format!(
            "QPP Warning: 'key' has size of {} bytes, required {} bytes at least",
            key.len(),
            min_seed_length
        ));
    }

    // Go: qpp.QPPMinimumPads(qppPower) — 7 pads for 8 qubits.
    let min_pads = qpp_minimum_pads(QPP_POWER);
    if count < min_pads as i64 {
        warnings.push(format!(
            "QPP Warning: QPPCount {count}, required {min_pads} at least"
        ));
    }

    // Go: new(big.Int).GCD(nil, nil, big.NewInt(int64(count)), big.NewInt(qppPower)).Int64() != 1.
    // `qppPower` is 8, so the greatest common divisor is 1 exactly for odd counts; `count > 0`
    // here, which is what `big.Int.GCD` requires of both arguments.
    if gcd(count as u64, u64::from(QPP_POWER)) != 1 {
        warnings.push(format!(
            "QPP Warning: QPPCount {count}, choose a prime number for security"
        ));
    }

    Ok(warnings)
}

/// Euclid's GCD of two positive integers, standing in for Go's `big.Int.GCD` on values that always
/// fit in 64 bits (`count > 0` and the constant 8).
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// A smux stream (or any byte stream) with Quantum Permutation Pad obfuscation on both
/// directions.
///
/// Go: `kcptun/std/qpp.go:QPPPort`. The pad is shared by every stream of the process
/// (`qpp.NewQPP([]byte(config.Key), uint16(config.QPPCount))`, built once in `main`), hence the
/// [`Arc`]; the two [`Rand`]s are per stream and per direction, created by
/// [`create_prng`] from the same raw key on both peers.
///
/// # Buffering
///
/// Unlike Go, which encrypts the caller's slice in place, this wrapper owns the ciphertext it
/// produces, so the encryption of a slice and its delivery are two steps. The contract is the one
/// [`SmuxStream`](crate::smuxio::SmuxStream) already documents: after
/// [`poll_write`](AsyncWrite::poll_write) returns `Pending`, the caller must retry with the same
/// slice — the bytes were encrypted into the wrapper's scratch buffer, and the retry finishes
/// delivering that ciphertext instead of encrypting anything new. `write_all`, and therefore
/// [`pipe`](crate::pipe::pipe), do exactly that. A `Ready(Ok(n))` therefore means the connection
/// really took the `n` bytes' worth of ciphertext, never that it was merely queued here.
// Go: kcptun/std/qpp.go:QPPPort
pub struct QppStream<S> {
    // Go: QPPPort.underlying
    underlying: S,
    // Go: QPPPort.pad
    pad: Arc<QuantumPermutationPad>,
    // Go: QPPPort.wprng
    wprng: Rand,
    // Go: QPPPort.rprng
    rprng: Rand,
    /// Ciphertext produced by [`poll_write`](AsyncWrite::poll_write) that the connection has not
    /// taken yet. The PRNG has already advanced over it, so it must be written exactly once, in
    /// order, and may never be re-encrypted.
    obuf: Vec<u8>,
    /// How much of `obuf` has reached the connection.
    opos: usize,
    /// How many plaintext bytes of the caller's slice `obuf` holds the ciphertext for, i.e. what
    /// the in-flight [`poll_write`](AsyncWrite::poll_write) will report once `obuf` is drained.
    /// Non-zero only between a `Pending` write and the retry that completes it.
    staged: usize,
}

impl<S> QppStream<S> {
    /// Wraps `underlying`, seeding a fresh PRNG per direction from `seed` (kcptun passes the raw
    /// `-key`).
    // Go: kcptun/std/qpp.go:NewQPPPort()
    pub fn new(underlying: S, pad: Arc<QuantumPermutationPad>, seed: &[u8]) -> QppStream<S> {
        QppStream {
            underlying,
            pad,
            wprng: create_prng(seed),
            rprng: create_prng(seed),
            obuf: Vec::new(),
            opos: 0,
            staged: 0,
        }
    }

    /// The wrapped stream.
    pub fn inner(&self) -> &S {
        &self.underlying
    }

    /// The wrapped stream, mutably. Writing to it directly desynchronises the write PRNG.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.underlying
    }
}

impl<S: AsyncWrite + Unpin> QppStream<S> {
    /// Pushes what is left of `obuf` into the connection.
    ///
    /// `Ready(Ok(()))` means the buffer is empty; the ciphertext is written in order and never
    /// regenerated, because the write PRNG has already moved past it.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.opos < self.obuf.len() {
            let n = ready!(Pin::new(&mut self.underlying).poll_write(cx, &self.obuf[self.opos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
            self.opos += n;
        }
        self.obuf.clear();
        self.opos = 0;
        Poll::Ready(Ok(()))
    }
}

/// Go: `QPPPort.Read` — read from the connection, then decrypt the bytes that arrived.
///
/// Go decrypts `p[:n]`, so a short read decrypts only what was read and the read PRNG advances
/// by exactly that many stream positions; the same holds here because [`ReadBuf`] reports what
/// the inner reader filled.
impl<S: AsyncRead + Unpin> AsyncRead for QppStream<S> {
    // Go: kcptun/std/qpp.go:QPPPort.Read()
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let start = buf.filled().len();
        // Whatever arrived is decrypted before the poll result is looked at, exactly as Go
        // decrypts `p[:n]` before `return n, err`: an inner reader that filled part of the buffer
        // and then reported `Pending` or an error must not leave ciphertext behind, or the read
        // PRNG falls out of step with the peer's write PRNG by that many stream positions.
        // tokio's own contract forbids such a `Pending`, but `S` is any stream.
        let poll = Pin::new(&mut me.underlying).poll_read(cx, buf);
        let end = buf.filled().len();
        if end > start {
            me.pad
                .decrypt_with_prng(&mut buf.filled_mut()[start..end], &mut me.rprng);
        }
        poll
    }
}

/// Go: `QPPPort.Write` — encrypt, then write.
impl<S: AsyncWrite + Unpin> AsyncWrite for QppStream<S> {
    /// Encrypts `buf` and hands it to the connection.
    ///
    /// Go can return the connection's short count (`return r.underlying.Write(p)`) because it
    /// encrypted in place: the caller simply re-offers the unwritten tail, already ciphertext.
    /// This port cannot re-encrypt a tail — that would advance the write PRNG twice over the same
    /// stream positions — so the ciphertext for the whole slice is staged in `obuf` and this
    /// returns `Ready(Ok(buf.len()))` only once the connection has taken all of it.
    ///
    /// **`Pending` means nothing was consumed and the caller must retry with the same slice**
    /// (see the type's *Buffering* section): the retry resumes draining the staged ciphertext
    /// rather than encrypting again. Reporting bytes that are still in `obuf` would be a lie a
    /// copy loop cannot recover from — [`pipe`](crate::pipe::pipe) would go back to reading its
    /// source, and a source that has gone quiet leaves that ciphertext stranded for good.
    // Go: kcptun/std/qpp.go:QPPPort.Write()
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.staged == 0 {
            // A flush or half-close that stopped mid-drain can leave ciphertext here; nothing
            // new may be encrypted before it is out, and `Pending` costs the caller nothing
            // because its bytes have not been touched yet.
            ready!(me.poll_drain(cx))?;
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            me.obuf.clear();
            me.obuf.extend_from_slice(buf);
            me.pad.encrypt_with_prng(&mut me.obuf, &mut me.wprng);
            me.opos = 0;
            me.staged = buf.len();
        }

        // An error is reported here and now, as Go's `return r.underlying.Write(p)` does, and
        // ends the stream; `staged` stays set, so a caller that writes again hits the same error
        // instead of encrypting over the top of the failed slice.
        ready!(me.poll_drain(cx))?;
        let n = me.staged;
        me.staged = 0;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.underlying).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // A shutdown must not strand ciphertext, but it must also not fail to shut down: the
        // drain error is reported after the connection has been told to finish.
        let drained = match me.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r,
        };
        ready!(Pin::new(&mut me.underlying).poll_shutdown(cx))?;
        Poll::Ready(drained)
    }
}

/// Deviation V04: the half-close is **forwarded**, where Go's `QPPPort` does not implement
/// `closeWriter` at all, so `std.Pipe`'s `if cw, ok := dst.(closeWriter); ok` fails and the
/// fallback `dst.Close()` tears the whole stream down — which can truncate the direction that is
/// still running. Forwarding sends only the smux `cmdFIN`, a frame every Go peer already handles
/// for non-QPP streams, so this is wire-compatible and strictly less lossy.
impl<S: HalfCloseWrite + Unpin> HalfCloseWrite for QppStream<S> {
    // Deviation V04: forward close_write through QPP (Go falls back to Close).
    // Go: kcptun/std/copy.go:closeWriter.CloseWrite() (not implemented by QPPPort)
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Everything written before the half-close has to be on the wire first, or forwarding
        // would lose exactly the data V04 exists to save.
        let drained = match me.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r,
        };
        ready!(Pin::new(&mut me.underlying).poll_close_write(cx))?;
        Poll::Ready(drained)
    }

    /// Go: `QPPPort.Close()` — closes the underlying stream and nothing else. Ciphertext that a
    /// failed write left in `obuf` is dropped here rather than retried, as Go's `Close` never
    /// writes.
    // Go: kcptun/std/qpp.go:QPPPort.Close()
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.underlying).poll_close(cx)
    }
}

#[cfg(test)]
#[path = "qpp_tests.rs"]
mod tests;
