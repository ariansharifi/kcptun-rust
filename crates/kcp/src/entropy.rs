//! Random packet nonces (port of kcp-go `entropy.go`).
//!
//! Go fills every packet nonce from one global AES-based (or ChaCha8) generator behind a mutex,
//! reseeded from `crypto/rand` every 2^24 reads. Here every thread has its own CSPRNG
//! (`rand::rng()`: ChaCha12 seeded from the OS and reseeded periodically), so concurrent senders
//! never contend on a lock (DECISIONS D14). The nonce only has to be unpredictable; its value is
//! not otherwise interpreted by the peer.
#![forbid(unsafe_code)]

use rand::Rng;

/// Fills `nonce` with random bytes from the calling thread's CSPRNG. Used for the 16-byte
/// block-cipher packet nonce and the 12-byte AEAD nonce. An empty slice is a no-op.
// Go: kcp-go/v5@v5.6.66 entropy.go:fillRand() (global rngAES / rngChacha8 behind a mutex)
// Deviation D14: per-thread CSPRNG instead of a global mutex-protected generator.
#[inline]
pub fn fill_nonce(nonce: &mut [u8]) {
    if nonce.is_empty() {
        return;
    }
    rand::rng().fill_bytes(nonce);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn fill_nonce_empty_is_noop() {
        let mut empty: [u8; 0] = [];
        fill_nonce(&mut empty);
    }

    /// Works for the AEAD (12) and block-cipher (16) nonce sizes, and any other length: every
    /// byte is written (a zero buffer does not stay zero) and consecutive nonces differ.
    #[test]
    fn fill_nonce_sizes_nonzero_and_distinct() {
        for len in [1usize, 8, 12, 16, 32, 1500] {
            let mut seen = HashSet::new();
            for _ in 0..64 {
                let mut buf = vec![0u8; len];
                fill_nonce(&mut buf);
                seen.insert(buf);
            }
            // Short nonces can collide by chance (1 byte: 64 draws from 256 values); from 8
            // bytes on a collision in 64 draws has probability < 2^-51.
            let min_distinct = if len >= 8 { 64 } else { 16 };
            assert!(
                seen.len() >= min_distinct,
                "len {len}: {} distinct",
                seen.len()
            );
            if len >= 8 {
                assert!(seen.iter().all(|n| n.iter().any(|&b| b != 0)), "len {len}");
            }
        }
    }

    #[test]
    fn fill_nonce_differs_between_calls() {
        let (mut a, mut b) = ([0u8; 12], [0u8; 12]);
        fill_nonce(&mut a);
        fill_nonce(&mut b);
        assert_ne!(a, b);
        let (mut c, mut d) = ([0u8; 16], [0u8; 16]);
        fill_nonce(&mut c);
        fill_nonce(&mut d);
        assert_ne!(c, d);
    }

    /// Every byte position takes many values (no stuck bytes, e.g. a copy that only covers part
    /// of the buffer as Go's rngAES.Read does for reads over 16 bytes).
    #[test]
    fn fill_nonce_covers_every_byte() {
        let mut values = vec![HashSet::new(); 40];
        for _ in 0..256 {
            let mut buf = [0u8; 40];
            fill_nonce(&mut buf);
            for (set, b) in values.iter_mut().zip(buf) {
                set.insert(b);
            }
        }
        // 256 uniform draws over 256 values give ~162 distinct values on average.
        for (i, set) in values.iter().enumerate() {
            assert!(set.len() > 64, "byte {i}: {} distinct values", set.len());
        }
    }

    /// Threads have independent generators, and all of them produce distinct nonces.
    #[test]
    fn fill_nonce_per_thread() {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..100)
                        .map(|_| {
                            let mut n = [0u8; 16];
                            fill_nonce(&mut n);
                            n
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all = HashSet::new();
        for h in handles {
            for n in h.join().expect("thread") {
                all.insert(n);
            }
        }
        assert_eq!(all.len(), 400);
    }
}
