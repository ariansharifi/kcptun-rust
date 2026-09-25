//! Port of `qpp@v1.1.25 qpp.go`: pad generation and the byte transform.

use std::fmt;

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::bigint::BigUint;
use crate::prng::{Rand, create_prng, xoshiro256ss};

// Go: qpp@v1.1.25 qpp.go, the `const` block.
//
// `PAD_IDENTIFIER` is Go's format string `"QPP_%b"`: the pad id in **binary**, without leading
// zeros ("QPP_0", "QPP_1", "QPP_10", ...). Rust spells that `format!("QPP_{pad_id:b}")`, so the
// constant itself has no port.

/// HMAC message that derives the permutation-matrix selector of a stream.
pub const PM_SELECTOR_IDENTIFIER: &str = "PERMUTATION_MATRIX_SELECTOR";
/// PBKDF2 salt of the AES keys that drive the pad shuffle.
pub const SHUFFLE_SALT: &str = "___QUANTUM_PERMUTATION_PAD_SHUFFLE_SALT___";
/// PBKDF2 salt of the PRNG state.
pub const PRNG_SALT: &str = "___QUANTUM_PERMUTATION_PAD_PRNG_SALT___";
/// Bit length of a native byte.
pub const NATIVE_BYTE_LENGTH: u8 = 8;
/// PBKDF2 iterations of the seed expansion and the shuffle keys.
pub const PBKDF2_LOOPS: u32 = 128;
/// PBKDF2 salt of the seed chunks.
pub const CHUNK_DERIVE_SALT: &str = "___QUANTUM_PERMUTATION_PAD_SEED_DERIVE___";
/// PBKDF2 iterations of the seed chunks.
pub const CHUNK_DERIVE_LOOPS: u32 = 1024;
/// A new pad is selected every `PAD_SWITCH` bytes of stream position.
pub const PAD_SWITCH: u8 = 8;
/// Number of quantum bits of this implementation.
pub const QUBITS: u8 = 8;

/// AES block size, the stride of the shuffle's in-place ECB passes.
// Go: crypto/aes.BlockSize
const AES_BLOCK_SIZE: usize = 16;

/// Size of one permutation matrix, `1 << QUBITS`.
// Go: qpp@v1.1.25 qpp.go:NewQPP():matrixBytes
pub const MATRIX_BYTES: usize = 1 << QUBITS;

/// One permutation of the 256 byte values.
type Matrix = [u8; MATRIX_BYTES];

/// Encryption/decryption state: the permutation matrices derived from a seed, their inverses,
/// and the two default generators of [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt).
// Go: qpp@v1.1.25 qpp.go:QuantumPermutationPad
#[derive(Clone)]
pub struct QuantumPermutationPad {
    /// Encryption pads, one permutation matrix each.
    pads: Box<[Matrix]>,
    /// Decryption pads, the inverse permutations.
    rpads: Box<[Matrix]>,
    /// Number of pads; always ≥ 1 (see [`new`](Self::new)).
    num_pads: u16,
    /// Default random source for encryption pad selection.
    enc_rand: Rand,
    /// Default random source for decryption pad selection.
    dec_rand: Rand,
}

/// Prints the shape only: the pads are key-derived material and rendering them would both dump a
/// secret into the log and produce megabytes of text (`num_pads * 512` bytes as decimal lists).
/// Go's type has no `String()`/`Format()`, so nothing equivalent can happen there either.
impl fmt::Debug for QuantumPermutationPad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuantumPermutationPad")
            .field("num_pads", &self.num_pads)
            .finish_non_exhaustive()
    }
}

impl QuantumPermutationPad {
    /// Creates a pad set from `seed`, which is used both for the permutations and for the two
    /// default generators.
    ///
    /// # Panics
    ///
    /// If `num_pads` is 0. Go builds the object and then divides by zero on the first
    /// `Encrypt`; kcptun rejects `QPPCount <= 0` before it gets that far
    /// (`QPPCount must be greater than 0 when QPP is enabled`), so failing here names the
    /// problem instead of crashing later.
    // Go: qpp@v1.1.25 qpp.go:NewQPP()
    pub fn new(seed: &[u8], num_pads: u16) -> Self {
        assert!(num_pads > 0, "NewQPP: numPads must be greater than 0");

        let chunks = seed_to_chunks(seed, QUBITS);
        // creat AES-256 blocks to generate random number for shuffling
        let blocks: Vec<Aes256> = chunks
            .iter()
            .map(|chunk| {
                let aeskey = pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(
                    chunk,
                    SHUFFLE_SALT.as_bytes(),
                    PBKDF2_LOOPS,
                );
                Aes256::new(&aeskey.into())
            })
            .collect();

        let mut pads = vec![[0u8; MATRIX_BYTES]; usize::from(num_pads)].into_boxed_slice();
        let mut rpads = vec![[0u8; MATRIX_BYTES]; usize::from(num_pads)].into_boxed_slice();

        // Initialize and shuffle pads to create permutation matrices
        for i in 0..usize::from(num_pads) {
            let pad = &mut pads[i];
            // Fill pad with sequential byte values
            fill(pad);
            // Shuffle pad to create a unique permutation matrix
            shuffle(&chunks[i % chunks.len()], pad, i as u16, &blocks);
            // Create the reverse permutation matrix for decryption
            reverse(pad, &mut rpads[i]);
        }

        QuantumPermutationPad {
            pads,
            rpads,
            num_pads,
            enc_rand: create_prng(seed), // Create default PRNG for encryption
            dec_rand: create_prng(seed), // Create default PRNG for decryption
        }
    }

    /// Number of pads.
    pub fn num_pads(&self) -> u16 {
        self.num_pads
    }

    /// The `i`-th encryption pad, for tests and vector checks.
    pub fn pad(&self, i: usize) -> &[u8; MATRIX_BYTES] {
        &self.pads[i]
    }

    /// The `i`-th decryption pad, for tests and vector checks.
    pub fn rpad(&self, i: usize) -> &[u8; MATRIX_BYTES] {
        &self.rpads[i]
    }

    /// All encryption pads, concatenated (Go's `qpp.pads`).
    pub fn pads_bytes(&self) -> Vec<u8> {
        self.pads.concat()
    }

    /// All decryption pads, concatenated (Go's `qpp.rpads`).
    pub fn rpads_bytes(&self) -> Vec<u8> {
        self.rpads.concat()
    }

    /// Encrypts `data` in place with the default encryption generator, continuing the stream
    /// where the previous call left off.
    // Go: qpp@v1.1.25 qpp.go:QuantumPermutationPad.Encrypt()
    pub fn encrypt(&mut self, data: &mut [u8]) {
        // The generator is taken out of `self` so the pads can be borrowed at the same time; Go
        // reaches both through the same pointer. `Rand` is 48 bytes and this is not the path
        // kcptun uses (it drives one generator per stream through `encrypt_with_prng`).
        let mut rand = self.enc_rand.clone();
        self.encrypt_with_prng(data, &mut rand);
        self.enc_rand = rand;
    }

    /// Decrypts `data` in place with the default decryption generator.
    // Go: qpp@v1.1.25 qpp.go:QuantumPermutationPad.Decrypt()
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let mut rand = self.dec_rand.clone();
        self.decrypt_with_prng(data, &mut rand);
        self.dec_rand = rand;
    }

    /// The default encryption generator, for tests.
    pub fn enc_rand(&self) -> &Rand {
        &self.enc_rand
    }

    /// The default decryption generator, for tests.
    pub fn dec_rand(&self) -> &Rand {
        &self.dec_rand
    }

    /// Encrypts `data` in place with `rand`.
    ///
    /// `rand` carries the position in the stream: the generator exposes 64-bit words, and its
    /// `count` says how many bytes of the current word have been consumed, so successive calls
    /// stay byte-aligned however the caller chops the stream up.
    // Go: qpp@v1.1.25 qpp.go:QuantumPermutationPad.EncryptWithPRNG()
    pub fn encrypt_with_prng(&self, data: &mut [u8], rand: &mut Rand) {
        if data.is_empty() {
            return;
        }

        // initial r, index, count
        let size = data.len();
        let mut r = rand.seed64;
        let mut base = &self.pads[usize::from(r as u16 % self.num_pads)];
        let mut count = rand.count;

        // inline xoshiro state for speed
        let mut s = rand.xoshiro;

        // handle unaligned 8bytes
        let mut offset = 0;
        if count != 0 {
            while offset < data.len() {
                // Use the already generated 64-bit random word and keep consuming it byte by
                // byte.
                let rr = (r >> (count << 3)) as u8;
                data[offset] = base[usize::from(data[offset] ^ rr)];
                offset += 1;
                count += 1;

                // switch to another pad when count reaches PAD_SWITCH
                if count == PAD_SWITCH {
                    r = xoshiro256ss(&mut s);
                    base = &self.pads[usize::from(r as u16 % self.num_pads)];
                    count = 0;
                    break;
                }
            }
        }

        // handle 8-byte aligned blocks; Go unrolls two of these per iteration
        let (groups, tail) = data[offset..].as_chunks_mut::<{ PAD_SWITCH as usize }>();
        for d in groups {
            d[0] = base[usize::from(d[0] ^ (r) as u8)];
            d[1] = base[usize::from(d[1] ^ (r >> 8) as u8)];
            d[2] = base[usize::from(d[2] ^ (r >> 16) as u8)];
            d[3] = base[usize::from(d[3] ^ (r >> 24) as u8)];
            d[4] = base[usize::from(d[4] ^ (r >> 32) as u8)];
            d[5] = base[usize::from(d[5] ^ (r >> 40) as u8)];
            d[6] = base[usize::from(d[6] ^ (r >> 48) as u8)];
            d[7] = base[usize::from(d[7] ^ (r >> 56) as u8)];

            // inline xoshiro256** for the next 8 bytes
            r = xoshiro256ss(&mut s);
            base = &self.pads[usize::from(r as u16 % self.num_pads)];
        }

        // handle remaining tail bytes after the aligned blocks; `count` is 0 here unless the
        // head loop ran out of data, in which case `tail` is empty
        for b in tail {
            let rr = (r >> (count << 3)) as u8;
            *b = base[usize::from(*b ^ rr)];
            count += 1;
        }

        // write back xoshiro state
        rand.xoshiro = s;
        rand.seed64 = r;
        rand.count = rand.count.wrapping_add(size as u8) & (PAD_SWITCH - 1);
    }

    /// Decrypts `data` in place with `rand`: the mirror of
    /// [`encrypt_with_prng`](Self::encrypt_with_prng), walking the reverse pads so that the
    /// cipher stream stays synchronised with the same generator.
    // Go: qpp@v1.1.25 qpp.go:QuantumPermutationPad.DecryptWithPRNG()
    pub fn decrypt_with_prng(&self, data: &mut [u8], rand: &mut Rand) {
        if data.is_empty() {
            return;
        }

        let size = data.len();
        let mut r = rand.seed64;
        let mut base = &self.rpads[usize::from(r as u16 % self.num_pads)];
        let mut count = rand.count;

        // inline xoshiro state for speed
        let mut s = rand.xoshiro;

        // handle unaligned 8bytes
        let mut offset = 0;
        if count != 0 {
            while offset < data.len() {
                let rr = (r >> (count << 3)) as u8;
                data[offset] = base[usize::from(data[offset])] ^ rr;
                offset += 1;
                count += 1;

                if count == PAD_SWITCH {
                    r = xoshiro256ss(&mut s);
                    base = &self.rpads[usize::from(r as u16 % self.num_pads)];
                    count = 0;
                    break;
                }
            }
        }

        // handle 8-byte aligned blocks; Go unrolls two of these per iteration
        let (groups, tail) = data[offset..].as_chunks_mut::<{ PAD_SWITCH as usize }>();
        for d in groups {
            d[0] = base[usize::from(d[0])] ^ (r) as u8;
            d[1] = base[usize::from(d[1])] ^ (r >> 8) as u8;
            d[2] = base[usize::from(d[2])] ^ (r >> 16) as u8;
            d[3] = base[usize::from(d[3])] ^ (r >> 24) as u8;
            d[4] = base[usize::from(d[4])] ^ (r >> 32) as u8;
            d[5] = base[usize::from(d[5])] ^ (r >> 40) as u8;
            d[6] = base[usize::from(d[6])] ^ (r >> 48) as u8;
            d[7] = base[usize::from(d[7])] ^ (r >> 56) as u8;

            r = xoshiro256ss(&mut s);
            base = &self.rpads[usize::from(r as u16 % self.num_pads)];
        }

        // handle remaining tail bytes; at this point `count` already encodes how many bytes of
        // `r` were consumed so the PRNG state stays identical to the encryption side
        for b in tail {
            let rr = (r >> (count << 3)) as u8;
            *b = base[usize::from(*b)] ^ rr;
            count += 1;
        }

        // write back xoshiro state
        rand.xoshiro = s;
        rand.seed64 = r;
        rand.count = rand.count.wrapping_add(size as u8) & (PAD_SWITCH - 1);
    }
}

// Go: qpp@v1.1.25 qpp.go:QPPMinimumSeedLength()
/// Seed length, in bytes, that holds as much entropy as the permutation space of `qubits` bits:
/// `ceil(bitlen((2^qubits)!) / 8)`. `QPPMinimumSeedLength(8)` is **211**.
///
/// The cost grows with `(2^qubits)!`, exactly as in Go; anything above 16 qubits is impractical
/// in either language. `qubits >= 64` gives 1, like Go's `1 << qubits` overflowing to 0.
pub fn qpp_minimum_seed_length(qubits: u8) -> usize {
    let perms_count = 1u64.checked_shl(u32::from(qubits)).unwrap_or(0);
    let mut perms = BigUint::from_u64(perms_count);
    for i in (1..perms_count).rev() {
        perms.mul_u64(i);
    }
    let bit_len = perms.bit_len();
    let byte_len = bit_len.div_ceil(8);
    if byte_len == 0 { 1 } else { byte_len }
}

// Go: qpp@v1.1.25 qpp.go:QPPMinimumPads()
/// Minimum number of pads for `qubits`: the number of 32-byte chunks the minimum seed length
/// needs. `QPPMinimumPads(8)` is **7**.
pub fn qpp_minimum_pads(qubits: u8) -> usize {
    let byte_len = qpp_minimum_seed_length(qubits);
    let mut minpads = byte_len / 32;
    let left = byte_len % 32;
    if left > 0 {
        minpads += 1;
    }
    minpads
}

// Go: qpp@v1.1.25 qpp.go:fill()
/// Initialises the pad with sequential byte values, the identity permutation.
fn fill(pad: &mut Matrix) {
    pad[0] = 0;
    for i in 1..pad.len() {
        pad[i] = pad[i - 1].wrapping_add(1);
    }
}

// Go: qpp@v1.1.25 qpp.go:reverse()
/// Writes the inverse of `pad` into `rpad`.
fn reverse(pad: &Matrix, rpad: &mut Matrix) {
    for (i, &p) in pad.iter().enumerate() {
        rpad[usize::from(p)] = i as u8;
    }
}

// Go: qpp@v1.1.25 qpp.go:seedToChunks()
/// Splits `seed` into the 32-byte chunks the pads are derived from.
///
/// A seed shorter than 32 bytes is PBKDF2-expanded to 32 bytes first. The seed is then read
/// cyclically: `seedIdx` keeps counting across chunks, so a seed whose length is not a
/// multiple of 32 gives overlapping chunks, and each chunk is stretched with 1024 PBKDF2
/// rounds.
pub fn seed_to_chunks(seed: &[u8], qubits: u8) -> Vec<[u8; 32]> {
    // Ensure the seed length is at least 32 bytes
    let expanded;
    let seed: &[u8] = if seed.len() < 32 {
        expanded =
            pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(seed, CHUNK_DERIVE_SALT.as_bytes(), PBKDF2_LOOPS);
        &expanded
    } else {
        seed
    };

    // Calculate the required byte length for full permutation space
    let byte_length = qpp_minimum_seed_length(qubits);
    let chunk_count = byte_length.div_ceil(32).max(1); // round up to avoid entropy shortfall

    // Split the seed into overlapping chunks
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut seed_idx = 0usize;
    for _ in 0..chunk_count {
        let mut chunk = [0u8; 32];
        for b in &mut chunk {
            *b = seed[seed_idx % seed.len()];
            seed_idx += 1;
        }

        // Perform key expansion
        chunks.push(pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(
            &chunk,
            CHUNK_DERIVE_SALT.as_bytes(),
            CHUNK_DERIVE_LOOPS,
        ));
    }

    chunks
}

// Go: qpp@v1.1.25 qpp.go:shuffle()
/// Shuffles `pad` into a permutation matrix, using the chunk selected by the pad id as the HMAC
/// key and the AES blocks as the source of randomness.
///
/// The Fisher-Yates index comes from re-encrypting a 32-byte running value with every AES block
/// in turn and reducing it, read as a **big-endian** 256-bit integer, modulo `i + 1`. The
/// reduction is done byte-wise: the modulus is at most 256, so the running remainder always
/// fits in nine bits and no bignum is needed.
fn shuffle(chunk: &[u8; 32], pad: &mut Matrix, pad_id: u16, blocks: &[Aes256]) {
    // use selected chunk based on pad ID to hmac the PAD_IDENTIFIER
    let message = format!("QPP_{pad_id:b}"); // Go: fmt.Sprintf("QPP_%b", padID)
    let mut mac = <Hmac<Sha256>>::new_from_slice(chunk).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    let mut sum: [u8; 32] = mac.finalize().into_bytes().into();

    for i in (1..pad.len()).rev() {
        // use all the entropy from the seed to generate a random number
        for block in blocks {
            let (aes_blocks, _) = sum.as_chunks_mut::<AES_BLOCK_SIZE>();
            for b in aes_blocks {
                block.encrypt_block(b.into());
            }
        }
        let j = mod_big_endian(&sum, i as u32 + 1);
        pad.swap(i, j as usize);
    }
}

/// `sum`, read as a big-endian unsigned integer, modulo `m`.
///
/// `m` is at most `MATRIX_BYTES` (256), so the running remainder stays below 256 and
/// `rem << 8 | byte` below 65536.
// Go: qpp@v1.1.25 qpp.go:shuffle():new(big.Int).SetBytes(sum).Mod(·, i+1)
fn mod_big_endian(sum: &[u8], m: u32) -> u32 {
    debug_assert!(m > 0 && m <= MATRIX_BYTES as u32);
    let mut rem: u32 = 0;
    for &b in sum {
        rem = ((rem << 8) | u32::from(b)) % m;
    }
    rem
}

// The ported Go tests live beside the code they exercise, so they can reach `fill`, `reverse`
// and `mod_big_endian` directly.
#[cfg(test)]
#[path = "qpp_tests.rs"]
mod tests;
