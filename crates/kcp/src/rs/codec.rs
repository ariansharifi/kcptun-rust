//! The Reed-Solomon encoder/decoder: a port of klauspost/reedsolomon v1.13.0 `reedsolomon.go`
//! restricted to what kcp-go uses (`New` with default options, `Encode`, `ReconstructData`).
//!
//! Only the default `buildMatrix` construction exists (Vandermonde x inverse of its top square).
//! `codeSomeShards` runs single-threaded (no goroutines or GFNI) with the SIMD kernels of
//! [`simd`](super::simd), selected at run time; those only change speed, never the bytes.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use super::Error;
use super::matrix::Matrix;
use super::simd::{self, Kernel};

/// Most shards (data + parity) a GF(2^8) code can have: the order of the field.
pub const MAX_TOTAL_SHARDS: usize = 256;

/// Bound of the inversion cache (entries). When full, it is cleared before the next insert.
/// klauspost's inversion tree is unbounded; kcp-go only ever sees at most C(ds+ps, ≤ps)
/// patterns, and in practice a handful, so the bound only limits pathological inputs.
pub const INVERSION_CACHE_MAX: usize = 256;

/// Bytes of each shard processed per round of the coding loop, so that one round of the inputs
/// and a group of outputs stay in cache while every output group is computed. klauspost derives
/// it from the cache sizes (`max(L2, 128 KiB) / (ps + 1)`, or `max(L1D, 32 KiB) / (inputs +
/// outputs)` with its generated kernels); it only affects cache behaviour, never the output.
/// kcp-go shards are at most 1500 bytes, so a single round is the norm. 32 KiB measured best
/// with the SIMD kernels (M5, 1 MiB shards, 10+3 / 10+10 / 50+20: 8 KiB and 128 KiB were 3-16%
/// slower).
const PER_ROUND: usize = 32 * 1024;

/// Bitmask of shard indices (up to [`MAX_TOTAL_SHARDS`]), the inversion cache key.
type ShardMask = [u64; MAX_TOTAL_SHARDS / 64];

/// A shard buffer as `reconstruct_data` sees it, with Go's `[]byte` convention: an empty
/// shard (`len == 0`, or `None`) is missing.
///
/// Missing data shards are resized to the shard size and filled in. Like Go, which reslices a
/// zero-length shard to `[0:shardSize]` when its capacity allows and allocates otherwise,
/// [`set_shard_len`](ShardBuf::set_shard_len) should reuse existing storage when it can.
pub trait ShardBuf {
    /// The shard's bytes (empty when missing).
    fn shard(&self) -> &[u8];
    /// The shard's bytes, mutable.
    fn shard_mut(&mut self) -> &mut [u8];
    /// Makes the shard `n` bytes long. The contents are overwritten afterwards.
    fn set_shard_len(&mut self, n: usize);
}

impl ShardBuf for Vec<u8> {
    fn shard(&self) -> &[u8] {
        self
    }
    fn shard_mut(&mut self) -> &mut [u8] {
        self
    }
    fn set_shard_len(&mut self, n: usize) {
        // Reuses the allocation when capacity >= n, like Go's `shards[i][0:shardSize]`.
        self.resize(n, 0);
    }
}

/// `None` is a missing shard (Go `nil`). Missing parity shards stay `None`.
impl ShardBuf for Option<Vec<u8>> {
    fn shard(&self) -> &[u8] {
        self.as_deref().unwrap_or_default()
    }
    fn shard_mut(&mut self) -> &mut [u8] {
        self.as_deref_mut().unwrap_or_default()
    }
    fn set_shard_len(&mut self, n: usize) {
        self.get_or_insert_with(Vec::new).resize(n, 0);
    }
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon
/// A Reed-Solomon code with `data_shards` data and `parity_shards` parity shards, bit-for-bit
/// the code of klauspost's `reedsolomon.New(data_shards, parity_shards)` (for up to 256
/// shards).
#[derive(Debug)]
pub struct Codec {
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
    /// The `total x data` encoding matrix; `None` when there are no parity shards (Go leaves
    /// `r.m` nil then).
    m: Option<Matrix>,
    /// Inverted decode matrices keyed by the invalid rows seen before `data_shards` valid
    /// ones (Go: the inversion tree, keyed by the same `invalidIndices`).
    tree: HashMap<ShardMask, Matrix>,
    /// The GF(2^8) multiply kernel (Go: the `useAVX2`/`useSSSE3`/`useNEON` options).
    kernel: Kernel,
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:buildMatrix()
/// The encoding matrix: a `total_shards x data_shards` Vandermonde matrix multiplied by the
/// inverse of its top square. The top square becomes the identity (data shards are stored
/// unchanged) and every square subset of rows stays invertible.
pub fn build_matrix(data_shards: usize, total_shards: usize) -> Result<Matrix, Error> {
    // Start with a Vandermonde matrix. This matrix would work, in theory, but doesn't have the
    // property that the data shards are unchanged after encoding.
    let vm = Matrix::vandermonde(total_shards, data_shards)?;
    // Multiply by the inverse of the top square of the matrix. This will make the top square be
    // the identity matrix, but preserve the property that any square subset of rows is
    // invertible.
    let top = vm.sub_matrix(0, 0, data_shards, data_shards)?;
    let top_inv = top.invert()?;
    vm.multiply(&top_inv)
}

impl Codec {
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:New()
    /// Creates a codec for `data_shards` data and `parity_shards` parity shards.
    ///
    /// Errors: [`Error::MaxShardNum`] if `data_shards + parity_shards > 256`, then
    /// [`Error::InvShardNum`] if `data_shards == 0` (Go's order). `parity_shards == 0` is
    /// allowed, as in Go: encoding is a no-op and nothing can be reconstructed.
    ///
    /// Deviation V07: with default options klauspost's `New` does not return `ErrMaxShardNum`
    /// for more than 256 shards but switches to its Leopard GF(2^16) codec, which no peer can
    /// decode; this port returns [`Error::MaxShardNum`] instead.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Codec, Error> {
        let tot_shards = data_shards
            .checked_add(parity_shards)
            .ok_or(Error::MaxShardNum)?;
        if tot_shards > MAX_TOTAL_SHARDS {
            return Err(Error::MaxShardNum);
        }
        if data_shards == 0 {
            return Err(Error::InvShardNum);
        }
        let m = if parity_shards == 0 {
            None
        } else {
            Some(build_matrix(data_shards, tot_shards)?)
        };
        Ok(Codec {
            data_shards,
            parity_shards,
            total_shards: tot_shards,
            m,
            tree: HashMap::new(),
            kernel: Kernel::detect(),
        })
    }

    /// The multiply kernel in use; [`Kernel::detect`] unless changed with
    /// [`set_kernel`](Codec::set_kernel).
    pub fn kernel(&self) -> Kernel {
        self.kernel
    }

    /// Selects the multiply kernel (for tests and benchmarks; every kernel gives the same
    /// bytes).
    pub fn set_kernel(&mut self, kernel: Kernel) {
        self.kernel = kernel;
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.DataShards()
    /// Number of data shards.
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.ParityShards()
    /// Number of parity shards.
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.TotalShards()
    /// Number of shards in total.
    pub fn total_shards(&self) -> usize {
        self.total_shards
    }

    /// The encoding matrix (`total_shards x data_shards`), `None` without parity shards.
    pub fn matrix(&self) -> Option<&Matrix> {
        self.m.as_ref()
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.Encode()
    /// Computes the parity shards from the data shards.
    ///
    /// `shards` holds the data shards followed by the parity shards, all of the same non-zero
    /// length. The parity shards are overwritten; the data shards are unchanged.
    ///
    /// Errors: [`Error::TooFewShards`] if `shards.len() != total_shards`,
    /// [`Error::ShardNoData`] if all shards are empty, [`Error::ShardSize`] if their lengths
    /// differ.
    pub fn encode<S: AsRef<[u8]> + AsMut<[u8]>>(&self, shards: &mut [S]) -> Result<(), Error> {
        if shards.len() != self.total_shards {
            return Err(Error::TooFewShards);
        }
        check_shards(shards.iter().map(|s| s.as_ref().len()), false)?;

        let Some(m) = self.m.as_ref() else {
            // No parity shards: Go's codeSomeShards returns without outputs.
            return Ok(());
        };
        let (data, parity) = shards.split_at_mut(self.data_shards);
        let inputs: Vec<&[u8]> = data.iter().map(|s| s.as_ref()).collect();
        let mut outputs: Vec<&mut [u8]> = parity.iter_mut().map(|s| s.as_mut()).collect();
        let rows: Vec<&[u8]> = (self.data_shards..self.total_shards)
            .map(|r| m.row(r))
            .collect();
        code_some_shards(self.kernel, &rows, &inputs, &mut outputs);
        Ok(())
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.ReconstructData()
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.reconstruct() (dataOnly)
    /// Recreates the missing **data** shards, if possible. Missing parity shards stay missing.
    ///
    /// A shard is missing when it is empty (see [`ShardBuf`]). The first `data_shards` present
    /// shards in index order are the decoder input, exactly like klauspost. Present shards must
    /// all have the same length.
    ///
    /// Errors: [`Error::TooFewShards`] if `shards.len() != total_shards` or fewer than
    /// `data_shards` shards are present, [`Error::ShardNoData`] if all shards are empty,
    /// [`Error::ShardSize`] if the present shards differ in length.
    pub fn reconstruct_data<S: ShardBuf>(&mut self, shards: &mut [S]) -> Result<(), Error> {
        if shards.len() != self.total_shards {
            return Err(Error::TooFewShards);
        }
        // Check arguments.
        let shard_size = check_shards(shards.iter().map(|s| s.shard().len()), true)?;

        // Quick check: are all of the shards present? If so, there's nothing to do.
        let mut number_present = 0;
        let mut data_present = 0;
        for (i, s) in shards.iter().enumerate() {
            if !s.shard().is_empty() {
                number_present += 1;
                if i < self.data_shards {
                    data_present += 1;
                }
            }
        }
        if number_present == self.total_shards || data_present == self.data_shards {
            // Cool. All of the shards have data. We don't need to do anything.
            return Ok(());
        }

        // More complete sanity check.
        if number_present < self.data_shards {
            return Err(Error::TooFewShards);
        }

        // The indices of the valid rows we do have, and the invalid rows we don't have up until
        // we have enough valid rows.
        let mut valid_indices = Vec::with_capacity(self.data_shards);
        let mut invalid_indices: ShardMask = [0; MAX_TOTAL_SHARDS / 64];
        for (matrix_row, s) in shards.iter().enumerate() {
            if valid_indices.len() >= self.data_shards {
                break;
            }
            if !s.shard().is_empty() {
                valid_indices.push(matrix_row);
            } else {
                invalid_indices[matrix_row / 64] |= 1 << (matrix_row % 64);
            }
        }

        // Get the inverted matrix for decoding.
        let data_shards = self.data_shards;
        let kernel = self.kernel;
        let data_decode_matrix = self.get_decode_matrix(&valid_indices, invalid_indices)?;

        // Prepare the missing data shards (the outputs).
        let mut is_output = [false; MAX_TOTAL_SHARDS];
        for (i_shard, s) in shards.iter_mut().take(data_shards).enumerate() {
            if s.shard().is_empty() {
                s.set_shard_len(shard_size);
                is_output[i_shard] = true;
            }
        }

        // Pull out the shards that correspond to the rows of the sub-matrix (the inputs, in
        // valid row order) and the missing data shards with their decode rows.
        let mut inputs: Vec<&[u8]> = Vec::with_capacity(data_shards);
        let mut outputs: Vec<&mut [u8]> = Vec::new();
        let mut matrix_rows: Vec<&[u8]> = Vec::new();
        let mut next_valid = valid_indices.iter().copied().peekable();
        for (i, s) in shards.iter_mut().enumerate() {
            if next_valid.peek() == Some(&i) {
                next_valid.next();
                let s: &S = s;
                inputs.push(s.shard());
            } else if is_output[i] {
                outputs.push(s.shard_mut());
                matrix_rows.push(data_decode_matrix.row(i));
            }
        }

        // Single reconstruction call for all missing shards.
        if !outputs.is_empty() {
            code_some_shards(kernel, &matrix_rows, &inputs, &mut outputs);
        }
        Ok(())
    }

    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.getDecodeMatrix()
    /// The inverse of the sub-matrix of the valid rows, from the cache or computed and cached.
    fn get_decode_matrix(
        &mut self,
        valid_indices: &[usize],
        invalid_indices: ShardMask,
    ) -> Result<&Matrix, Error> {
        let data_shards = self.data_shards;
        let m = self.m.as_ref().ok_or(Error::TooFewShards)?;
        if self.tree.len() >= INVERSION_CACHE_MAX && !self.tree.contains_key(&invalid_indices) {
            self.tree.clear();
        }
        match self.tree.entry(invalid_indices) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                // Pull out the rows of the matrix that correspond to the shards that we have and
                // build a square matrix. This matrix could be used to generate the shards that
                // we have from the original data.
                let mut sub_matrix = Matrix::new(data_shards, data_shards)?;
                for (sub_matrix_row, &valid_index) in
                    valid_indices.iter().take(data_shards).enumerate()
                {
                    sub_matrix
                        .row_mut(sub_matrix_row)
                        .copy_from_slice(m.row(valid_index));
                }
                // Invert the matrix, so we can go from the encoded shards back to the original
                // data. Since this matrix maps back to the original data, it can be used to
                // create a data shard, but not a parity shard.
                let inv = sub_matrix.invert()?;
                Ok(e.insert(inv))
            }
        }
    }

    /// Number of cached inverted matrices.
    #[cfg(test)]
    fn inversion_cache_len(&self) -> usize {
        self.tree.len()
    }
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:checkShards() and shardSize()
/// Checks the shard lengths and returns the shard size: the first non-zero length.
///
/// Errors: [`Error::ShardNoData`] if all are zero, [`Error::ShardSize`] if a length differs
/// from the size (a zero length is accepted only when `nilok`).
fn check_shards(lens: impl Iterator<Item = usize> + Clone, nilok: bool) -> Result<usize, Error> {
    let size = lens.clone().find(|&n| n != 0).unwrap_or(0);
    if size == 0 {
        return Err(Error::ShardNoData);
    }
    for n in lens {
        if n != size && (n != 0 || !nilok) {
            return Err(Error::ShardSize);
        }
    }
    Ok(size)
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.codeSomeShards() (single
// goroutine, clear = true)
/// `outputs[r] = sum over c of matrix_rows[r][c] * inputs[c]`, processed in rounds of
/// [`PER_ROUND`] bytes with `kernel` ([`simd::code_block`]). All inputs and outputs have the
/// length of `inputs[0]`; `matrix_rows` has one row (at least `inputs.len()` long) per output.
fn code_some_shards(
    kernel: Kernel,
    matrix_rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) {
    let Some(first) = inputs.first() else {
        return;
    };
    if outputs.is_empty() {
        return;
    }
    let len = first.len();
    let mut start = 0;
    let mut end = PER_ROUND.min(len);
    while start < len {
        simd::code_block(kernel, matrix_rows, inputs, outputs, start, end);
        start = end;
        end = end.saturating_add(PER_ROUND).min(len);
    }
}

#[cfg(test)]
mod tests;
