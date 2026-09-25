//! Reed-Solomon erasure coding, byte-compatible with klauspost/reedsolomon v1.13.0 as kcp-go
//! v5.6.66 uses it (`reedsolomon.New(ds, ps)` with default options, DECISIONS D08).
//!
//! - [`galois`]: GF(2^8) (polynomial 0x11D) tables and the scalar multiply kernels.
//! - [`matrix`]: matrix algebra, Gauss-Jordan inversion and the Vandermonde matrix.
//! - [`codec`]: [`Codec`], the encoder/decoder: `buildMatrix`, `Encode`, `ReconstructData` and
//!   the inversion cache.
//! - [`simd`]: NEON / AVX2 / SSSE3 split-nibble multiply kernels and their runtime dispatch
//!   ([`Kernel`]); the only `unsafe` code of the codec.
//!
//! Go reference: `reference/kcptun/vendor/github.com/klauspost/reedsolomon/`.

pub mod codec;
pub mod galois;
pub mod matrix;
pub mod simd;

pub use codec::{Codec, ShardBuf};
pub use matrix::Matrix;
pub use simd::Kernel;

/// Errors of the Reed-Solomon codec, with klauspost's exact messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrInvShardNum
    /// `Codec::new` with no data shards.
    #[error("cannot create Encoder with less than one data shard or less than zero parity shards")]
    InvShardNum,
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrMaxShardNum
    /// `Codec::new` with more than 256 shards in total.
    #[error("cannot create Encoder with more than 256 data+parity shards")]
    MaxShardNum,
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrTooFewShards
    /// The shard slice is not `total_shards` long, or too few shards are present to
    /// reconstruct.
    #[error("too few shards given")]
    TooFewShards,
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrShardNoData
    /// Every shard is empty.
    #[error("no shard data")]
    ShardNoData,
    // Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrShardSize
    /// The shards differ in length (empty shards are allowed only where they mean "missing").
    #[error("shard sizes do not match")]
    ShardSize,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errInvalidRowSize
    /// A matrix with no rows, or a row index out of range.
    #[error("invalid row size")]
    InvalidRowSize,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errInvalidColSize
    /// A matrix with no columns.
    #[error("invalid column size")]
    InvalidColSize,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errColSizeMismatch
    /// Matrix rows of different lengths.
    #[error("column size is not the same for all rows")]
    ColSizeMismatch,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errMatrixSize
    /// Matrix shapes that do not fit the operation.
    #[error("matrix sizes do not match")]
    MatrixSize,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.Multiply() (fmt.Errorf)
    /// `Matrix::multiply` with mismatched inner dimensions.
    #[error("columns on left ({left_cols}) is different than rows on right ({right_rows})")]
    MultiplySize {
        /// Columns of the left matrix.
        left_cols: usize,
        /// Rows of the right matrix.
        right_rows: usize,
    },
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errSingular
    /// The matrix has no inverse.
    #[error("matrix is singular")]
    Singular,
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:errNotSquare
    /// Only square matrices can be inverted.
    #[error("only square matrices can be inverted")]
    NotSquare,
}
