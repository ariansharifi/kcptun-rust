//! Matrix algebra over GF(2^8), ported from klauspost/reedsolomon v1.13.0 `matrix.go`.
//!
//! Go stores `[][]byte` (one slice per row); here a matrix is one row-major buffer. Operations,
//! their order and their errors are Go's. `SwapRows` exchanges row contents where Go swaps row
//! slices, which gives the same matrix.
#![forbid(unsafe_code)]

use std::fmt;

use super::Error;
use super::galois::{gal_exp, gal_multiply, gal_one_over};

// Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix
/// A `rows x cols` matrix over GF(2^8), `byte[row][col]`.
#[derive(Clone, PartialEq, Eq)]
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<u8>,
}

impl Matrix {
    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:newMatrix()
    /// A matrix of zeros. Errors like Go when `rows` or `cols` is 0.
    pub fn new(rows: usize, cols: usize) -> Result<Matrix, Error> {
        if rows == 0 {
            return Err(Error::InvalidRowSize);
        }
        if cols == 0 {
            return Err(Error::InvalidColSize);
        }
        Ok(Matrix {
            rows,
            cols,
            data: vec![0; rows * cols],
        })
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:newMatrixData() + matrix.Check()
    /// A matrix from row-major rows (Go: `newMatrixData`). Errors like Go's `Check` when there
    /// are no rows, the first row is empty, or the rows differ in length.
    pub fn from_rows<R: AsRef<[u8]>>(rows: &[R]) -> Result<Matrix, Error> {
        let first = rows.first().ok_or(Error::InvalidRowSize)?;
        let cols = first.as_ref().len();
        if cols == 0 {
            return Err(Error::InvalidColSize);
        }
        let mut data = Vec::with_capacity(rows.len() * cols);
        for row in rows {
            let row = row.as_ref();
            if row.len() != cols {
                return Err(Error::ColSizeMismatch);
            }
            data.extend_from_slice(row);
        }
        Ok(Matrix {
            rows: rows.len(),
            cols,
            data,
        })
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:identityMatrix()
    /// The `size x size` identity matrix.
    pub fn identity(size: usize) -> Result<Matrix, Error> {
        let mut m = Matrix::new(size, size)?;
        for i in 0..size {
            m.set(i, i, 1);
        }
        Ok(m)
    }

    /// Number of rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Row `r` (Go: `m[r]`). Panics if `r >= rows`.
    #[inline]
    pub fn row(&self, r: usize) -> &[u8] {
        &self.data[r * self.cols..(r + 1) * self.cols]
    }

    /// Row `r`, mutable. Panics if `r >= rows`.
    #[inline]
    pub fn row_mut(&mut self, r: usize) -> &mut [u8] {
        &mut self.data[r * self.cols..(r + 1) * self.cols]
    }

    /// Element `m[r][c]`. Panics if out of range.
    #[inline]
    pub fn get(&self, r: usize, c: usize) -> u8 {
        assert!(c < self.cols, "column {c} out of range");
        self.data[r * self.cols + c]
    }

    /// Sets `m[r][c] = v`. Panics if out of range.
    #[inline]
    pub fn set(&mut self, r: usize, c: usize, v: u8) {
        assert!(c < self.cols, "column {c} out of range");
        self.data[r * self.cols + c] = v;
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.Multiply()
    /// `self x right`. Errors like Go when the inner dimensions differ.
    pub fn multiply(&self, right: &Matrix) -> Result<Matrix, Error> {
        if self.cols != right.rows {
            return Err(Error::MultiplySize {
                left_cols: self.cols,
                right_rows: right.rows,
            });
        }
        let mut result = Matrix::new(self.rows, right.cols)?;
        for r in 0..result.rows {
            for c in 0..result.cols {
                let mut value = 0u8;
                for i in 0..self.cols {
                    value ^= gal_multiply(self.get(r, i), right.get(i, c));
                }
                result.set(r, c, value);
            }
        }
        Ok(result)
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.Augment()
    /// The concatenation `[self | right]`. Errors like Go when the row counts differ.
    pub fn augment(&self, right: &Matrix) -> Result<Matrix, Error> {
        if self.rows != right.rows {
            return Err(Error::MatrixSize);
        }
        let mut result = Matrix::new(self.rows, self.cols + right.cols)?;
        for r in 0..self.rows {
            let (left, rest) = result.row_mut(r).split_at_mut(self.cols);
            left.copy_from_slice(self.row(r));
            rest.copy_from_slice(right.row(r));
        }
        Ok(result)
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.SameSize()
    /// Errors like Go unless both matrices have the same shape.
    pub fn same_size(&self, n: &Matrix) -> Result<(), Error> {
        if self.rows != n.rows || self.cols != n.cols {
            return Err(Error::MatrixSize);
        }
        Ok(())
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.SubMatrix()
    /// A copy of rows `rmin..rmax` and columns `cmin..cmax`. Errors like Go (`newMatrix`) when
    /// a range is empty or reversed; panics if a bound exceeds the matrix, as Go does.
    pub fn sub_matrix(
        &self,
        rmin: usize,
        cmin: usize,
        rmax: usize,
        cmax: usize,
    ) -> Result<Matrix, Error> {
        let mut result = Matrix::new(rmax.saturating_sub(rmin), cmax.saturating_sub(cmin))?;
        for r in rmin..rmax {
            result
                .row_mut(r - rmin)
                .copy_from_slice(&self.row(r)[cmin..cmax]);
        }
        Ok(result)
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.SwapRows()
    /// Exchanges rows `r1` and `r2`. Errors like Go when either is out of range.
    pub fn swap_rows(&mut self, r1: usize, r2: usize) -> Result<(), Error> {
        if r1 >= self.rows || r2 >= self.rows {
            return Err(Error::InvalidRowSize);
        }
        if r1 != r2 {
            let (lo, hi) = (r1.min(r2), r1.max(r2));
            let cols = self.cols;
            let (a, b) = self.data.split_at_mut(hi * cols);
            a[lo * cols..(lo + 1) * cols].swap_with_slice(&mut b[..cols]);
        }
        Ok(())
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.IsSquare()
    /// True if the matrix is square.
    pub fn is_square(&self) -> bool {
        self.rows == self.cols
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.Invert()
    /// The inverse of this matrix: Gauss-Jordan elimination on `[self | I]`.
    ///
    /// Returns [`Error::NotSquare`] for a non-square matrix and [`Error::Singular`] when it has
    /// no inverse.
    pub fn invert(&self) -> Result<Matrix, Error> {
        if !self.is_square() {
            return Err(Error::NotSquare);
        }
        let size = self.rows;
        let work = Matrix::identity(size)?;
        let mut work = self.augment(&work)?;
        work.gaussian_elimination()?;
        work.sub_matrix(0, size, size, size * 2)
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.gaussianElimination()
    /// Reduces the left square of this (augmented) matrix to the identity, in place.
    fn gaussian_elimination(&mut self) -> Result<(), Error> {
        let rows = self.rows;
        let columns = self.cols;
        // Clear out the part below the main diagonal and scale the main diagonal to be 1.
        for r in 0..rows {
            // If the element on the diagonal is 0, find a row below that has a non-zero and
            // swap them.
            if self.get(r, r) == 0 {
                for row_below in r + 1..rows {
                    if self.get(row_below, r) != 0 {
                        self.swap_rows(r, row_below)?;
                        break;
                    }
                }
            }
            // If we couldn't find one, the matrix is singular.
            if self.get(r, r) == 0 {
                return Err(Error::Singular);
            }
            // Scale to 1.
            if self.get(r, r) != 1 {
                let scale = gal_one_over(self.get(r, r));
                for v in self.row_mut(r) {
                    *v = gal_multiply(*v, scale);
                }
            }
            // Make everything below the 1 be a 0 by subtracting a multiple of it. (Subtraction
            // and addition are both exclusive or in the Galois field.)
            for row_below in r + 1..rows {
                if self.get(row_below, r) != 0 {
                    let scale = self.get(row_below, r);
                    self.sub_scaled_row(row_below, r, scale, columns);
                }
            }
        }

        // Now clear the part above the main diagonal.
        for d in 0..rows {
            for row_above in 0..d {
                if self.get(row_above, d) != 0 {
                    let scale = self.get(row_above, d);
                    self.sub_scaled_row(row_above, d, scale, columns);
                }
            }
        }
        Ok(())
    }

    /// `m[dst][c] ^= scale * m[src][c]` for `c < columns` (`dst != src`).
    fn sub_scaled_row(&mut self, dst: usize, src: usize, scale: u8, columns: usize) {
        let cols = self.cols;
        let (d, s) = if dst < src {
            let (a, b) = self.data.split_at_mut(src * cols);
            (&mut a[dst * cols..dst * cols + columns], &b[..columns])
        } else {
            let (a, b) = self.data.split_at_mut(dst * cols);
            (&mut b[..columns], &a[src * cols..src * cols + columns])
        };
        for (dv, &sv) in d.iter_mut().zip(s.iter()) {
            *dv ^= gal_multiply(scale, sv);
        }
    }

    // Go: klauspost/reedsolomon@v1.13.0 matrix.go:vandermonde()
    /// A Vandermonde matrix, `m[r][c] = r^c`: any subset of rows that forms a square matrix is
    /// invertible. `rows` must be at most 256 (`r` is taken as a byte, like Go's `byte(r)`).
    pub fn vandermonde(rows: usize, cols: usize) -> Result<Matrix, Error> {
        let mut result = Matrix::new(rows, cols)?;
        for r in 0..rows {
            for c in 0..cols {
                result.set(r, c, gal_exp(r as u8, c));
            }
        }
        Ok(result)
    }
}

// Go: klauspost/reedsolomon@v1.13.0 matrix.go:matrix.String()
/// Human-readable contents, like Go: `[[1, 2], [3, 4]]`.
impl fmt::Display for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for r in 0..self.rows {
            if r > 0 {
                f.write_str(", ")?;
            }
            f.write_str("[")?;
            for (i, v) in self.row(r).iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{v}")?;
            }
            f.write_str("]")?;
        }
        f.write_str("]")
    }
}

impl fmt::Debug for Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matrix({}x{}) {self}", self.rows, self.cols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rows: &[&[u8]]) -> Matrix {
        Matrix::from_rows(rows).unwrap()
    }

    #[test]
    fn new_matrix_errors() {
        assert_eq!(Matrix::new(0, 3).unwrap_err(), Error::InvalidRowSize);
        assert_eq!(Matrix::new(3, 0).unwrap_err(), Error::InvalidColSize);
        assert_eq!(Error::InvalidRowSize.to_string(), "invalid row size");
        assert_eq!(Error::InvalidColSize.to_string(), "invalid column size");
        let empty: [&[u8]; 0] = [];
        assert_eq!(
            Matrix::from_rows(&empty).unwrap_err(),
            Error::InvalidRowSize
        );
        assert_eq!(
            Matrix::from_rows(&[&[][..]]).unwrap_err(),
            Error::InvalidColSize
        );
        assert_eq!(
            Matrix::from_rows(&[&[1u8, 2][..], &[3][..]]).unwrap_err(),
            Error::ColSizeMismatch
        );
    }

    #[test]
    fn identity_and_display() {
        let i = Matrix::identity(3).unwrap();
        assert_eq!(i.to_string(), "[[1, 0, 0], [0, 1, 0], [0, 0, 1]]");
        assert!(i.is_square());
        assert_eq!(
            format!("{i:?}"),
            "Matrix(3x3) [[1, 0, 0], [0, 1, 0], [0, 0, 1]]"
        );
    }

    // Values of klauspost's TestMatrixMultiply (matrix_test.go).
    #[test]
    fn multiply() {
        let m1 = m(&[&[1, 2], &[3, 4]]);
        let m2 = m(&[&[5, 6], &[7, 8]]);
        assert_eq!(
            m1.multiply(&m2).unwrap().to_string(),
            "[[11, 22], [19, 42]]"
        );
        let err = m1.multiply(&Matrix::identity(3).unwrap()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "columns on left (2) is different than rows on right (3)"
        );
    }

    #[test]
    fn augment_sub_matrix_swap() {
        let a = m(&[&[1, 2], &[3, 4]]);
        let b = m(&[&[5], &[6]]);
        let ab = a.augment(&b).unwrap();
        assert_eq!(ab.to_string(), "[[1, 2, 5], [3, 4, 6]]");
        assert_eq!(
            a.augment(&Matrix::identity(3).unwrap()),
            Err(Error::MatrixSize)
        );
        assert_eq!(
            ab.sub_matrix(0, 1, 2, 3).unwrap().to_string(),
            "[[2, 5], [4, 6]]"
        );
        assert_eq!(ab.sub_matrix(1, 1, 1, 3), Err(Error::InvalidRowSize));
        let mut s = ab.clone();
        s.swap_rows(0, 1).unwrap();
        assert_eq!(s.to_string(), "[[3, 4, 6], [1, 2, 5]]");
        s.swap_rows(1, 1).unwrap();
        assert_eq!(s.swap_rows(0, 2), Err(Error::InvalidRowSize));
        assert!(ab.same_size(&s).is_ok());
        assert_eq!(ab.same_size(&a), Err(Error::MatrixSize));
    }

    // Values of klauspost's TestMatrixInverse (matrix_test.go).
    #[test]
    fn invert() {
        let a = m(&[&[56, 23, 98], &[3, 100, 200], &[45, 201, 123]]);
        let inv = a.invert().unwrap();
        assert_eq!(
            inv.to_string(),
            "[[175, 133, 33], [130, 13, 245], [112, 35, 126]]"
        );
        assert_eq!(a.multiply(&inv).unwrap(), Matrix::identity(3).unwrap());

        // Needs a row swap (zero pivot).
        let b = m(&[
            &[1, 0, 0, 0, 0],
            &[0, 1, 0, 0, 0],
            &[0, 0, 0, 1, 0],
            &[0, 0, 0, 0, 1],
            &[7, 7, 6, 6, 1],
        ]);
        let inv = b.invert().unwrap();
        assert_eq!(
            inv.to_string(),
            "[[1, 0, 0, 0, 0], [0, 1, 0, 0, 0], [123, 123, 1, 122, 122], [0, 0, 1, 0, 0], [0, 0, 0, 1, 0]]"
        );
        assert_eq!(b.multiply(&inv).unwrap(), Matrix::identity(5).unwrap());

        let singular = m(&[&[4, 2], &[12, 6]]);
        assert_eq!(singular.invert(), Err(Error::Singular));
        assert_eq!(Error::Singular.to_string(), "matrix is singular");
        let not_square = m(&[&[1, 2, 3]]);
        assert_eq!(not_square.invert(), Err(Error::NotSquare));
        assert_eq!(
            Error::NotSquare.to_string(),
            "only square matrices can be inverted"
        );
    }

    #[test]
    fn vandermonde_values() {
        let v = Matrix::vandermonde(4, 3).unwrap();
        // r^c: row 0 is [1, 0, 0] (0^0 = 1), row 1 all ones, rows 2 and 3 powers.
        assert_eq!(
            v.to_string(),
            "[[1, 0, 0], [1, 1, 1], [1, 2, 4], [1, 3, 5]]"
        );
        let v = Matrix::vandermonde(256, 2).unwrap();
        assert_eq!(v.row(255), [1, 255]);
    }

    #[test]
    fn vandermonde_square_subsets_invert() {
        let v = Matrix::vandermonde(12, 5).unwrap();
        // A few row subsets of size 5.
        for start in 0..7 {
            let rows: Vec<&[u8]> = (start..start + 5).map(|r| v.row(r)).collect();
            let sub = Matrix::from_rows(&rows).unwrap();
            let inv = sub.invert().unwrap();
            assert_eq!(sub.multiply(&inv).unwrap(), Matrix::identity(5).unwrap());
        }
    }
}
