//! Append-only CSV output.
//!
//! Every long-running lab tool writes its samples here, and the rules come straight from what a
//! six-hour unattended run needs:
//!
//! - **append, never rewrite**: a restarted sampler continues the same file;
//! - **header only when the file is empty**, so appending twice does not repeat it (the same
//!   rule `kcptun_std::snmp` uses for `-snmplog`, which keeps the two CSVs consistent);
//! - **flush after every row**: a dropped ssh session, a reboot or a SIGKILL loses nothing but
//!   the row in flight;
//! - **fixed field count**: a row with the wrong arity is a bug, not a silently skewed column.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// A CSV file that rows are appended to.
#[derive(Debug)]
pub struct CsvAppender {
    file: File,
    path: PathBuf,
    fields: usize,
}

impl CsvAppender {
    /// Opens (or creates) `path` for appending and writes `header` if the file is empty.
    pub fn open(path: &Path, header: &[&str]) -> std::io::Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(path)?;
        let mut this = Self {
            file,
            path: path.to_path_buf(),
            fields: header.len(),
        };
        if this.file.metadata()?.len() == 0 {
            let cells: Vec<String> = header.iter().map(|h| (*h).to_string()).collect();
            this.row(&cells)?;
        }
        Ok(this)
    }

    /// The file being written, for log messages.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one row and flushes it.
    pub fn row(&mut self, cells: &[String]) -> std::io::Result<()> {
        if cells.len() != self.fields {
            return Err(std::io::Error::other(format!(
                "csv: {} cells for a {}-column file ({})",
                cells.len(),
                self.fields,
                self.path.display()
            )));
        }
        let mut line = String::with_capacity(cells.len() * 12);
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            line.push_str(&escape(cell));
        }
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()
    }
}

/// Quotes a field when it would otherwise change the record's shape.
///
/// The rules are the ones Go's `encoding/csv` uses, which is what the `-snmplog` writer follows,
/// so both CSVs in a run directory can be read by the same parser.
// Go: encoding/csv/writer.go:Writer.fieldNeedsQuotes(), the same list as
// `kcptun_std::snmp::field_needs_quotes`: a comma, a quote, CR or LF, the literal `\.`, or a
// *leading* unicode space. A trailing space is not on Go's list and is not on ours.
pub fn escape(field: &str) -> String {
    let needs_quotes = field.contains([',', '"', '\r', '\n'])
        || field.starts_with(char::is_whitespace)
        || field == "\\.";
    if !needs_quotes {
        return field.to_string();
    }
    let mut out = String::with_capacity(field.len() + 2);
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Formats a float with three decimals, the precision every rate and percentile column uses.
pub fn f3(v: f64) -> String {
    if v.is_finite() {
        format!("{v:.3}")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_go_encoding_csv() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape("two\nlines"), "\"two\nlines\"");
        assert_eq!(escape(" lead"), "\" lead\"");
        assert_eq!(escape("\tlead"), "\"\tlead\"");
        // Go quotes a leading space but not a trailing one.
        assert_eq!(escape("trail "), "trail ");
        assert_eq!(escape("\\."), "\"\\.\"");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn f3_drops_non_finite_values() {
        assert_eq!(f3(1.5), "1.500");
        assert_eq!(f3(f64::NAN), "");
        assert_eq!(f3(f64::INFINITY), "");
    }

    #[test]
    fn header_is_written_once_and_rows_append() {
        let dir = std::env::temp_dir().join(format!("kr-csv-{}", std::process::id()));
        let path = dir.join("nested").join("out.csv");
        let _ = std::fs::remove_dir_all(&dir);

        let mut csv = CsvAppender::open(&path, &["a", "b"]).expect("open");
        csv.row(&["1".into(), "x,y".into()]).expect("row");
        drop(csv);

        let mut again = CsvAppender::open(&path, &["a", "b"]).expect("reopen");
        again.row(&["2".into(), "z".into()]).expect("row");
        assert!(
            again.row(&["only-one".into()]).is_err(),
            "arity is enforced"
        );
        drop(again);

        let text = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(text, "a,b\n1,\"x,y\"\n2,z\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
