//! Test-case matrix: a [`Case`] describes one kcptun configuration (the knobs that change
//! the wire format or the session layout), [`Matrix`] lists values per dimension and expands
//! them either exhaustively or **pairwise** (every pair of values of any two dimensions
//! appears in at least one case), which keeps Go↔Rust matrices small while still catching
//! bugs triggered by the interaction of two settings.
//!
//! Both expansions are deterministic: the same matrix always yields the same cases in the
//! same order, so a failing case can be re-run by its [`label`](Case::label).

use std::collections::BTreeSet;
use std::fmt;

/// kcptun's KCP mode presets: `(nodelay, interval, resend, nc)`.
// Go: kcptun@v0.0.0-20260208051026-39935d5307f0 std/config.go:PredefinedModes
pub const PREDEFINED_MODES: [(&str, [u32; 4]); 4] = [
    ("normal", [0, 40, 2, 1]),
    ("fast", [0, 30, 2, 1]),
    ("fast2", [1, 20, 2, 1]),
    ("fast3", [1, 10, 2, 1]),
];

/// `(nodelay, interval, resend, nc)` of a predefined mode, `None` for `manual` or unknown
/// names (kcptun then keeps the individual `-nodelay -interval -resend -nc` flags, whose
/// defaults are [`MANUAL_MODE_DEFAULTS`]).
// Go: kcptun@v0.0.0-20260208051026-39935d5307f0 std/config.go:BaseConfig.ApplyMode()
pub fn mode_params(mode: &str) -> Option<[u32; 4]> {
    PREDEFINED_MODES
        .iter()
        .find(|(name, _)| *name == mode)
        .map(|(_, p)| *p)
}

/// kcptun's `-nodelay -interval -resend -nc` flag defaults, in effect when the mode is not a
/// predefined one (`ApplyMode()` then changes nothing).
// Go: kcptun@v0.0.0-20260208051026-39935d5307f0 client/main.go, server/main.go: cli flag Values (nodelay, interval, resend, nc)
pub const MANUAL_MODE_DEFAULTS: [u32; 4] = [0, 50, 0, 0];

/// Which side a flag list is for (the kcptun server has no `-conn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// kcptun `client`.
    Client,
    /// kcptun `server`.
    Server,
}

impl Side {
    /// The logical binary name this side runs: `client` or `server` (what
    /// [`bin`](crate::bins::bin) is given).
    pub fn bin_name(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
        }
    }
}

/// One kcptun configuration. [`Default`] is kcptun's defaults (client and server agree on
/// all of these).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Case {
    /// `-crypt` (default `aes`).
    pub crypt: String,
    /// `-nocomp` (default off, i.e. snappy compression on).
    pub nocomp: bool,
    /// `-smuxver` (default 2).
    pub smuxver: u32,
    /// `-datashard` / `-ds` (default 10).
    pub ds: u32,
    /// `-parityshard` / `-ps` (default 3).
    pub ps: u32,
    /// `-QPP` (default off).
    pub qpp: bool,
    /// `-mode` (default `fast`).
    pub mode: String,
    /// `-conn`, client only (default 1).
    pub conn: u32,
    /// `-tcp` (default off; tcpraw, Linux only).
    pub tcp: bool,
    /// `-mtu` (default 1350).
    pub mtu: u32,
    /// Further flags appended verbatim to both sides.
    pub extra: Vec<String>,
}

impl Default for Case {
    fn default() -> Self {
        // Go: kcptun@v0.0.0-20260208051026-39935d5307f0 client/main.go, server/main.go: cli flag Values
        Case {
            crypt: "aes".into(),
            nocomp: false,
            smuxver: 2,
            ds: 10,
            ps: 3,
            qpp: false,
            mode: "fast".into(),
            conn: 1,
            tcp: false,
            mtu: 1350,
            extra: Vec::new(),
        }
    }
}

impl Case {
    /// kcptun's defaults; same as [`Case::default`].
    pub fn new() -> Self {
        Case::default()
    }

    /// Sets `-crypt`.
    pub fn crypt(mut self, crypt: impl Into<String>) -> Self {
        self.crypt = crypt.into();
        self
    }

    /// Sets `-nocomp`.
    pub fn nocomp(mut self, nocomp: bool) -> Self {
        self.nocomp = nocomp;
        self
    }

    /// Sets `-smuxver`.
    pub fn smuxver(mut self, smuxver: u32) -> Self {
        self.smuxver = smuxver;
        self
    }

    /// Sets `-ds`.
    pub fn ds(mut self, ds: u32) -> Self {
        self.ds = ds;
        self
    }

    /// Sets `-ps`.
    pub fn ps(mut self, ps: u32) -> Self {
        self.ps = ps;
        self
    }

    /// Sets `-ds` and `-ps` together.
    pub fn fec(self, ds: u32, ps: u32) -> Self {
        self.ds(ds).ps(ps)
    }

    /// Sets `-QPP`.
    pub fn qpp(mut self, qpp: bool) -> Self {
        self.qpp = qpp;
        self
    }

    /// Sets `-mode`.
    pub fn mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    /// Sets `-conn` (client only).
    pub fn conn(mut self, conn: u32) -> Self {
        self.conn = conn;
        self
    }

    /// Sets `-tcp`.
    pub fn tcp(mut self, tcp: bool) -> Self {
        self.tcp = tcp;
        self
    }

    /// Sets `-mtu`.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Appends one extra flag or value.
    pub fn extra_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra.push(arg.into());
        self
    }

    /// Appends extra flags and values.
    pub fn extra_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extra.extend(args.into_iter().map(Into::into));
        self
    }

    /// kcptun command-line flags (Go single-dash style, in the kcptun client's declaration order) for
    /// `side`, followed by [`extra`](Self::extra). Boolean flags appear only when set;
    /// `-conn` only on the client. Addresses (`-l`, `-r`, `-t`) are the caller's business.
    pub fn args(&self, side: Side) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "-crypt".into(),
            self.crypt.clone(),
            "-mode".into(),
            self.mode.clone(),
        ];
        if self.qpp {
            a.push("-QPP".into());
        }
        if side == Side::Client {
            a.extend(["-conn".into(), self.conn.to_string()]);
        }
        a.extend([
            "-mtu".into(),
            self.mtu.to_string(),
            "-ds".into(),
            self.ds.to_string(),
            "-ps".into(),
            self.ps.to_string(),
        ]);
        if self.nocomp {
            a.push("-nocomp".into());
        }
        a.extend(["-smuxver".into(), self.smuxver.to_string()]);
        if self.tcp {
            a.push("-tcp".into());
        }
        a.extend(self.extra.iter().cloned());
        a
    }

    /// Shorthand for [`args`](Self::args)`(Side::Client)`.
    pub fn client_args(&self) -> Vec<String> {
        self.args(Side::Client)
    }

    /// Shorthand for [`args`](Self::args)`(Side::Server)`.
    pub fn server_args(&self) -> Vec<String> {
        self.args(Side::Server)
    }

    /// Flags for the `kcpecho` Go peer (raw KCP, no smux/compression/QPP): `-crypt -ds -ps
    /// -mtu`, plus `-nodelay -interval -resend -nc` from [`mode_params`], or kcptun's flag
    /// defaults [`MANUAL_MODE_DEFAULTS`] for `manual`/unknown modes (kcpecho's own defaults
    /// are kcptun's `fast`, so they are always passed explicitly). `nocomp`, `smuxver`,
    /// `qpp`, `conn`, `tcp` and `extra` do not apply to kcpecho and are left out.
    pub fn kcpecho_args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "-crypt".into(),
            self.crypt.clone(),
            "-ds".into(),
            self.ds.to_string(),
            "-ps".into(),
            self.ps.to_string(),
            "-mtu".into(),
            self.mtu.to_string(),
        ];
        let [nodelay, interval, resend, nc] =
            mode_params(&self.mode).unwrap_or(MANUAL_MODE_DEFAULTS);
        for (flag, v) in [
            ("-nodelay", nodelay),
            ("-interval", interval),
            ("-resend", resend),
            ("-nc", nc),
        ] {
            a.extend([flag.into(), v.to_string()]);
        }
        a
    }

    /// A compact, unique, deterministic description for test output, e.g.
    /// `crypt=aes ds=10 ps=3 mode=fast mtu=1350 smuxver=2 conn=1 +nocomp +qpp`.
    pub fn label(&self) -> String {
        let mut s = format!(
            "crypt={} ds={} ps={} mode={} mtu={} smuxver={} conn={}",
            self.crypt, self.ds, self.ps, self.mode, self.mtu, self.smuxver, self.conn
        );
        for (on, name) in [
            (self.nocomp, "nocomp"),
            (self.qpp, "qpp"),
            (self.tcp, "tcp"),
        ] {
            if on {
                s.push_str(" +");
                s.push_str(name);
            }
        }
        if !self.extra.is_empty() {
            s.push_str(" extra=[");
            s.push_str(&self.extra.join(" "));
            s.push(']');
        }
        s
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// One dimension of a [`Matrix`]: the values a [`Case`] field takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dim {
    /// `-crypt` values.
    Crypt(Vec<String>),
    /// `-nocomp` values.
    NoComp(Vec<bool>),
    /// `-smuxver` values.
    SmuxVer(Vec<u32>),
    /// `-ds` values.
    Ds(Vec<u32>),
    /// `-ps` values.
    Ps(Vec<u32>),
    /// `(ds, ps)` pairs as one dimension (FEC off is `(0, 0)`).
    Fec(Vec<(u32, u32)>),
    /// `-QPP` values.
    Qpp(Vec<bool>),
    /// `-mode` values.
    Mode(Vec<String>),
    /// `-conn` values.
    Conn(Vec<u32>),
    /// `-tcp` values.
    Tcp(Vec<bool>),
    /// `-mtu` values.
    Mtu(Vec<u32>),
    /// Alternative extra flag lists (appended to the base case's extras).
    Extra(Vec<Vec<String>>),
}

impl Dim {
    /// Number of values.
    pub fn len(&self) -> usize {
        match self {
            Dim::Crypt(v) | Dim::Mode(v) => v.len(),
            Dim::NoComp(v) | Dim::Qpp(v) | Dim::Tcp(v) => v.len(),
            Dim::SmuxVer(v) | Dim::Ds(v) | Dim::Ps(v) | Dim::Conn(v) | Dim::Mtu(v) => v.len(),
            Dim::Fec(v) => v.len(),
            Dim::Extra(v) => v.len(),
        }
    }

    /// True if the dimension has no values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sets the field of `case` to value number `i` (`i < len()`).
    fn apply(&self, case: &mut Case, i: usize) {
        match self {
            Dim::Crypt(v) => case.crypt = v[i].clone(),
            Dim::NoComp(v) => case.nocomp = v[i],
            Dim::SmuxVer(v) => case.smuxver = v[i],
            Dim::Ds(v) => case.ds = v[i],
            Dim::Ps(v) => case.ps = v[i],
            Dim::Fec(v) => (case.ds, case.ps) = v[i],
            Dim::Qpp(v) => case.qpp = v[i],
            Dim::Mode(v) => case.mode = v[i].clone(),
            Dim::Conn(v) => case.conn = v[i],
            Dim::Tcp(v) => case.tcp = v[i],
            Dim::Mtu(v) => case.mtu = v[i],
            Dim::Extra(v) => case.extra.extend(v[i].iter().cloned()),
        }
    }
}

/// A base [`Case`] plus the dimensions to vary. Dimensions with no values are ignored (the
/// base value stays).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matrix {
    base: Case,
    dims: Vec<Dim>,
}

fn strings<S: Into<String>>(v: impl IntoIterator<Item = S>) -> Vec<String> {
    v.into_iter().map(Into::into).collect()
}

impl Matrix {
    /// A matrix over `base` with no dimensions yet.
    pub fn new(base: Case) -> Self {
        Matrix {
            base,
            dims: Vec::new(),
        }
    }

    /// Adds a dimension (ignored if empty).
    pub fn dim(mut self, dim: Dim) -> Self {
        if !dim.is_empty() {
            self.dims.push(dim);
        }
        self
    }

    /// Adds a `-crypt` dimension.
    pub fn crypt<S: Into<String>>(self, v: impl IntoIterator<Item = S>) -> Self {
        self.dim(Dim::Crypt(strings(v)))
    }

    /// Adds a `-nocomp` dimension.
    pub fn nocomp(self, v: impl IntoIterator<Item = bool>) -> Self {
        self.dim(Dim::NoComp(v.into_iter().collect()))
    }

    /// Adds a `-smuxver` dimension.
    pub fn smuxver(self, v: impl IntoIterator<Item = u32>) -> Self {
        self.dim(Dim::SmuxVer(v.into_iter().collect()))
    }

    /// Adds a `-ds` dimension.
    pub fn ds(self, v: impl IntoIterator<Item = u32>) -> Self {
        self.dim(Dim::Ds(v.into_iter().collect()))
    }

    /// Adds a `-ps` dimension.
    pub fn ps(self, v: impl IntoIterator<Item = u32>) -> Self {
        self.dim(Dim::Ps(v.into_iter().collect()))
    }

    /// Adds a combined `(ds, ps)` dimension.
    pub fn fec(self, v: impl IntoIterator<Item = (u32, u32)>) -> Self {
        self.dim(Dim::Fec(v.into_iter().collect()))
    }

    /// Adds a `-QPP` dimension.
    pub fn qpp(self, v: impl IntoIterator<Item = bool>) -> Self {
        self.dim(Dim::Qpp(v.into_iter().collect()))
    }

    /// Adds a `-mode` dimension.
    pub fn mode<S: Into<String>>(self, v: impl IntoIterator<Item = S>) -> Self {
        self.dim(Dim::Mode(strings(v)))
    }

    /// Adds a `-conn` dimension.
    pub fn conn(self, v: impl IntoIterator<Item = u32>) -> Self {
        self.dim(Dim::Conn(v.into_iter().collect()))
    }

    /// Adds a `-tcp` dimension.
    pub fn tcp(self, v: impl IntoIterator<Item = bool>) -> Self {
        self.dim(Dim::Tcp(v.into_iter().collect()))
    }

    /// Adds a `-mtu` dimension.
    pub fn mtu(self, v: impl IntoIterator<Item = u32>) -> Self {
        self.dim(Dim::Mtu(v.into_iter().collect()))
    }

    /// Adds a dimension of alternative extra flag lists.
    pub fn extra(self, v: impl IntoIterator<Item = Vec<String>>) -> Self {
        self.dim(Dim::Extra(v.into_iter().collect()))
    }

    /// The dimensions, in the order added.
    pub fn dims(&self) -> &[Dim] {
        &self.dims
    }

    /// Value counts per dimension.
    pub fn levels(&self) -> Vec<usize> {
        self.dims.iter().map(Dim::len).collect()
    }

    fn build(&self, rows: Vec<Vec<usize>>) -> Vec<Case> {
        rows.into_iter()
            .map(|row| {
                let mut c = self.base.clone();
                for (d, &i) in self.dims.iter().zip(&row) {
                    d.apply(&mut c, i);
                }
                c
            })
            .collect()
    }

    /// Every combination (the cartesian product), first dimension slowest.
    pub fn exhaustive(&self) -> Vec<Case> {
        self.build(exhaustive_indices(&self.levels()))
    }

    /// A deterministic set of cases covering every pair of values of any two dimensions
    /// (see [`pairwise_indices`]). With no dimensions this is just the base case.
    pub fn pairwise(&self) -> Vec<Case> {
        self.build(pairwise_indices(&self.levels()))
    }
}

/// The cartesian product of `0..levels[k]`, first position slowest. One empty row for no
/// levels; no rows if any level is 0.
pub fn exhaustive_indices(levels: &[usize]) -> Vec<Vec<usize>> {
    let mut rows = vec![Vec::with_capacity(levels.len())];
    for &n in levels {
        rows = rows
            .into_iter()
            .flat_map(|r| {
                (0..n).map(move |v| {
                    let mut r = r.clone();
                    r.push(v);
                    r
                })
            })
            .collect();
    }
    rows
}

/// Index rows (row `r`, position `k` holds a value index `< levels[k]`) such that for every
/// two positions `i < j` and every value pair `(a, b)` some row has `a` at `i` and `b` at
/// `j`.
///
/// Deterministic IPOG (in-parameter-order, Lei & Tai). Positions are processed largest level
/// first (stable, so equal levels keep their order); the output columns are in the caller's
/// order. Start with the product of the first two positions, then add one position at a
/// time. *Horizontal growth* gives each existing row the value covering the most
/// still-uncovered pairs (ties: lowest value). *Vertical growth* places each remaining pair, in order, into the first row whose cells
/// are unset or already equal to it, or else appends a row with only those two cells set.
/// Cells still unset at the end become 0. One empty row for no levels; no rows if any level
/// is 0; with one position, one row per value.
pub fn pairwise_indices(levels: &[usize]) -> Vec<Vec<usize>> {
    if levels.contains(&0) {
        return Vec::new();
    }
    if levels.len() < 2 {
        return exhaustive_indices(levels);
    }
    // IPOG works best with the largest dimensions first; build in that order (stable sort,
    // so equal sizes keep their order) and map the columns back.
    let mut order: Vec<usize> = (0..levels.len()).collect();
    order.sort_by(|&a, &b| levels[b].cmp(&levels[a]));
    let sorted: Vec<usize> = order.iter().map(|&k| levels[k]).collect();
    ipog(&sorted)
        .into_iter()
        .map(|r| {
            let mut out = vec![0; levels.len()];
            for (pos, &k) in order.iter().enumerate() {
                out[k] = r[pos];
            }
            out
        })
        .collect()
}

/// IPOG over `levels` (at least two, none 0) in the given column order.
fn ipog(levels: &[usize]) -> Vec<Vec<usize>> {
    let mut rows: Vec<Vec<Option<usize>>> = exhaustive_indices(&levels[..2])
        .into_iter()
        .map(|r| r.into_iter().map(Some).collect())
        .collect();

    for (k, &nk) in levels.iter().enumerate().skip(2) {
        // Pairs (i, value at i, value at k) not yet covered, for every earlier position i.
        let mut uncovered: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
        for (i, &ni) in levels[..k].iter().enumerate() {
            for a in 0..ni {
                for b in 0..nk {
                    uncovered.insert((i, a, b));
                }
            }
        }

        // Horizontal growth.
        for row in &mut rows {
            let gain = |b: usize| {
                row.iter()
                    .enumerate()
                    .filter(|(i, a)| matches!(a, Some(a) if uncovered.contains(&(*i, *a, b))))
                    .count()
            };
            let mut best = 0;
            let mut best_gain = gain(0);
            for b in 1..nk {
                let g = gain(b);
                if g > best_gain {
                    best = b;
                    best_gain = g;
                }
            }
            for (i, a) in row.iter().enumerate() {
                if let Some(a) = a {
                    uncovered.remove(&(i, *a, best));
                }
            }
            row.push(Some(best));
        }

        // Vertical growth.
        while let Some(&(i, a, b)) = uncovered.iter().next() {
            let fits =
                |r: &Vec<Option<usize>>| r[i].is_none_or(|x| x == a) && r[k].is_none_or(|x| x == b);
            let idx = match rows.iter().position(fits) {
                Some(idx) => idx,
                None => {
                    rows.push(vec![None; k + 1]);
                    rows.len() - 1
                }
            };
            let row = &mut rows[idx];
            row[i] = Some(a);
            row[k] = Some(b);
            for (j, v) in row[..k].iter().enumerate() {
                if let Some(v) = v {
                    uncovered.remove(&(j, *v, b));
                }
            }
        }
    }

    rows.into_iter()
        .map(|r| r.into_iter().map(|v| v.unwrap_or(0)).collect())
        .collect()
}

/// Returns the first pair `(i, a, j, b)` (positions `i < j`, values `a`, `b`) that no row
/// covers, or `None` if `rows` is a complete pairwise cover of `levels`. Also returns the
/// offending row as a pair if a row has the wrong length or an out-of-range value.
pub fn first_uncovered_pair(
    levels: &[usize],
    rows: &[Vec<usize>],
) -> Option<(usize, usize, usize, usize)> {
    for r in rows {
        if r.len() != levels.len() {
            return Some((usize::MAX, r.len(), usize::MAX, levels.len()));
        }
        if let Some((k, &v)) = r.iter().enumerate().find(|(k, v)| **v >= levels[*k]) {
            return Some((k, v, usize::MAX, levels[k]));
        }
    }
    let mut seen: BTreeSet<(usize, usize, usize, usize)> = BTreeSet::new();
    for r in rows {
        for i in 0..r.len() {
            for j in i + 1..r.len() {
                seen.insert((i, r[i], j, r[j]));
            }
        }
    }
    for i in 0..levels.len() {
        for j in i + 1..levels.len() {
            for a in 0..levels[i] {
                for b in 0..levels[j] {
                    if !seen.contains(&(i, a, j, b)) {
                        return Some((i, a, j, b));
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_case_is_kcptun_defaults() {
        let c = Case::new();
        assert_eq!(c, Case::default());
        assert_eq!(
            c.client_args(),
            [
                "-crypt", "aes", "-mode", "fast", "-conn", "1", "-mtu", "1350", "-ds", "10", "-ps",
                "3", "-smuxver", "2"
            ]
        );
        assert_eq!(
            c.server_args(),
            [
                "-crypt", "aes", "-mode", "fast", "-mtu", "1350", "-ds", "10", "-ps", "3",
                "-smuxver", "2"
            ]
        );
        assert_eq!(
            c.label(),
            "crypt=aes ds=10 ps=3 mode=fast mtu=1350 smuxver=2 conn=1"
        );
    }

    #[test]
    fn builder_sets_every_flag() {
        let c = Case::new()
            .crypt("salsa20")
            .nocomp(true)
            .smuxver(1)
            .fec(0, 0)
            .qpp(true)
            .mode("fast3")
            .conn(4)
            .tcp(true)
            .mtu(1200)
            .extra_arg("-sndwnd")
            .extra_args(["2048", "-acknodelay"]);
        assert_eq!(
            c.args(Side::Client),
            [
                "-crypt",
                "salsa20",
                "-mode",
                "fast3",
                "-QPP",
                "-conn",
                "4",
                "-mtu",
                "1200",
                "-ds",
                "0",
                "-ps",
                "0",
                "-nocomp",
                "-smuxver",
                "1",
                "-tcp",
                "-sndwnd",
                "2048",
                "-acknodelay"
            ]
        );
        let server = c.args(Side::Server);
        assert!(!server.iter().any(|a| a == "-conn"));
        assert!(server.ends_with(&[
            "-tcp".into(),
            "-sndwnd".into(),
            "2048".into(),
            "-acknodelay".into()
        ]));
        assert_eq!(
            c.to_string(),
            "crypt=salsa20 ds=0 ps=0 mode=fast3 mtu=1200 smuxver=1 conn=4 +nocomp +qpp +tcp \
             extra=[-sndwnd 2048 -acknodelay]"
        );
        assert_eq!(Case::new().ds(7).ps(2), Case::new().fec(7, 2));
    }

    #[test]
    fn kcpecho_args_map_modes() {
        assert_eq!(
            Case::new().kcpecho_args(),
            [
                "-crypt",
                "aes",
                "-ds",
                "10",
                "-ps",
                "3",
                "-mtu",
                "1350",
                "-nodelay",
                "0",
                "-interval",
                "30",
                "-resend",
                "2",
                "-nc",
                "1"
            ]
        );
        let normal = Case::new().mode("normal").kcpecho_args();
        assert_eq!(
            &normal[8..],
            [
                "-nodelay",
                "0",
                "-interval",
                "40",
                "-resend",
                "2",
                "-nc",
                "1"
            ]
        );
        let fast2 = Case::new().mode("fast2").kcpecho_args();
        assert_eq!(
            &fast2[8..],
            [
                "-nodelay",
                "1",
                "-interval",
                "20",
                "-resend",
                "2",
                "-nc",
                "1"
            ]
        );
        // manual (or an unknown name) gets kcptun's flag defaults, not kcpecho's (= fast).
        // Go: kcptun@v0.0.0-20260208051026-39935d5307f0 client/main.go: nodelay/interval/resend/nc Values 0/50/0/0
        let manual = Case::new().mode("manual").kcpecho_args();
        assert_eq!(
            &manual[8..],
            [
                "-nodelay",
                "0",
                "-interval",
                "50",
                "-resend",
                "0",
                "-nc",
                "0"
            ]
        );
        assert_eq!(Case::new().mode("bogus").kcpecho_args(), manual);
        // Options kcpecho does not have are left out.
        let c = Case::new().qpp(true).nocomp(true).tcp(true).extra_arg("-x");
        assert_eq!(c.kcpecho_args(), Case::new().kcpecho_args());
        assert_eq!(mode_params("fast3"), Some([1, 10, 2, 1]));
        assert_eq!(mode_params("manual"), None);
    }

    #[test]
    fn exhaustive_is_the_cartesian_product() {
        assert_eq!(exhaustive_indices(&[]), vec![Vec::<usize>::new()]);
        assert!(exhaustive_indices(&[2, 0]).is_empty());
        assert_eq!(
            exhaustive_indices(&[2, 3]),
            [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]]
        );
        let m = Matrix::new(Case::new())
            .crypt(["aes", "none"])
            .nocomp([false, true]);
        let cases = m.exhaustive();
        assert_eq!(cases.len(), 4);
        assert_eq!(cases[1].crypt, "aes");
        assert!(cases[1].nocomp);
        assert_eq!(cases[2].crypt, "none");
        assert!(!cases[2].nocomp);
    }

    #[test]
    fn pairwise_edge_cases() {
        assert_eq!(pairwise_indices(&[]), vec![Vec::<usize>::new()]);
        assert_eq!(pairwise_indices(&[3]), [[0], [1], [2]]);
        assert!(pairwise_indices(&[2, 0, 3]).is_empty());
        assert_eq!(pairwise_indices(&[2, 2]), exhaustive_indices(&[2, 2]));
        assert_eq!(pairwise_indices(&[1, 1, 1, 1]), [[0, 0, 0, 0]]);
        // Three binary dimensions need only 4 of the 8 combinations.
        let rows = pairwise_indices(&[2, 2, 2]);
        assert_eq!(rows.len(), 4);
        assert_eq!(first_uncovered_pair(&[2, 2, 2], &rows), None);
    }

    #[test]
    fn pairwise_covers_every_pair() {
        let shapes: &[&[usize]] = &[
            &[2, 3],
            &[3, 3, 3],
            &[3, 3, 3, 3],
            &[2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            &[5, 1, 4, 2, 3],
            &[1, 4, 4, 1],
            &[2, 7, 3, 2, 5, 2],
            &[4, 4, 4, 4, 4, 4],
            &[6, 2, 2, 3, 2, 2, 2, 2, 2, 3, 2],
        ];
        for &levels in shapes {
            let rows = pairwise_indices(levels);
            assert_eq!(
                first_uncovered_pair(levels, &rows),
                None,
                "levels {levels:?}: rows {rows:?}"
            );
            // Never more rows than the product, never fewer than the largest pair product.
            let product: usize = levels.iter().product();
            let mut sorted = levels.to_vec();
            sorted.sort_unstable_by(|a, b| b.cmp(a));
            assert!(rows.len() <= product, "{levels:?}");
            assert!(rows.len() >= sorted[0] * sorted[1], "{levels:?}");
            // Rows are distinct.
            let distinct: HashSet<&Vec<usize>> = rows.iter().collect();
            assert_eq!(distinct.len(), rows.len(), "{levels:?}: duplicate rows");
        }
    }

    #[test]
    fn pairwise_is_small() {
        // Known optimum 9 for 3^4 (orthogonal array); IPOG gets within a few rows.
        assert!(pairwise_indices(&[3, 3, 3, 3]).len() <= 11);
        // 2^10 = 1024 combinations; pairwise needs only a handful (optimum 6).
        assert!(pairwise_indices(&[2; 10]).len() <= 12);
        // Two large dimensions dominate: 7 * 5 = 35 is the lower bound and is reached.
        assert_eq!(pairwise_indices(&[2, 7, 3, 2, 5, 2]).len(), 35);
        // A kcptun-sized matrix: 13,824 combinations, fewer than 25 cases.
        let full: usize = [6, 2, 2, 3, 2, 2, 2, 2, 2, 3, 2].iter().product();
        let n = pairwise_indices(&[6, 2, 2, 3, 2, 2, 2, 2, 2, 3, 2]).len();
        assert_eq!(full, 13_824);
        assert!(n <= 25, "{n} rows");
    }

    #[test]
    fn pairwise_is_deterministic() {
        let m = || {
            Matrix::new(Case::new())
                .crypt(["aes", "salsa20", "none", "aes-128-gcm"])
                .fec([(10, 3), (0, 0), (3, 2)])
                .nocomp([false, true])
                .smuxver([1, 2])
                .qpp([false, true])
                .mode(["fast", "fast3", "normal"])
                .conn([1, 3])
        };
        let a = m().pairwise();
        let b = m().pairwise();
        assert_eq!(a, b);
        assert_eq!(
            pairwise_indices(&[4, 3, 2, 2, 2, 3, 2]),
            pairwise_indices(&[4, 3, 2, 2, 2, 3, 2])
        );
        // Every pair of values really appears in the built cases, too.
        let crypts = ["aes", "salsa20", "none", "aes-128-gcm"];
        for crypt in crypts {
            for fec in [(10, 3), (0, 0), (3, 2)] {
                assert!(
                    a.iter().any(|c| c.crypt == crypt && (c.ds, c.ps) == fec),
                    "{crypt} {fec:?}"
                );
            }
            for mode in ["fast", "fast3", "normal"] {
                assert!(a.iter().any(|c| c.crypt == crypt && c.mode == mode));
            }
            for qpp in [false, true] {
                assert!(a.iter().any(|c| c.crypt == crypt && c.qpp == qpp));
            }
        }
        let labels: HashSet<String> = a.iter().map(Case::label).collect();
        assert_eq!(labels.len(), a.len(), "labels identify cases");
        assert!(a.len() < 4 * 3 * 2 * 2 * 2 * 3 * 2);
    }

    #[test]
    fn matrix_keeps_base_and_ignores_empty_dims() {
        let base = Case::new().mtu(1400).extra_arg("-quiet");
        let m = Matrix::new(base.clone())
            .crypt(Vec::<String>::new())
            .extra([vec![], vec!["-sndwnd".to_string(), "256".to_string()]])
            .tcp([false]);
        assert_eq!(m.levels(), [2, 1]);
        assert_eq!(m.dims().len(), 2);
        let cases = m.pairwise();
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0], base);
        assert_eq!(cases[1].extra, ["-quiet", "-sndwnd", "256"]);
        assert!(cases.iter().all(|c| c.mtu == 1400 && c.crypt == "aes"));
        assert_eq!(
            Matrix::new(base.clone()).pairwise(),
            std::slice::from_ref(&base)
        );
        assert_eq!(Matrix::new(base.clone()).exhaustive(), [base]);
        let m = Matrix::new(Case::new())
            .ds([1, 2])
            .ps([0])
            .smuxver([1])
            .mode(["fast2"])
            .conn([2])
            .mtu([900])
            .nocomp([true])
            .qpp([true]);
        let c = &m.pairwise()[1];
        assert_eq!((c.ds, c.ps, c.smuxver, c.conn, c.mtu), (2, 0, 1, 2, 900));
        assert_eq!(c.mode, "fast2");
        assert!(c.nocomp && c.qpp);
    }

    #[test]
    fn uncovered_pair_checker_detects_gaps() {
        let levels = [2, 2, 2];
        let mut rows = pairwise_indices(&levels);
        let removed = rows.pop().unwrap();
        let gap = first_uncovered_pair(&levels, &rows).expect("gap");
        let (i, a, j, b) = gap;
        assert_eq!((removed[i], removed[j]), (a, b));
        assert!(first_uncovered_pair(&levels, &[vec![0, 0]]).is_some());
        assert!(first_uncovered_pair(&levels, &[vec![0, 0, 2]]).is_some());
    }
}
