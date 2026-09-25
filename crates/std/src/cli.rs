//! Go-compatible command-line parsing and help rendering (DECISIONS D10: no `clap`).
//!
//! kcptun's command line is Go's `flag` package driven by urfave/cli v1.22.17, and its users
//! rely on that dialect: `-mode fast3`, `-mtu=1400`, `-nocomp`, `-mtu 01350` (octal 744),
//! `KCPTUN_KEY` as the default for `--key`, parsing that stops at the first non-flag argument.
//! This module reproduces it, including the error texts and the help layout.
//!
//! Go sources:
//! - `reference/kcptun/vendor/github.com/urfave/cli@v1.22.17/{app,flag,help,parse,template}.go`
//! - Go 1.27.1 `flag` (`FlagSet.parseOne`, `intValue.Set`, `boolValue.Set`),
//!   `strconv` (`ParseInt` base 0, `ParseBool`, `Quote`), `text/tabwriter`, `path/filepath.Base`
//!
//! The golden vectors in `testdata/vectors/cli.json` are produced by `tools/govectors` running
//! the pinned urfave/cli, and the tests below replay every one of them.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Exit code used for command-line usage errors.
///
/// Deviation V06 (accepted): Go prints `Incorrect Usage. <err>` plus the help text and then
/// exits **0**, because `kcptun`'s `main` ignores the error returned by `cli.App.Run`. The text
/// is kept byte for byte; only the status differs, so supervisors and scripts can tell a bad
/// configuration from a clean start. This constant is the single place that decides it: set it
/// to `0` to get Go's behaviour back.
pub const USAGE_ERROR_EXIT_CODE: i32 = 2;

/// Exit code of `<prog> help <unknown-topic>`.
// Go: urfave/cli help.go:ShowCommandHelp -> NewExitError(..., 3), errors.go:HandleExitCoder
pub const NO_HELP_TOPIC_EXIT_CODE: i32 = 3;

/// Placeholder shown for flags that take a value.
// Go: urfave/cli flag.go:defaultPlaceholder
const DEFAULT_PLACEHOLDER: &str = "value";

/// urfave's `HelpFlag`, appended to the app's flags and to every command's.
// Go: urfave/cli flag.go:HelpFlag
const HELP_FLAG: FlagSpec<'static> = FlagSpec::bool_flag("help, h", "show help");

/// Usage line of the built-in `help` command.
// Go: urfave/cli help.go:helpCommand
const HELP_COMMAND_USAGE: &str = "Shows a list of commands or help for one command";

// ---------------------------------------------------------------------------------------
// Go string and number helpers
// ---------------------------------------------------------------------------------------

/// Error kinds of `strconv`, which Go's `flag` package maps to its own messages.
// Go: strconv/atoi.go:ErrSyntax, ErrRange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumError {
    Syntax,
    Range,
}

impl NumError {
    /// The text Go's `flag` package shows for this error.
    // Go: flag/flag.go:errParse, errRange, numError()
    fn flag_text(self) -> &'static str {
        match self {
            NumError::Syntax => "parse error",
            NumError::Range => "value out of range",
        }
    }

    /// The text of `*strconv.NumError`, used where Go prints the raw `strconv` error.
    // Go: strconv/atoi.go:(*NumError).Error
    fn strconv_text(self, func: &str, num: &str) -> String {
        let reason = match self {
            NumError::Syntax => "invalid syntax",
            NumError::Range => "value out of range",
        };
        format!("strconv.{func}: parsing {}: {reason}", go_quote(num))
    }
}

/// ASCII lower-casing exactly as Go's `strconv.lower` does (`c | 0x20`).
// Go: strconv/atoi.go:lower
fn lower(c: u8) -> u8 {
    c | 0x20
}

/// `strconv.ParseUint(s, 0, 64)`: base is taken from the `0b`/`0o`/`0x` prefix or a leading
/// zero (octal), and underscores are allowed between digits.
// Go: strconv/atoi.go:ParseUint
fn parse_uint_base0(s: &str) -> Result<u64, NumError> {
    if s.is_empty() {
        return Err(NumError::Syntax);
    }
    let bytes = s.as_bytes();
    let mut base: u64 = 10;
    let mut body = s;
    if bytes[0] == b'0' {
        if bytes.len() >= 3 && lower(bytes[1]) == b'b' {
            base = 2;
            body = &s[2..];
        } else if bytes.len() >= 3 && lower(bytes[1]) == b'o' {
            base = 8;
            body = &s[2..];
        } else if bytes.len() >= 3 && lower(bytes[1]) == b'x' {
            base = 16;
            body = &s[2..];
        } else {
            base = 8;
            body = &s[1..];
        }
    }

    // Cutoff is the smallest number such that cutoff*base > MaxUint64.
    let cutoff = u64::MAX / base + 1;
    let max_val = u64::MAX; // bitSize 64

    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in body.as_bytes() {
        let d: u64 = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => u64::from(c - b'0'),
            _ if lower(c).is_ascii_lowercase() => u64::from(lower(c) - b'a' + 10),
            _ => return Err(NumError::Syntax),
        };
        if d >= base {
            return Err(NumError::Syntax);
        }
        if n >= cutoff {
            return Err(NumError::Range); // n*base overflows
        }
        n *= base;
        let n1 = n.wrapping_add(d);
        if n1 < n || n1 > max_val {
            return Err(NumError::Range); // n+d overflows
        }
        n = n1;
    }
    if underscores && !underscore_ok(s) {
        return Err(NumError::Syntax);
    }
    Ok(n)
}

/// Whether the underscores in `s` are in positions Go accepts for a base-0 literal: between
/// digits, or between a base prefix and the first digit.
// Go: strconv/atoi.go:underscoreOK
fn underscore_ok(s: &str) -> bool {
    // saw tracks the last character class: '^' start, '0' digit or base prefix, '_'
    // underscore, '!' anything else.
    let mut saw = b'^';
    let mut i = 0usize;
    let mut b = s.as_bytes();

    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        b = &b[1..];
    }

    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(lower(b[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(b[1]) == b'x';
    }

    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw = b'0';
            i += 1;
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
        i += 1;
    }
    saw != b'_'
}

/// `strconv.ParseInt(s, 0, 64)`, the conversion Go's `flag.IntVar` performs (`strconv.IntSize`
/// is 64 on every platform this port targets).
// Go: strconv/atoi.go:ParseInt, flag/flag.go:(*intValue).Set
fn parse_int_base0(s: &str) -> Result<i64, NumError> {
    if s.is_empty() {
        return Err(NumError::Syntax);
    }
    let (neg, rest) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let un = parse_uint_base0(rest)?;

    let cutoff = 1u64 << 63;
    if !neg && un >= cutoff {
        return Err(NumError::Range);
    }
    if neg && un > cutoff {
        return Err(NumError::Range);
    }
    let n = un as i64;
    Ok(if neg { n.wrapping_neg() } else { n })
}

/// `strconv.ParseBool`.
// Go: strconv/atob.go:ParseBool
fn parse_bool(s: &str) -> Result<bool, NumError> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(NumError::Syntax),
    }
}

/// Whether Go's `strconv.Quote` would print `c` as itself.
///
/// Go consults `unicode.IsPrint` (categories L, M, N, P, S plus ASCII space). Rust has no
/// category tables in `core`, so above ASCII this combines three rules: Cc/Zs/Zl/Zp are caught
/// by `is_control`/`is_whitespace` (for example U+00A0), Cf and Co are listed in
/// [`is_format_or_private`] (for example the U+FEFF byte-order mark a Windows editor may put
/// in front of a JSON config), and everything else is printable. Only unassigned code points
/// (Cn), which Go also escapes, are still treated as printable.
// Go: strconv/quote.go:IsPrint
pub(crate) fn go_is_print(c: char) -> bool {
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }
    !c.is_control() && !c.is_whitespace() && !is_format_or_private(c)
}

/// Unicode's format (Cf) and private-use (Co) code points, which `unicode.IsPrint` rejects.
///
/// Surrogates (Cs) cannot be a Rust `char` at all. The table is Unicode 16.0; a later Unicode
/// version adding a format character would only make such a character print verbatim instead
/// of as `\uXXXX` in an error message.
// Go: unicode/tables.go:Cf, Co
fn is_format_or_private(c: char) -> bool {
    const FORMAT: &[(u32, u32)] = &[
        (0x00ad, 0x00ad),
        (0x0600, 0x0605),
        (0x061c, 0x061c),
        (0x06dd, 0x06dd),
        (0x070f, 0x070f),
        (0x0890, 0x0891),
        (0x08e2, 0x08e2),
        (0x180e, 0x180e),
        (0x200b, 0x200f),
        (0x202a, 0x202e),
        (0x2060, 0x2064),
        (0x2066, 0x206f),
        (0xfeff, 0xfeff),
        (0xfff9, 0xfffb),
        (0x110bd, 0x110bd),
        (0x110cd, 0x110cd),
        (0x13430, 0x1343f),
        (0x1bca0, 0x1bca3),
        (0x1d173, 0x1d17a),
        (0xe0001, 0xe0001),
        (0xe0020, 0xe007f),
        // Private use areas (Co).
        (0xe000, 0xf8ff),
        (0xf0000, 0xffffd),
        (0x100000, 0x10fffd),
    ];
    let v = u32::from(c);
    FORMAT.iter().any(|&(lo, hi)| (lo..=hi).contains(&v))
}

/// `strconv.Quote`: a double-quoted Go string literal, used by `%q` in the `flag` package's
/// error messages and in urfave's `(default: "...")`.
// Go: strconv/quote.go:Quote
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            _ if go_is_print(c) => out.push(c),
            _ => {
                let v = u32::from(c);
                // Go uses \x only below a space and for DEL; everything else is \u / \U.
                if v < 0x20 || v == 0x7f {
                    let _ = write!(out, "\\x{v:02x}");
                } else if v < 0x10000 {
                    let _ = write!(out, "\\u{v:04x}");
                } else {
                    let _ = write!(out, "\\U{v:08x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// `path/filepath.Base`: the last element of `path`, used by urfave to derive the program name
/// shown in the USAGE line from `os.Args[0]`.
// Go: path/filepath/path.go:Base (unix separator)
pub fn filepath_base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut p = path;
    while p.ends_with('/') {
        p = &p[..p.len() - 1];
    }
    if p.is_empty() {
        return "/".to_string();
    }
    match p.rfind('/') {
        Some(i) => p[i + 1..].to_string(),
        None => p.to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// text/tabwriter
// ---------------------------------------------------------------------------------------

/// Column alignment as `text/tabwriter` does it, with the parameters urfave's help printer
/// uses: `tabwriter.NewWriter(out, 1, 8, 2, ' ', 0)`.
// Go: urfave/cli help.go:printHelpCustom, text/tabwriter/tabwriter.go
mod tabwriter {
    /// `minwidth`: minimal cell width including any padding.
    const MINWIDTH: usize = 1;
    /// `padding`: cell padding added to an cell before computing its width.
    const PADDING: usize = 2;
    /// `padchar`: the padding character (spaces, so `tabwidth` never applies).
    const PADCHAR: char = ' ';

    /// Formats tab-separated text into aligned columns.
    ///
    /// The text is split into lines at `\n` and each line into cells at `\t`; the last cell of
    /// a line is "terminal" and never padded, which is why the help output has no trailing
    /// spaces. As in Go, the final line is written without a newline (our input always ends
    /// with one, so that last line is empty).
    // Go: text/tabwriter/tabwriter.go:(*Writer).format
    pub(super) fn format(text: &str) -> String {
        let lines: Vec<Vec<&str>> = text.split('\n').map(|l| l.split('\t').collect()).collect();
        let mut out = String::with_capacity(text.len() + 64);
        let mut widths: Vec<usize> = Vec::new();
        format_block(&mut out, &lines, &mut widths, 0, lines.len());
        out
    }

    /// Formats the lines `[line0, line1)` at column `widths.len()`, recursing into the columns
    /// to the right of each column block.
    // Go: text/tabwriter/tabwriter.go:(*Writer).format
    fn format_block(
        out: &mut String,
        lines: &[Vec<&str>],
        widths: &mut Vec<usize>,
        line0: usize,
        line1: usize,
    ) {
        let column = widths.len();
        let mut line0 = line0;
        let mut this = line0;
        while this < line1 {
            // A cell exists in this column and is not the last cell of its line.
            if column + 1 < lines[this].len() {
                write_lines(out, lines, widths, line0, this);
                line0 = this;

                // Column block begin.
                let mut width = MINWIDTH;
                while this < line1 && column + 1 < lines[this].len() {
                    let w = lines[this][column].chars().count() + PADDING;
                    if w > width {
                        width = w;
                    }
                    this += 1;
                }
                // Column block end.

                widths.push(width);
                format_block(out, lines, widths, line0, this);
                widths.pop();
                line0 = this;
            } else {
                this += 1;
            }
        }
        write_lines(out, lines, widths, line0, line1);
    }

    /// Writes the lines `[line0, line1)`, padding every cell that has a known column width.
    // Go: text/tabwriter/tabwriter.go:(*Writer).writeLines
    fn write_lines(
        out: &mut String,
        lines: &[Vec<&str>],
        widths: &[usize],
        line0: usize,
        line1: usize,
    ) {
        for (i, line) in lines.iter().enumerate().take(line1).skip(line0) {
            for (j, cell) in line.iter().enumerate() {
                out.push_str(cell);
                if let Some(&w) = widths.get(j) {
                    for _ in cell.chars().count()..w {
                        out.push(PADCHAR);
                    }
                }
            }
            // The last buffered line has no newline of its own.
            if i + 1 != lines.len() {
                out.push('\n');
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Flag definitions
// ---------------------------------------------------------------------------------------

/// Default value of a flag, which also decides its type.
///
/// `Bool` carries no value: urfave's `BoolFlag` has no `Value` field, which is why booleans
/// render without a `value` placeholder and without `(default: ...)`.
// Go: urfave/cli flag_string.go:StringFlag, flag_int.go:IntFlag, flag_bool.go:BoolFlag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagDefault<'a> {
    Str(&'a str),
    Int(i64),
    Bool,
}

/// One command-line flag, in urfave's declaration order.
///
/// `name` is urfave's raw name: aliases separated by commas, spaces around them ignored
/// (`"remoteaddr, r"` defines `remoteaddr` and `r`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagSpec<'a> {
    pub name: &'a str,
    pub default: FlagDefault<'a>,
    pub usage: &'a str,
    /// Environment variable consulted for the default value (empty: none).
    pub env: &'a str,
    /// Hidden flags are parsed normally but left out of the help text.
    pub hidden: bool,
}

impl<'a> FlagSpec<'a> {
    /// A string flag (urfave `StringFlag`).
    pub const fn str_flag(name: &'a str, default: &'a str, usage: &'a str) -> Self {
        FlagSpec {
            name,
            default: FlagDefault::Str(default),
            usage,
            env: "",
            hidden: false,
        }
    }

    /// An int flag (urfave `IntFlag`).
    pub const fn int_flag(name: &'a str, default: i64, usage: &'a str) -> Self {
        FlagSpec {
            name,
            default: FlagDefault::Int(default),
            usage,
            env: "",
            hidden: false,
        }
    }

    /// A bool flag (urfave `BoolFlag`); its default is always `false`.
    pub const fn bool_flag(name: &'a str, usage: &'a str) -> Self {
        FlagSpec {
            name,
            default: FlagDefault::Bool,
            usage,
            env: "",
            hidden: false,
        }
    }

    /// Sets the environment variable used as the default (urfave `EnvVar`).
    pub const fn env(mut self, env: &'a str) -> Self {
        self.env = env;
        self
    }

    /// Hides the flag from the help text (urfave `Hidden`).
    pub const fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// The flag's names, in declaration order.
    // Go: urfave/cli flag.go:eachName
    pub fn names(&self) -> impl Iterator<Item = &'a str> {
        each_name(self.name)
    }
}

/// Splits an urfave flag name into its aliases: comma separated, spaces trimmed.
// Go: urfave/cli flag.go:eachName
fn each_name(name: &str) -> impl Iterator<Item = &str> {
    name.split(',').map(|part| part.trim_matches(' '))
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// A command-line error, with Go's exact message.
// Go: flag/flag.go:(*FlagSet).parseOne (failf), urfave/cli context.go:normalizeFlags
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("bad flag syntax: {0}")]
    BadFlagSyntax(String),

    #[error("flag provided but not defined: -{0}")]
    NotDefined(String),

    /// Go's `flag.ErrHelp`, returned when `-h`/`-help` is not a defined flag. [`App`] always
    /// defines both, so kcptun never reaches it.
    #[error("flag: help requested")]
    Help,

    #[error("invalid boolean value {} for -{name}: parse error", go_quote(.value))]
    InvalidBoolValue { value: String, name: String },

    #[error("flag needs an argument: -{0}")]
    NeedsArgument(String),

    #[error("invalid value {} for flag -{name}: {reason}", go_quote(.value))]
    InvalidValue {
        value: String,
        name: String,
        /// `"parse error"` or `"value out of range"` (Go's `flag.errParse` / `errRange`).
        reason: &'static str,
    },

    /// Two aliases of the same flag were given on the command line.
    #[error("Cannot use two forms of the same flag: {name} {other}")]
    TwoForms { name: String, other: String },

    /// An environment variable could not be converted to the flag's type.
    #[error("could not parse {value} as {kind} value for flag {name}: {detail}")]
    Env {
        value: String,
        kind: &'static str,
        name: String,
        detail: String,
    },
}

// ---------------------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------------------

/// Environment lookup, so tests can run without touching the process environment.
pub trait Env {
    /// Like Go's `syscall.Getenv`: `Some` even when the variable is set to the empty string.
    fn get(&self, key: &str) -> Option<String>;
}

/// The process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var_os(key).map(|v| v.to_string_lossy().into_owned())
    }
}

impl Env for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<String> {
        HashMap::get(self, key).cloned()
    }
}

/// An empty environment.
impl Env for () {
    fn get(&self, _key: &str) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------------------
// Values and flag set
// ---------------------------------------------------------------------------------------

/// The value of one flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Value {
    /// The text Go's `flag.Value.String()` returns, which is what urfave's lookups re-parse.
    // Go: flag/flag.go:(*stringValue|intValue|boolValue).String
    fn go_string(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Int(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
        }
    }

    fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
}

/// One entry of the flag set: Go registers an independent variable per **name**, so aliases
/// start out unrelated and are reconciled afterwards by `normalizeFlags`.
#[derive(Debug, Clone)]
struct Entry {
    name: String,
    value: Value,
}

/// A parsed set of flags: Go's `flag.FlagSet` with `ContinueOnError` and a discarded output.
// Go: flag/flag.go:FlagSet
#[derive(Debug, Clone, Default)]
struct FlagSet {
    entries: Vec<Entry>,
    index: HashMap<String, usize>,
    /// Names that were set on the command line (Go's `f.actual`).
    actual: HashSet<String>,
    /// Arguments left after parsing stopped.
    args: Vec<String>,
}

impl FlagSet {
    fn lookup(&self, name: &str) -> Option<&Entry> {
        self.index.get(name).map(|&i| &self.entries[i])
    }

    fn set_value(&mut self, name: &str, value: Value) {
        if let Some(&i) = self.index.get(name) {
            self.entries[i].value = value;
        }
    }

    /// Go's `FlagSet.Parse`: `parseOne` until it reports no more flags or fails.
    // Go: flag/flag.go:(*FlagSet).Parse
    fn parse(&mut self, arguments: &[String]) -> Result<(), UsageError> {
        self.args = arguments.to_vec();
        loop {
            match self.parse_one() {
                Ok(true) => continue,
                Ok(false) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Parses one flag, returning whether a flag was seen.
    // Go: flag/flag.go:(*FlagSet).parseOne
    fn parse_one(&mut self) -> Result<bool, UsageError> {
        let Some(s) = self.args.first().cloned() else {
            return Ok(false);
        };
        let bytes = s.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'-' {
            return Ok(false);
        }
        let mut num_minuses = 1;
        if bytes[1] == b'-' {
            num_minuses = 2;
            if bytes.len() == 2 {
                // "--" terminates the flags
                self.args.remove(0);
                return Ok(false);
            }
        }
        let mut name = &s[num_minuses..];
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(UsageError::BadFlagSyntax(s.clone()));
        }

        // It's a flag. Does it have an argument?
        self.args.remove(0);
        let mut has_value = false;
        let mut value = String::new();
        // Go scans from index 1: an '=' cannot be the first character of the name.
        if let Some(i) = name.bytes().skip(1).position(|c| c == b'=').map(|p| p + 1) {
            value = name[i + 1..].to_string();
            has_value = true;
            name = &name[..i];
        }

        let Some(entry) = self.lookup(name) else {
            if name == "help" || name == "h" {
                // Go prints the usage to the (discarded) output and returns flag.ErrHelp.
                return Err(UsageError::Help);
            }
            return Err(UsageError::NotDefined(name.to_string()));
        };
        let is_bool = entry.value.is_bool();
        let is_int = matches!(entry.value, Value::Int(_));
        let name = name.to_string();

        if is_bool {
            // Special case: a bool flag doesn't need an argument.
            let v = if has_value {
                parse_bool(&value).map_err(|_| UsageError::InvalidBoolValue {
                    value: value.clone(),
                    name: name.clone(),
                })?
            } else {
                true
            };
            self.set_value(&name, Value::Bool(v));
        } else {
            // It must have a value, which might be the next argument.
            if !has_value && !self.args.is_empty() {
                has_value = true;
                value = self.args.remove(0);
            }
            if !has_value {
                return Err(UsageError::NeedsArgument(name));
            }
            let new = if is_int {
                Value::Int(
                    parse_int_base0(&value).map_err(|e| UsageError::InvalidValue {
                        value: value.clone(),
                        name: name.clone(),
                        reason: e.flag_text(),
                    })?,
                )
            } else {
                Value::Str(value.clone())
            };
            self.set_value(&name, new);
        }
        self.actual.insert(name);
        Ok(true)
    }

    /// Copies a value between the aliases of one flag, and rejects using two of them at once.
    // Go: urfave/cli context.go:normalizeFlags
    fn normalize_flags(&mut self, flags: &[FlagSpec<'_>]) -> Result<(), UsageError> {
        for f in flags {
            let parts: Vec<&str> = each_name(f.name).collect();
            if parts.len() == 1 {
                continue;
            }
            let mut source: Option<String> = None;
            for name in &parts {
                if self.actual.contains(*name) {
                    if let Some(other) = source {
                        return Err(UsageError::TwoForms {
                            name: (*name).to_string(),
                            other,
                        });
                    }
                    source = Some((*name).to_string());
                }
            }
            let Some(source) = source else { continue };
            let value = match self.lookup(&source) {
                Some(e) => e.value.clone(),
                None => continue,
            };
            for name in &parts {
                if !self.actual.contains(*name) {
                    self.copy_flag(name, &value);
                }
            }
        }
        Ok(())
    }

    /// Go's `copyFlag`: `set.Set(name, ff.Value.String())`, which also marks the alias as set.
    // Go: urfave/cli context.go:copyFlag
    fn copy_flag(&mut self, name: &str, value: &Value) {
        let text = value.go_string();
        let Some(entry) = self.lookup(name) else {
            return;
        };
        let new = match entry.value {
            Value::Int(_) => match parse_int_base0(&text) {
                Ok(v) => Value::Int(v),
                Err(_) => return,
            },
            Value::Bool(_) => match parse_bool(&text) {
                Ok(v) => Value::Bool(v),
                Err(_) => return,
            },
            Value::Str(_) => Value::Str(text),
        };
        self.set_value(name, new);
        self.actual.insert(name.to_string());
    }
}

// ---------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------

/// The parsed command line handed to the program's action.
// Go: urfave/cli context.go:Context
#[derive(Debug, Clone, Default)]
pub struct Context {
    values: HashMap<String, Value>,
    set_flags: HashSet<String>,
    args: Vec<String>,
}

impl Context {
    /// Go: `Context.String`; `""` when the flag does not exist.
    // Go: urfave/cli flag_string.go:lookupString
    pub fn string(&self, name: &str) -> String {
        self.values
            .get(name)
            .map(Value::go_string)
            .unwrap_or_default()
    }

    /// Go: `Context.Int`; `0` when the flag does not exist or does not parse.
    // Go: urfave/cli flag_int.go:lookupInt
    pub fn int(&self, name: &str) -> i64 {
        match self.values.get(name) {
            Some(v) => parse_int_base0(&v.go_string()).unwrap_or(0),
            None => 0,
        }
    }

    /// Go: `Context.Bool`; `false` when the flag does not exist or does not parse.
    // Go: urfave/cli flag_bool.go:lookupBool
    pub fn bool(&self, name: &str) -> bool {
        match self.values.get(name) {
            Some(v) => parse_bool(&v.go_string()).unwrap_or(false),
            None => false,
        }
    }

    /// Whether the flag was given on the command line, or its environment variable is set.
    ///
    /// Go also treats urfave's `FilePath` as "set"; this port has no `FilePath` because kcptun
    /// never uses it.
    // Go: urfave/cli context.go:(*Context).IsSet
    pub fn is_set(&self, name: &str) -> bool {
        self.set_flags.contains(name)
    }

    /// The arguments left after parsing stopped.
    // Go: urfave/cli context.go:(*Context).Args
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

// ---------------------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------------------

/// What the caller should do after [`App::run`].
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The command line parsed; run the program with this context.
    Action(Context),
    /// Everything has already been written to [`Run::stdout`] / [`Run::stderr`]; exit with
    /// this status.
    Exit(i32),
}

/// The result of [`App::run`]: what to do, and what Go would have written where.
#[derive(Debug, Clone)]
pub struct Run {
    pub outcome: RunOutcome,
    /// Go's `App.Writer` (`os.Stdout`): help, version and usage errors.
    pub stdout: String,
    /// Go's `cli.ErrWriter` (`os.Stderr`): `ExitCoder` errors such as an unknown help topic.
    pub stderr: String,
}

/// A command-line application: urfave's `cli.App` restricted to what kcptun uses (global
/// flags, the built-in `help` command, `--help`/`--version`).
// Go: urfave/cli app.go:App
#[derive(Debug, Clone)]
pub struct App<'a> {
    /// `App.Name`, shown in the NAME section and by `--version` (kcptun sets `"kcptun"`).
    pub name: &'a str,
    /// `App.HelpName`, shown in the USAGE line. urfave defaults it to
    /// `filepath.Base(os.Args[0])`; see [`filepath_base`].
    pub help_name: String,
    /// `App.Usage`, the short description after the name.
    pub usage: &'a str,
    /// `App.Version`.
    pub version: &'a str,
    /// Global flags, in help order, with `--help, -h` and `--version, -v` appended.
    pub flags: Vec<FlagSpec<'a>>,
}

impl<'a> App<'a> {
    /// Builds the app and runs urfave's `Setup`: the `help` command and the `--help, -h` and
    /// `--version, -v` flags are appended unless a flag of that name already exists.
    // Go: urfave/cli app.go:NewApp, (*App).Setup, flag.go:HelpFlag, VersionFlag
    pub fn new(
        name: &'a str,
        help_name: impl Into<String>,
        usage: &'a str,
        version: &'a str,
        flags: impl IntoIterator<Item = FlagSpec<'a>>,
    ) -> Self {
        let mut app = App {
            name,
            help_name: help_name.into(),
            usage,
            version,
            flags: flags.into_iter().collect(),
        };
        app.append_flag(HELP_FLAG);
        if !app.version.is_empty() {
            app.append_flag(FlagSpec::bool_flag("version, v", "print the version"));
        }
        app
    }

    /// Go: `App.appendFlag` (a no-op when a flag of that name is already defined).
    // Go: urfave/cli app.go:(*App).appendFlag, funcs.go:hasFlag
    fn append_flag(&mut self, flag: FlagSpec<'a>) {
        if self.flags.iter().any(|f| f.name == flag.name) {
            return;
        }
        self.flags.push(flag);
    }

    /// Flags shown in the help text.
    // Go: urfave/cli flag.go:visibleFlags
    fn visible_flags(&self) -> impl Iterator<Item = &FlagSpec<'a>> {
        self.flags.iter().filter(|f| !f.hidden)
    }

    /// Builds the flag set, applying environment defaults.
    // Go: urfave/cli flag.go:flagSet, flag_{string,int,bool}.go:ApplyWithError
    fn new_flag_set(&self, env: &dyn Env) -> Result<FlagSet, UsageError> {
        let mut set = FlagSet::default();
        for f in &self.flags {
            let env_val = flag_from_env(env, f.env);
            let value = match (f.default, env_val) {
                (FlagDefault::Str(d), None) => Value::Str(d.to_string()),
                (FlagDefault::Str(_), Some(v)) => Value::Str(v),
                (FlagDefault::Int(d), None) => Value::Int(d),
                (FlagDefault::Int(_), Some(v)) => {
                    Value::Int(parse_int_base0(&v).map_err(|e| UsageError::Env {
                        value: v.clone(),
                        kind: "int",
                        name: f.name.to_string(),
                        detail: e.strconv_text("ParseInt", &v),
                    })?)
                }
                (FlagDefault::Bool, None) => Value::Bool(false),
                (FlagDefault::Bool, Some(v)) if v.is_empty() => Value::Bool(false),
                (FlagDefault::Bool, Some(v)) => {
                    Value::Bool(parse_bool(&v).map_err(|e| UsageError::Env {
                        value: v.clone(),
                        kind: "bool",
                        name: f.name.to_string(),
                        detail: e.strconv_text("ParseBool", &v),
                    })?)
                }
            };
            for name in f.names() {
                set.index.insert(name.to_string(), set.entries.len());
                set.entries.push(Entry {
                    name: name.to_string(),
                    value: value.clone(),
                });
            }
        }
        Ok(set)
    }

    /// Builds the context, resolving `IsSet` the way urfave does.
    // Go: urfave/cli context.go:NewContext, (*Context).IsSet
    fn context(&self, set: &FlagSet, env: &dyn Env) -> Context {
        let mut values = HashMap::with_capacity(set.entries.len());
        for e in &set.entries {
            values.insert(e.name.clone(), e.value.clone());
        }
        let mut set_flags = set.actual.clone();
        for f in &self.flags {
            let names: Vec<&str> = f.names().collect();
            let by_cmdline = names.iter().any(|n| set.actual.contains(*n));
            let by_env = !by_cmdline
                && !f.env.is_empty()
                && each_name(f.env).any(|v| env.get(v.trim()).is_some());
            if by_cmdline || by_env {
                for n in names {
                    set_flags.insert(n.to_string());
                }
            }
        }
        Context {
            values,
            set_flags,
            args: set.args.clone(),
        }
    }

    /// Parses `argv` (including `argv[0]`) like `cli.App.Run`.
    ///
    /// Nothing is printed and no process exits: the caller writes [`Run::stdout`] and
    /// [`Run::stderr`] and acts on [`Run::outcome`].
    // Go: urfave/cli app.go:(*App).Run
    pub fn run(&self, argv: &[String], env: &dyn Env) -> Run {
        let mut stdout = String::new();
        let mut stderr = String::new();

        let outcome = 'run: {
            let mut set = match self.new_flag_set(env) {
                Ok(set) => set,
                Err(e) => {
                    // Deviation V06 (extended): Go returns this error from App.Run and kcptun's
                    // main ignores it, so the process writes nothing to any writer and exits 0.
                    // Both halves below are the deviation — the stderr line is text Go never
                    // emits, and the non-zero status comes from USAGE_ERROR_EXIT_CODE. Drop the
                    // writeln and set that constant to 0 for bit-exact Go behaviour.
                    // Unreachable for kcptun's own tables: only `key`, a StringFlag, has an
                    // EnvVar (client/main.go:84, server/main.go:89).
                    let _ = writeln!(stderr, "{e}");
                    break 'run RunOutcome::Exit(USAGE_ERROR_EXIT_CODE);
                }
            };

            let parse_err = set.parse(argv.get(1..).unwrap_or(&[])).err();
            let norm_err = set.normalize_flags(&self.flags).err();
            let ctx = self.context(&set, env);

            // normalizeFlags runs after parsing and its error takes precedence. Note that it is
            // printed without the "Incorrect Usage." prefix and without the blank line.
            if let Some(err) = norm_err {
                let _ = writeln!(stdout, "{err}");
                stdout.push_str(&self.render_help());
                break 'run RunOutcome::Exit(USAGE_ERROR_EXIT_CODE);
            }
            if let Some(err) = parse_err {
                let _ = write!(stdout, "Incorrect Usage. {err}\n\n");
                stdout.push_str(&self.render_help());
                break 'run RunOutcome::Exit(USAGE_ERROR_EXIT_CODE);
            }

            // Go: checkHelp, then checkVersion.
            if ctx.bool("help") || ctx.bool("h") {
                stdout.push_str(&self.render_help());
                break 'run RunOutcome::Exit(0);
            }
            if !self.version.is_empty() && (ctx.bool("version") || ctx.bool("v")) {
                let _ = writeln!(stdout, "{} version {}", self.name, self.version);
                break 'run RunOutcome::Exit(0);
            }

            // The built-in "help" command, the only command kcptun's apps have.
            if let Some(first) = ctx.args().first()
                && (first == "help" || first == "h")
            {
                let tail = ctx.args()[1..].to_vec();
                break 'run self.run_help_command(&tail, &mut stdout, &mut stderr);
            }

            RunOutcome::Action(ctx)
        };

        Run {
            outcome,
            stdout,
            stderr,
        }
    }

    /// The built-in `help` command, which parses its own arguments before it looks for a topic.
    ///
    /// urfave runs commands through `Command.Run`, which reorders the arguments so that known
    /// flags come first, parses them against the command's flags (just `--help, -h` here) and
    /// only then hands what is left to the action. That is why `help -h` prints the *help
    /// command's* help, `help -- foo` still resolves the topic `foo`, and `help ""` renders the
    /// subcommand template.
    // Go: urfave/cli command.go:(*Command).Run, parseFlags, reorderArgs;
    //     help.go:helpCommand, checkCommandHelp, ShowCommandHelp
    fn run_help_command(
        &self,
        tail: &[String],
        stdout: &mut String,
        stderr: &mut String,
    ) -> RunOutcome {
        let reordered = reorder_args(&[HELP_FLAG], tail);

        let mut set = FlagSet::default();
        for name in HELP_FLAG.names() {
            set.index.insert(name.to_string(), set.entries.len());
            set.entries.push(Entry {
                name: name.to_string(),
                value: Value::Bool(false),
            });
        }
        let parse_result = set
            .parse(&reordered)
            .and_then(|()| set.normalize_flags(&[HELP_FLAG]));
        if let Err(err) = parse_result {
            // Go: `fmt.Fprintln(w, "Incorrect Usage:", err)` — a colon here, where App.Run
            // writes "Incorrect Usage." with a full stop.
            let _ = write!(stdout, "Incorrect Usage: {err}\n\n");
            stdout.push_str(&render_help_command_help());
            return RunOutcome::Exit(USAGE_ERROR_EXIT_CODE);
        }

        let help_requested = set
            .lookup("help")
            .is_some_and(|e| matches!(e.value, Value::Bool(true)))
            || set
                .lookup("h")
                .is_some_and(|e| matches!(e.value, Value::Bool(true)));
        if help_requested {
            stdout.push_str(&render_help_command_help());
            return RunOutcome::Exit(0);
        }

        match set.args.first() {
            // No topic: the app help.
            None => {
                stdout.push_str(&self.render_help());
                RunOutcome::Exit(0)
            }
            // An empty topic renders SubcommandHelpTemplate for the whole app.
            Some(topic) if topic.is_empty() => {
                stdout.push_str(&self.render_subcommand_help());
                RunOutcome::Exit(0)
            }
            // The only command there is to describe is "help" itself.
            Some(topic) if topic == "help" || topic == "h" => {
                stdout.push_str(&render_help_command_help());
                RunOutcome::Exit(0)
            }
            Some(topic) => {
                let _ = writeln!(stderr, "No help topic for '{topic}'");
                RunOutcome::Exit(NO_HELP_TOPIC_EXIT_CODE)
            }
        }
    }

    /// Renders the app help exactly as urfave's `AppHelpTemplate` plus `text/tabwriter` do.
    // Go: urfave/cli template.go:AppHelpTemplate, help.go:printHelpCustom
    pub fn render_help(&self) -> String {
        self.render_help_template(false)
    }

    /// Renders urfave's `SubcommandHelpTemplate`, which `<prog> help ""` reaches. It is the app
    /// help without the VERSION block, with `OPTIONS:` instead of `GLOBAL OPTIONS:` and with a
    /// trailing indent line that the template's `{{range}}` leaves behind.
    // Go: urfave/cli template.go:SubcommandHelpTemplate, help.go:ShowCommandHelp
    pub fn render_subcommand_help(&self) -> String {
        self.render_help_template(true)
    }

    fn render_help_template(&self, subcommand: bool) -> String {
        let mut t = String::with_capacity(1024);

        t.push_str("NAME:\n   ");
        // The app template prints App.Name, the subcommand template App.HelpName.
        t.push_str(if subcommand {
            self.help_name.as_str()
        } else {
            self.name
        });
        if !self.usage.is_empty() {
            t.push_str(" - ");
            t.push_str(self.usage);
        }

        t.push_str("\n\nUSAGE:\n   ");
        t.push_str(&self.help_name);
        let has_visible_flags = self.visible_flags().next().is_some();
        if subcommand {
            t.push_str(" command");
            if has_visible_flags {
                t.push_str(" [command options]");
            }
        } else {
            if has_visible_flags {
                t.push_str(" [global options]");
            }
            // The app always has the built-in help command.
            t.push_str(" command [command options]");
        }
        t.push_str(" [arguments...]");

        if !subcommand && !self.version.is_empty() {
            t.push_str("\n\nVERSION:\n   ");
            t.push_str(self.version);
        }

        t.push_str("\n\nCOMMANDS:");
        t.push_str("\n   help, h\t");
        t.push_str(HELP_COMMAND_USAGE);

        let visible: Vec<&FlagSpec<'_>> = self.visible_flags().collect();
        if !visible.is_empty() {
            if subcommand {
                t.push_str("\n\nOPTIONS:\n   ");
                for f in &visible {
                    t.push_str(&stringify_flag(f));
                    t.push_str("\n   ");
                }
            } else {
                t.push_str("\n\nGLOBAL OPTIONS:\n   ");
                for (i, f) in visible.iter().enumerate() {
                    if i > 0 {
                        t.push_str("\n   ");
                    }
                    t.push_str(&stringify_flag(f));
                }
            }
        }
        t.push('\n');

        tabwriter::format(&t)
    }
}

/// Moves the command's own flags in front of everything else, the way urfave does before it
/// parses a command's arguments (`SkipArgReorder` is false).
///
/// So `help foo -h` is parsed as `help -h foo` and prints the help command's own help, while
/// nothing after a `--` is moved — and the `--` itself is moved to the front of what is left.
// Go: urfave/cli command.go:reorderArgs
fn reorder_args(flags: &[FlagSpec<'_>], args: &[String]) -> Vec<String> {
    let mut reordered: Vec<String> = Vec::new();
    let mut remaining: Vec<String> = Vec::new();
    let mut next_may_be_value = false;
    for (i, arg) in args.iter().enumerate() {
        if next_may_be_value && !arg_is_flag(flags, arg) {
            next_may_be_value = false;
            reordered.push(arg.clone());
        } else if arg == "--" {
            // Go puts the delimiter in front of the arguments seen so far.
            remaining.insert(0, "--".to_string());
            remaining.extend_from_slice(&args[i + 1..]);
            break;
        } else if arg_is_flag(flags, arg) {
            reordered.push(arg.clone());
            next_may_be_value = !arg.contains('=');
        } else {
            remaining.push(arg.clone());
        }
    }
    reordered.extend(remaining);
    reordered
}

/// Whether `arg` spells one of `flags`, in either the `-name` or the `--name` form and with or
/// without a `=value` tail. A lone `-` or `--` never is.
// Go: urfave/cli command.go:argIsFlag
fn arg_is_flag(flags: &[FlagSpec<'_>], arg: &str) -> bool {
    if arg == "-" || arg == "--" || !arg.starts_with('-') {
        return false;
    }
    // Go strips the dashes with strings.Replace, which removes the first one or two dashes
    // found anywhere in the argument, not just a prefix.
    let mut name = if arg.starts_with("--") {
        arg.replacen('-', "", 2)
    } else {
        arg.to_string()
    };
    if name.starts_with('-') {
        name = name.replacen('-', "", 1);
    }
    let name = name.split('=').next().unwrap_or(name.as_str()).to_string();
    flags.iter().flat_map(|f| f.names()).any(|key| key == name)
}

/// `<prog> help help`: urfave renders the help command with `CommandHelpTemplate`, and its
/// `HelpName` is empty because `Setup` appends the command **after** filling the help names in
/// — hence the lone " - " and the four-space USAGE line. Verified against the Go binaries.
// Go: urfave/cli app.go:(*App).Setup, help.go:helpCommand, template.go:CommandHelpTemplate
fn render_help_command_help() -> String {
    tabwriter::format(&format!(
        "NAME:\n    - {HELP_COMMAND_USAGE}\n\nUSAGE:\n    [command]\n"
    ))
}

/// The environment value for `env_var` (a comma-separated list, first match wins).
// Go: urfave/cli flag.go:flagFromFileEnv
fn flag_from_env(env: &dyn Env, env_var: &str) -> Option<String> {
    if env_var.is_empty() {
        return None;
    }
    // Go trims with strings.TrimSpace, i.e. all whitespace and not just the ASCII spaces of
    // urfave's ", " separator that `each_name` strips. `App::context` (IsSet) trims the same
    // way, so both sites agree on which variable a name refers to.
    each_name(env_var).find_map(|name| env.get(name.trim()))
}

/// One flag's help line: `<names>\t<usage> (default: ...) [$ENV]`.
// Go: urfave/cli flag.go:stringifyFlag
fn stringify_flag(f: &FlagSpec<'_>) -> String {
    let (mut placeholder, usage) = unquote_usage(f.usage);

    let mut needs_placeholder = false;
    let mut default_value = String::new();
    match f.default {
        FlagDefault::Str(v) => {
            needs_placeholder = true;
            default_value = if v.is_empty() {
                " (default: )".to_string()
            } else {
                format!(" (default: {})", go_quote(v))
            };
        }
        FlagDefault::Int(v) => {
            needs_placeholder = true;
            default_value = format!(" (default: {v})");
        }
        // BoolFlag has no Value field, so urfave adds neither a default nor a placeholder.
        FlagDefault::Bool => {}
    }
    if default_value == " (default: )" {
        default_value.clear();
    }
    if needs_placeholder && placeholder.is_empty() {
        placeholder = DEFAULT_PLACEHOLDER;
    }

    let usage_with_default = format!("{usage}{default_value}").trim().to_string();
    let mut out = format!(
        "{}\t{usage_with_default}",
        prefixed_names(f.name, placeholder)
    );
    out.push_str(&env_hint(f.env));
    out
}

/// ` [$A, $B]` for a comma-separated `EnvVar` list, or `""`.
// Go: urfave/cli flag.go:withEnvHint (unix branch)
fn env_hint(env_var: &str) -> String {
    if env_var.is_empty() {
        return String::new();
    }
    let joined: Vec<&str> = env_var.split(',').collect();
    format!(" [${}]", joined.join(", $"))
}

/// Pulls a back-quoted placeholder out of a usage string, returning it and the usage with the
/// back quotes removed.
// Go: urfave/cli flag.go:unquoteUsage
fn unquote_usage(usage: &str) -> (&str, String) {
    let b = usage.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'`' {
            for j in i + 1..b.len() {
                if b[j] == b'`' {
                    let name = &usage[i + 1..j];
                    return (name, format!("{}{}{}", &usage[..i], name, &usage[j + 1..]));
                }
            }
            break;
        }
    }
    ("", usage.to_string())
}

/// `--name value, -n value`: one dash for one-character names, two for longer ones.
// Go: urfave/cli flag.go:prefixedNames, prefixFor
fn prefixed_names(full_name: &str, placeholder: &str) -> String {
    let parts: Vec<&str> = each_name(full_name).collect();
    let mut prefixed = String::new();
    for (i, name) in parts.iter().enumerate() {
        prefixed.push_str(if name.len() == 1 { "-" } else { "--" });
        prefixed.push_str(name);
        if !placeholder.is_empty() {
            prefixed.push(' ');
            prefixed.push_str(placeholder);
        }
        if i + 1 < parts.len() {
            prefixed.push_str(", ");
        }
    }
    prefixed
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
