//! A tiny `--flag value` parser.
//!
//! The lab tools are driven by `tools/lab/lab.py`, never by a human typing quickly, so the
//! parser is deliberately strict: it refuses unknown flags, refuses a repeated flag unless the
//! caller asks for all of its values, and never guesses. Strictness is what keeps a six-hour
//! unattended run from starting with a silently ignored option.
//!
//! Grammar: `<command> [--flag value | --flag=value | --bool-flag]...`. A flag that is not
//! listed as boolean consumes the next token, whatever it looks like, so negative numbers and
//! values beginning with `-` are fine.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

/// Parsed command line: the subcommand plus its flags.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The subcommand (`serve`, `ping`, …), empty when the argv had none.
    pub command: String,
    /// Flag name (without `--`) to the values it was given, in occurrence order. A boolean flag
    /// maps to a single empty string.
    values: BTreeMap<String, Vec<String>>,
}

impl Args {
    /// Parses `argv` **without** the program name.
    ///
    /// `bool_flags` lists the flags that stand alone; every other flag takes the next token.
    pub fn parse<I>(argv: I, bool_flags: &[&str]) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut out = Args::default();
        let mut it = argv.into_iter().peekable();
        if let Some(first) = it.peek()
            && !first.starts_with('-')
        {
            out.command = it.next().unwrap_or_default();
        }
        while let Some(tok) = it.next() {
            let Some(flag) = tok.strip_prefix("--") else {
                return Err(format!(
                    "unexpected argument {tok:?} (flags start with `--`)"
                ));
            };
            if flag.is_empty() {
                return Err("unexpected argument \"--\"".to_string());
            }
            let (name, inline) = match flag.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (flag.to_string(), None),
            };
            let value = match (bool_flags.contains(&name.as_str()), inline) {
                (true, None) => String::new(),
                (true, Some(v)) if v == "true" => String::new(),
                (true, Some(v)) => {
                    return Err(format!("--{name} takes no value (got {v:?})"));
                }
                (false, Some(v)) => v,
                (false, None) => match it.next() {
                    Some(v) => v,
                    None => return Err(format!("--{name} needs a value")),
                },
            };
            out.values.entry(name).or_default().push(value);
        }
        Ok(out)
    }

    /// Fails unless every flag given is in `allowed`.
    pub fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        for name in self.values.keys() {
            if !allowed.contains(&name.as_str()) {
                return Err(format!("unknown flag --{name}"));
            }
        }
        Ok(())
    }

    /// True when the flag was given at least once.
    pub fn has(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Every value of a repeatable flag, in the order they were given.
    pub fn all(&self, name: &str) -> &[String] {
        self.values.get(name).map_or(&[], Vec::as_slice)
    }

    /// The single value of `name`, or `None`. Fails when the flag was repeated.
    pub fn opt(&self, name: &str) -> Result<Option<&str>, String> {
        match self.values.get(name) {
            None => Ok(None),
            Some(v) if v.len() == 1 => Ok(Some(v[0].as_str())),
            Some(v) => Err(format!("--{name} given {} times", v.len())),
        }
    }

    /// The single value of `name`, or `default`.
    pub fn str_or<'a>(&'a self, name: &str, default: &'a str) -> Result<&'a str, String> {
        Ok(self.opt(name)?.unwrap_or(default))
    }

    /// The single value of `name`; fails when it is missing.
    pub fn req(&self, name: &str) -> Result<&str, String> {
        self.opt(name)?
            .ok_or_else(|| format!("--{name} is required"))
    }

    /// Parses the single value of `name`, or returns `default`.
    pub fn parsed_or<T>(&self, name: &str, default: T) -> Result<T, String>
    where
        T: FromStr,
        T::Err: Display,
    {
        match self.opt(name)? {
            None => Ok(default),
            Some(raw) => raw
                .parse()
                .map_err(|e| format!("--{name}: bad value {raw:?}: {e}")),
        }
    }

    /// Parses the single value of `name`; fails when it is missing.
    pub fn parsed_req<T>(&self, name: &str) -> Result<T, String>
    where
        T: FromStr,
        T::Err: Display,
    {
        let raw = self.req(name)?;
        raw.parse()
            .map_err(|e| format!("--{name}: bad value {raw:?}: {e}"))
    }

    /// Splits every `--flag label=value` occurrence into its two halves.
    pub fn pairs(&self, name: &str) -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        for raw in self.all(name) {
            let (label, value) = raw
                .split_once('=')
                .ok_or_else(|| format!("--{name} wants label=value, got {raw:?}"))?;
            if label.is_empty() || value.is_empty() {
                return Err(format!("--{name} wants label=value, got {raw:?}"));
            }
            out.push((label.to_string(), value.to_string()));
        }
        Ok(out)
    }
}

/// Parses a size that may carry a `k`/`m`/`g` suffix (`1m` = 1048576).
pub fn parse_size(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let (digits, scale) = match trimmed.chars().last() {
        Some('k') | Some('K') => (&trimmed[..trimmed.len() - 1], 1024),
        Some('m') | Some('M') => (&trimmed[..trimmed.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&trimmed[..trimmed.len() - 1], 1024 * 1024 * 1024),
        _ => (trimmed, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|e| format!("bad size {raw:?}: {e}"))?;
    n.checked_mul(scale)
        .ok_or_else(|| format!("size {raw:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn parses_command_flags_and_inline_values() {
        let a = Args::parse(
            argv("ping --connect 1.2.3.4:5 --size=64 --verify"),
            &["verify"],
        )
        .expect("parses");
        assert_eq!(a.command, "ping");
        assert_eq!(a.opt("connect"), Ok(Some("1.2.3.4:5")));
        assert_eq!(a.parsed_or::<u64>("size", 0), Ok(64));
        assert!(a.has("verify"));
        assert!(!a.has("json"));
    }

    #[test]
    fn a_value_flag_takes_the_next_token_whatever_it_looks_like() {
        let a = Args::parse(argv("serve --listen -1"), &[]).expect("parses");
        assert_eq!(a.opt("listen"), Ok(Some("-1")));
    }

    #[test]
    fn repeatable_flags_keep_their_order() {
        let a = Args::parse(argv("s --pid cli=1 --pid srv=2"), &[]).expect("parses");
        assert_eq!(
            a.pairs("pid"),
            Ok(vec![
                ("cli".to_string(), "1".to_string()),
                ("srv".to_string(), "2".to_string()),
            ])
        );
        assert!(
            a.opt("pid").is_err(),
            "a repeated flag is not a single value"
        );
    }

    #[test]
    fn missing_values_and_unknown_flags_are_refused() {
        assert!(Args::parse(argv("s --listen"), &[]).is_err());
        assert!(Args::parse(argv("s --verify=yes"), &["verify"]).is_err());
        assert!(Args::parse(argv("s positional"), &[]).is_err());
        let a = Args::parse(argv("s --nope 1"), &[]).expect("parses");
        assert_eq!(
            a.reject_unknown(&["yes"]),
            Err("unknown flag --nope".into())
        );
    }

    #[test]
    fn required_and_typed_accessors_report_the_flag_name() {
        let a = Args::parse(argv("s --size abc"), &[]).expect("parses");
        assert_eq!(a.req("connect"), Err("--connect is required".into()));
        let err = a.parsed_req::<u64>("size").expect_err("not a number");
        assert!(err.starts_with("--size: bad value \"abc\""), "{err}");
    }

    #[test]
    fn sizes_accept_k_m_and_g_suffixes() {
        assert_eq!(parse_size("10240"), Ok(10240));
        assert_eq!(parse_size("10k"), Ok(10240));
        assert_eq!(parse_size("1M"), Ok(1024 * 1024));
        assert_eq!(parse_size("2g"), Ok(2 * 1024 * 1024 * 1024));
        assert!(parse_size("1t").is_err());
        assert!(parse_size("18446744073709551615g").is_err());
    }
}
