//! The slice of Go's `encoding/json` that kcptun's `-c <file>` configuration needs.
//!
//! `std/config.go:ParseJSONConfig` is `json.NewDecoder(file).Decode(config)`, so the JSON file
//! overlays the values the command line already produced (DECISIONS D11). Reproducing that
//! faithfully means reproducing quite a lot of Go:
//!
//! - keys are matched **exactly** first and case-insensitively afterwards, unknown keys are
//!   ignored, and duplicate keys let the last one win;
//! - a JSON `null` leaves the field untouched ("Because null is often used in JSON to mean
//!   *not present*, unmarshaling a JSON null into any other Go type has no effect");
//! - a type mismatch is reported but decoding **continues** (Go's `d.saveError` keeps the first
//!   error), so later fields of the same file are still applied;
//! - numbers go into `int` fields through `strconv.ParseInt(literal, 10, 64)`, which rejects
//!   fractions, exponents and out-of-range values; the error quotes the literal;
//! - strings are decoded with `AllowInvalidUTF8`, which replaces every invalid **byte** with
//!   its own U+FFFD rather than one per invalid subsequence;
//! - nesting is capped at [`MAX_NESTING_DEPTH`], above which Go reports `exceeded max depth`;
//! - syntax errors carry Go's exact text, down to `%q`-quoted characters.
//!
//! [`Value`] therefore keeps numbers as their source text and objects in file order, and the
//! parser is written against Go's grammar rather than a general-purpose JSON crate.
//!
//! Go sources (Go 1.27.1, whose `encoding/json` is the v2 implementation behind the v1 API):
//! - `encoding/json/{decode.go, stream.go}`: `Decoder.Decode`, `object`, `literalStore`,
//!   `UnmarshalTypeError`
//! - `encoding/json/v2_scanner.go:transformSyntacticError`: the v1 wording of syntax errors
//! - `encoding/json/internal/jsonwire/{decode.go, wire.go}`: the scanner and its messages
//!
//! Every message below is checked against the real Go decoder by the `config` golden vectors
//! (`tools/govectors/config.go`).

use std::fmt::Write as _;

use crate::cli::go_is_print;

// ---------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------

/// A parsed JSON value.
///
/// Numbers keep their source text because Go's error messages quote it (`cannot unmarshal
/// number 1e3 …`) and because `int` fields are filled with `ParseInt` on exactly those bytes.
/// Objects keep file order because Go reports the **first** field that fails to decode.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The number's source text, e.g. `-1`, `1.5`, `1e+3`.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// Members in file order, duplicates included.
    Object(Vec<(String, Value)>),
}

/// Releases a document without recursing.
///
/// The derived drop glue walks nested containers recursively, which overflows the native stack
/// well before the [`MAX_NESTING_DEPTH`] documents the parser accepts (Go's own limit exists
/// for the same reason, but its stacks grow on demand).
impl Drop for Value {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        take_children(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            take_children(&mut value, &mut pending);
        }
    }
}

/// Moves `value`'s children into `out`, leaving it childless so that dropping it is shallow.
fn take_children(value: &mut Value, out: &mut Vec<Value>) {
    match value {
        Value::Array(elements) => out.append(elements),
        Value::Object(members) => out.extend(std::mem::take(members).into_iter().map(|(_, v)| v)),
        _ => {}
    }
}

impl Value {
    /// The word Go puts into `UnmarshalTypeError.Value` for this kind of value.
    // Go: encoding/json decode.go:(*decodeState).{array,object,literalStore}
    fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// A JSON syntax error, with Go's exact text.
///
/// Go 1.27's scanner produces v2 messages which `transformSyntacticError` rewrites into the
/// historical v1 wording ("object name" → "object key", "at start of value" → "looking for
/// beginning of value", …) and truncates at `" (expecting"` unless the message is about a
/// literal. The texts below are the result of that rewriting.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyntaxError {
    /// The input is empty or contains only whitespace (Go returns `io.EOF`).
    #[error("EOF")]
    Eof,
    /// The input ends in the middle of a value (Go returns `io.ErrUnexpectedEOF`).
    #[error("unexpected EOF")]
    UnexpectedEof,
    /// `invalid character …` / `invalid escape sequence …`.
    #[error("{0}")]
    Invalid(String),
    /// More than [`MAX_NESTING_DEPTH`] nested objects and arrays.
    // Go: encoding/json/jsontext/state.go:errMaxDepth
    #[error("exceeded max depth")]
    MaxDepth,
}

/// A value that does not fit the Go field it was decoded into.
// Go: encoding/json decode.go:UnmarshalTypeError
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnmarshalError {
    /// The whole document has the wrong shape (kcptun's configs are objects).
    #[error("json: cannot unmarshal {value} into Go value of type {go_type}")]
    TopLevel {
        /// Go's `UnmarshalTypeError.Value`, e.g. `array`.
        value: String,
        /// The Go type of the configuration struct, e.g. `main.Config`.
        go_type: &'static str,
    },
    /// One field has the wrong type.
    #[error(
        "json: cannot unmarshal {value} into Go struct field {struct_name}.{field} of type {go_type}"
    )]
    Field {
        /// Go's `UnmarshalTypeError.Value`, e.g. `string` or `number 1.5`.
        value: String,
        /// The struct's `reflect.Type.Name()`, e.g. `Config`.
        struct_name: &'static str,
        /// The key **as it appears in the document** (unescaped), which is what Go pushes
        /// onto its field stack, not the `json:"…"` tag it matched.
        field: String,
        /// `string`, `int` or `bool`.
        go_type: &'static str,
    },
}

// ---------------------------------------------------------------------------------------
// Struct decoding
// ---------------------------------------------------------------------------------------

/// A mutable reference to one JSON-decodable field of a configuration struct.
///
/// kcptun's configs only contain `string`, `int` and `bool` fields; anything else would need a
/// new variant here and in [`Field::set`].
#[derive(Debug)]
pub enum Field<'a> {
    Str(&'a mut String),
    /// Go's `int`, 64-bit on every platform this port targets.
    Int(&'a mut i64),
    Bool(&'a mut bool),
}

impl Field<'_> {
    /// What `reflect.Type.String()` returns for the field.
    fn go_type(&self) -> &'static str {
        match self {
            Field::Str(_) => "string",
            Field::Int(_) => "int",
            Field::Bool(_) => "bool",
        }
    }

    /// Stores `value`, or reports Go's `UnmarshalTypeError`.
    // Go: encoding/json decode.go:(*decodeState).literalStore
    fn set(
        &mut self,
        value: &Value,
        struct_name: &'static str,
        field: &str,
    ) -> Result<(), UnmarshalError> {
        let mismatch = |value: String, go_type| UnmarshalError::Field {
            value,
            struct_name,
            field: field.to_string(),
            go_type,
        };
        match (self, value) {
            (Field::Str(dst), Value::String(s)) => {
                **dst = s.clone();
                Ok(())
            }
            (Field::Bool(dst), Value::Bool(b)) => {
                **dst = *b;
                Ok(())
            }
            // Go: strconv.ParseInt(s, 10, 64), then v.OverflowInt(n). A fraction, an exponent
            // or a value outside int64 all end up in the same message, quoting the literal.
            (Field::Int(dst), Value::Number(literal)) => match literal.parse::<i64>() {
                Ok(n) => {
                    **dst = n;
                    Ok(())
                }
                Err(_) => Err(mismatch(format!("number {literal}"), "int")),
            },
            (dst, v) => Err(mismatch(v.kind().to_string(), dst.go_type())),
        }
    }
}

/// One configuration struct that a JSON file can overlay.
pub trait JsonStruct {
    /// `reflect.Type.Name()` of the struct, used in field error messages (`Config.mtu`).
    const GO_STRUCT_NAME: &'static str;
    /// `reflect.Type.String()` of the struct, used when the document is not an object.
    const GO_TYPE_NAME: &'static str;

    /// Every field a JSON key can address, by its `json:"…"` name. Fields promoted from an
    /// embedded struct are listed as if they were declared in the outer struct, which is how
    /// Go's `cachedTypeFields` flattens them.
    fn json_fields(&mut self) -> Vec<(&'static str, Field<'_>)>;
}

/// Overlays `value` onto `config`, Go-style.
///
/// Only keys present in the document change anything; everything else keeps the value the
/// command line produced. Returns the **first** error while still applying the fields that do
/// decode, exactly like Go's `d.saveError`.
// Go: encoding/json decode.go:(*decodeState).object
pub fn decode_struct<C: JsonStruct + ?Sized>(
    config: &mut C,
    value: &Value,
) -> Result<(), UnmarshalError> {
    let object = match value {
        // Go: "unmarshaling a JSON null into any other Go type has no effect".
        Value::Null => return Ok(()),
        Value::Object(members) => members,
        other => {
            return Err(UnmarshalError::TopLevel {
                value: other.kind().to_string(),
                go_type: C::GO_TYPE_NAME,
            });
        }
    };

    let mut fields = config.json_fields();
    let mut first_error = None;
    for (key, member) in object {
        let Some(index) = find_field(&fields, key) else {
            continue; // Go skips values whose key matches no field.
        };
        if matches!(member, Value::Null) {
            continue;
        }
        // Go pushes the document's own key onto `errorContext.FieldStack`, not the tag it
        // matched, so a folded or escaped key is reported exactly as the file spells it.
        // Go: encoding/json decode.go:(*decodeState).object
        if let Err(e) = fields[index].1.set(member, C::GO_STRUCT_NAME, key)
            && first_error.is_none()
        {
            first_error = Some(e);
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Finds the field a JSON key addresses: an exact match first, a case-insensitive one
/// afterwards.
// Go: encoding/json decode.go:(*decodeState).object (byExactName, then byFoldedName)
fn find_field(fields: &[(&'static str, Field<'_>)], key: &str) -> Option<usize> {
    if let Some(i) = fields.iter().position(|(name, _)| *name == key) {
        return Some(i);
    }
    fields.iter().position(|(name, _)| go_fold_eq(name, key))
}

/// Go's case-insensitive name match.
///
/// The v1 API sets `MatchCaseSensitiveDelimiter`, so a folded candidate is accepted only when
/// `strings.EqualFold(name, field)` holds (`encoding/json/v2/fields.go:matchFoldedName`); the
/// `foldName` bucket that ignores `-` and `_` never widens the match. `EqualFold` compares rune
/// by rune using `unicode.SimpleFold`, so this does the same.
// Go: encoding/json/v2/fields.go:matchFoldedName, strings.EqualFold
fn go_fold_eq(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    let mut b = b.chars();
    for ca in a.chars() {
        match b.next() {
            Some(cb) if fold_char_eq(ca, cb) => {}
            _ => return false,
        }
    }
    b.next().is_none()
}

/// One rune of [`go_fold_eq`].
fn fold_char_eq(a: char, b: char) -> bool {
    if a == b {
        return true;
    }
    let (a, b) = (fold_to_ascii(a), fold_to_ascii(b));
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(&b);
    }
    // Neither rune folds into ASCII. Every name in kcptun's field tables is ASCII, so this
    // approximation of Go's `unicode.SimpleFold` walk is unreachable from `find_field`.
    a.to_lowercase().eq(b.to_lowercase())
}

/// Folds the only two non-ASCII runes whose Go fold set contains an ASCII letter.
///
/// Verified by walking `unicode.SimpleFold` over the whole code-space with Go 1.27.1: the sets
/// are `{S, s, U+017F}` and `{K, k, U+212A}` and nothing else reaches ASCII.
// Go: unicode.SimpleFold
fn fold_to_ascii(c: char) -> char {
    match c {
        '\u{17f}' => 's',  // LATIN SMALL LETTER LONG S
        '\u{212a}' => 'k', // KELVIN SIGN
        _ => c,
    }
}

// ---------------------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------------------

// The "where" clauses of Go's `invalid character` messages, after
// v2_scanner.go:syntaxErrorReplacer has rewritten them into the v1 wording.
const WHERE_VALUE: &str = "looking for beginning of value";
const WHERE_OBJECT_KEY_STRING: &str = "looking for beginning of object key string";
const WHERE_AFTER_OBJECT_KEY: &str = "after object key";
const WHERE_AFTER_OBJECT_PAIR: &str = "after object key:value pair";
const WHERE_AFTER_ARRAY_ELEMENT: &str = "after array element";
const WHERE_IN_STRING: &str = "in string";
const WHERE_IN_NUMBER: &str = "in numeric literal";

/// How many objects and arrays may be open at once, per RFC 8259 section 9.
// Go: encoding/json/jsontext/state.go:maxNestingDepth
pub const MAX_NESTING_DEPTH: usize = 10000;

/// Parses one JSON value, the way `json.Decoder.Decode` reads one.
///
/// Anything after that value is ignored: Go's decoder stops at the end of the first value and
/// never looks at the rest of the stream, so `{"mtu":1} trailing junk` decodes cleanly.
pub fn parse(input: &[u8]) -> Result<Value, SyntaxError> {
    let mut p = Parser { buf: input, pos: 0 };
    p.skip_whitespace();
    if p.pos >= p.buf.len() {
        // Go: Decode on an exhausted reader returns io.EOF.
        return Err(SyntaxError::Eof);
    }
    p.value()
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A container [`Parser::value`] has opened but not yet closed.
enum Frame {
    Array(Vec<Value>),
    Object {
        members: Vec<(String, Value)>,
        /// The key whose value is being parsed right now.
        key: String,
    },
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    // Go: encoding/json/internal/jsonwire/decode.go:ConsumeWhitespace
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    /// `invalid character <c> <where>` for the character at the current position.
    // Go: encoding/json/internal/jsonwire/wire.go:NewInvalidCharacterError
    fn invalid_char(&self, where_: &str) -> SyntaxError {
        SyntaxError::Invalid(format!(
            "invalid character {} {where_}",
            quote_rune_bytes(&self.buf[self.pos..])
        ))
    }

    /// Parses one value, with an explicit stack of open containers.
    ///
    /// Go's own decoder recurses, but its stacks grow on demand and it caps nesting at
    /// [`MAX_NESTING_DEPTH`] "to prevent stack overflows"; a native stack cannot be grown, so
    /// this walks the document iteratively and the cap only reproduces Go's error.
    // Go: encoding/json/jsontext state machine, object and array states
    fn value(&mut self) -> Result<Value, SyntaxError> {
        let mut stack: Vec<Frame> = Vec::new();
        // The value just finished, waiting to be attached to the innermost open container.
        let mut done: Value;
        'parse: loop {
            done = match self.peek() {
                None => return Err(SyntaxError::UnexpectedEof),
                Some(b'{') => {
                    if stack.len() >= MAX_NESTING_DEPTH {
                        return Err(SyntaxError::MaxDepth);
                    }
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        Value::Object(Vec::new())
                    } else {
                        let key = self.object_key()?;
                        stack.push(Frame::Object {
                            members: Vec::new(),
                            key,
                        });
                        continue 'parse;
                    }
                }
                Some(b'[') => {
                    if stack.len() >= MAX_NESTING_DEPTH {
                        return Err(SyntaxError::MaxDepth);
                    }
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        Value::Array(Vec::new())
                    } else {
                        stack.push(Frame::Array(Vec::new()));
                        continue 'parse;
                    }
                }
                Some(b'"') => Value::String(self.string()?),
                Some(b't') => self.literal("true").map(|()| Value::Bool(true))?,
                Some(b'f') => self.literal("false").map(|()| Value::Bool(false))?,
                Some(b'n') => self.literal("null").map(|()| Value::Null)?,
                Some(b'-' | b'0'..=b'9') => self.number()?,
                Some(_) => return Err(self.invalid_char(WHERE_VALUE)),
            };

            // Attach `done` to the container below it, closing containers as they end.
            loop {
                let Some(frame) = stack.last_mut() else {
                    return Ok(done);
                };
                let closed = match frame {
                    Frame::Array(elements) => {
                        elements.push(std::mem::replace(&mut done, Value::Null));
                        self.skip_whitespace();
                        match self.peek() {
                            None => return Err(SyntaxError::UnexpectedEof),
                            Some(b',') => {
                                self.pos += 1;
                                self.skip_whitespace();
                                false
                            }
                            Some(b']') => {
                                self.pos += 1;
                                true
                            }
                            Some(_) => return Err(self.invalid_char(WHERE_AFTER_ARRAY_ELEMENT)),
                        }
                    }
                    Frame::Object { members, key } => {
                        let key = std::mem::take(key);
                        members.push((key, std::mem::replace(&mut done, Value::Null)));
                        self.skip_whitespace();
                        match self.peek() {
                            None => return Err(SyntaxError::UnexpectedEof),
                            Some(b',') => {
                                self.pos += 1;
                                let next = self.object_key()?;
                                let Some(Frame::Object { key, .. }) = stack.last_mut() else {
                                    unreachable!("the object frame is still on the stack")
                                };
                                *key = next;
                                false
                            }
                            Some(b'}') => {
                                self.pos += 1;
                                true
                            }
                            Some(_) => return Err(self.invalid_char(WHERE_AFTER_OBJECT_PAIR)),
                        }
                    }
                };
                if !closed {
                    continue 'parse; // the container wants another element or member
                }
                done = match stack.pop() {
                    Some(Frame::Array(elements)) => Value::Array(elements),
                    Some(Frame::Object { members, .. }) => Value::Object(members),
                    None => unreachable!("the frame just matched is still on the stack"),
                };
            }
        }
    }

    /// One object key and its colon, leaving the position at the member's value.
    fn object_key(&mut self) -> Result<String, SyntaxError> {
        self.skip_whitespace();
        match self.peek() {
            None => return Err(SyntaxError::UnexpectedEof),
            Some(b'"') => {}
            Some(_) => return Err(self.invalid_char(WHERE_OBJECT_KEY_STRING)),
        }
        let name = self.string()?;

        self.skip_whitespace();
        match self.peek() {
            None => return Err(SyntaxError::UnexpectedEof),
            Some(b':') => self.pos += 1,
            Some(_) => return Err(self.invalid_char(WHERE_AFTER_OBJECT_KEY)),
        }

        self.skip_whitespace();
        Ok(name)
    }

    /// `true`, `false` or `null`. Go names the expected byte:
    /// `invalid character 'X' in literal true (expecting 'r')`.
    // Go: encoding/json/internal/jsonwire/decode.go:consumeLiteral
    fn literal(&mut self, lit: &str) -> Result<(), SyntaxError> {
        for (i, want) in lit.bytes().enumerate() {
            match self.buf.get(self.pos + i) {
                None => return Err(SyntaxError::UnexpectedEof),
                Some(&c) if c == want => {}
                Some(_) => {
                    self.pos += i;
                    return Err(self.invalid_char(&format!(
                        "in literal {lit} (expecting {})",
                        quote_rune(char::from(want))
                    )));
                }
            }
        }
        self.pos += lit.len();
        Ok(())
    }

    /// A JSON number, kept as its source text.
    // Go: encoding/json/internal/jsonwire/decode.go:ConsumeNumber
    fn number(&mut self) -> Result<Value, SyntaxError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            None => return Err(SyntaxError::UnexpectedEof),
            // A leading zero ends the integer part; `01` is two tokens, not a number.
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.skip_digits(),
            Some(_) => return Err(self.invalid_char(WHERE_IN_NUMBER)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.require_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.require_digits()?;
        }
        // The slice is ASCII by construction.
        Ok(Value::Number(
            String::from_utf8_lossy(&self.buf[start..self.pos]).into_owned(),
        ))
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn require_digits(&mut self) -> Result<(), SyntaxError> {
        match self.peek() {
            None => Err(SyntaxError::UnexpectedEof),
            Some(b'0'..=b'9') => {
                self.skip_digits();
                Ok(())
            }
            Some(_) => Err(self.invalid_char(WHERE_IN_NUMBER)),
        }
    }

    /// A JSON string.
    ///
    /// Go's v1 API decodes with `AllowInvalidUTF8`, so invalid UTF-8 bytes and unpaired
    /// surrogate escapes become U+FFFD instead of failing. Go replaces **one byte at a time**
    /// (`dst = append(dst, "�"...); n += rn` with `rn == 1` from `utf8.DecodeRune`), so a
    /// three-byte GBK sequence such as `\xe3\xba\xc3` yields three replacement characters, not
    /// one; `String::from_utf8_lossy` would collapse maximal subsequences instead. Since the
    /// `key` field feeds PBKDF2, getting this wrong would derive a different session key from
    /// the same file.
    // Go: encoding/json/internal/jsonwire/decode.go:consumeStringResumable, unescapeString
    fn string(&mut self) -> Result<String, SyntaxError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(SyntaxError::UnexpectedEof),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => self.escape(&mut out)?,
                Some(0x00..=0x1f) => return Err(self.invalid_char(WHERE_IN_STRING)),
                Some(c) if c < 0x80 => {
                    out.push(char::from(c));
                    self.pos += 1;
                }
                Some(_) => {
                    // `decode_rune` is `utf8.DecodeRune`: (U+FFFD, 1) for an invalid byte. Go's
                    // `!utf8.FullRune` case returns io.ErrUnexpectedEOF, which this reaches too
                    // because a truncated rune at the end of the buffer leaves no closing quote.
                    let (c, n) = decode_rune(&self.buf[self.pos..]);
                    out.push(c);
                    self.pos += n.max(1);
                }
            }
        }
    }

    /// One `\…` escape, appended to `out`.
    fn escape(&mut self, out: &mut String) -> Result<(), SyntaxError> {
        let start = self.pos;
        let Some(&kind) = self.buf.get(start + 1) else {
            return Err(SyntaxError::UnexpectedEof);
        };
        let simple = match kind {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            self.pos = start + 2;
            return Ok(());
        }
        if kind != b'u' {
            return Err(invalid_escape(self.buf, start, 2));
        }

        let hi = self.hex4(start)?;
        self.pos = start + 6;
        let code = if (0xd800..0xdc00).contains(&hi) {
            // A high surrogate pairs up only with an immediately following low surrogate.
            match self.low_surrogate() {
                Some(lo) => {
                    self.pos += 6;
                    0x10000 + ((u32::from(hi) - 0xd800) << 10) + (u32::from(lo) - 0xdc00)
                }
                None => u32::from(char::REPLACEMENT_CHARACTER),
            }
        } else if (0xdc00..0xe000).contains(&hi) {
            u32::from(char::REPLACEMENT_CHARACTER) // lone low surrogate
        } else {
            u32::from(hi)
        };
        out.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
        Ok(())
    }

    /// The four hex digits of the `\uXXXX` escape that starts at `esc`.
    fn hex4(&self, esc: usize) -> Result<u16, SyntaxError> {
        let mut v: u16 = 0;
        for i in 0..4 {
            match self.buf.get(esc + 2 + i) {
                // Go runs out of input before it can tell the escape is invalid.
                None => return Err(SyntaxError::UnexpectedEof),
                Some(&c) => match char::from(c).to_digit(16) {
                    Some(d) => v = v * 16 + d as u16,
                    None => return Err(invalid_escape(self.buf, esc, 6)),
                },
            }
        }
        Ok(v)
    }

    /// A `\uXXXX` low surrogate at the current position, if there is one.
    fn low_surrogate(&self) -> Option<u16> {
        if self.buf.get(self.pos) != Some(&b'\\') || self.buf.get(self.pos + 1) != Some(&b'u') {
            return None;
        }
        let lo = self.hex4(self.pos).ok()?;
        (0xdc00..0xe000).contains(&lo).then_some(lo)
    }
}

/// `invalid escape sequence <what> in string`, where `what` is up to `want` bytes from the
/// backslash (Go shows the whole `\uXXXX` when the hex digits are wrong, `\q` otherwise).
///
/// Known cosmetic difference: Go clips `what` at the end of `json.NewDecoder`'s read buffer,
/// which doubles from 512 bytes, so a `-c` file of exactly 65/129/257/513/1025/… bytes whose
/// malformed escape sits in its last six bytes prints one byte less than this does. That is an
/// artifact of Go's buffering, not of the document, and it is not reproduced (step 08.2).
// Go: encoding/json/internal/jsonwire/wire.go:NewInvalidEscapeSequenceError
fn invalid_escape(buf: &[u8], start: usize, want: usize) -> SyntaxError {
    let end = (start + want).min(buf.len());
    SyntaxError::Invalid(format!(
        "invalid escape sequence {} in string",
        quote_text(&buf[start..end])
    ))
}

// ---------------------------------------------------------------------------------------
// Go text quoting
// ---------------------------------------------------------------------------------------

/// Decodes the first rune of `b` like Go's `utf8.DecodeRune`: invalid encodings yield
/// `(U+FFFD, 1)`.
fn decode_rune(b: &[u8]) -> (char, usize) {
    if b.is_empty() {
        return (char::REPLACEMENT_CHARACTER, 0);
    }
    let len = match b[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (char::REPLACEMENT_CHARACTER, 1),
    };
    match b.get(..len).and_then(|s| std::str::from_utf8(s).ok()) {
        Some(s) => match s.chars().next() {
            Some(c) => (c, len),
            None => (char::REPLACEMENT_CHARACTER, 1),
        },
        None => (char::REPLACEMENT_CHARACTER, 1),
    }
}

/// `strconv.QuoteRune`: a single-quoted Go rune literal.
// Go: strconv/quote.go:QuoteRune
pub(crate) fn quote_rune(c: char) -> String {
    let mut out = String::with_capacity(4);
    out.push('\'');
    match c {
        '\'' => out.push_str("\\'"),
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
    out.push('\'');
    out
}

/// `jsonwire.QuoteRune`: the first rune of `b`, or `'\xNN'` when it is not valid UTF-8.
// Go: encoding/json/internal/jsonwire/wire.go:QuoteRune
fn quote_rune_bytes(b: &[u8]) -> String {
    match (decode_rune(b), b.first()) {
        // Go: `r == utf8.RuneError && n == 1` means the bytes are not valid UTF-8. A genuine
        // U+FFFD in the input decodes with n == 3 and is quoted normally.
        ((char::REPLACEMENT_CHARACTER, 1), Some(&first)) => format!("'\\x{first:x}'"),
        ((c, _), _) => quote_rune(c),
    }
}

/// How `jsonwire.InvalidTextError` renders the offending text: a single rune is quoted like a
/// rune, text that needs escaping is quoted like a string, and anything else gets backquotes.
// Go: encoding/json/internal/jsonwire/wire.go:(*InvalidTextError).Error
fn quote_text(what: &[u8]) -> String {
    // (rune, byte length, first byte) for each rune; an invalid byte has length 1.
    let mut runes = Vec::new();
    let mut i = 0;
    while i < what.len() {
        let (c, n) = decode_rune(&what[i..]);
        runes.push((c, n, what[i]));
        i += n;
    }
    if runes.len() == 1 {
        return quote_rune_bytes(what);
    }
    let invalid = |c: char, n: usize| c == char::REPLACEMENT_CHARACTER && n == 1;
    // Go ranges over the text as a Go string, so its `r == utf8.RuneError` test is also true
    // for a genuine, correctly encoded U+FFFD, not only for an invalid byte.
    let needs_escape = runes.iter().any(|&(c, _, _)| {
        c == '`' || c == char::REPLACEMENT_CHARACTER || c.is_whitespace() || !go_is_print(c)
    });
    if !needs_escape {
        return format!("`{}`", String::from_utf8_lossy(what));
    }
    let mut out = String::with_capacity(what.len() + 2);
    out.push('"');
    for &(c, n, byte) in &runes {
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
            // Go's strconv.Quote writes invalid UTF-8 byte by byte.
            _ if invalid(c, n) => {
                let _ = write!(out, "\\x{byte:02x}");
            }
            _ if go_is_print(c) => out.push(c),
            _ => {
                let v = u32::from(c);
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
