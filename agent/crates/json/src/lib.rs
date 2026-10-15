//! Strict bounded JSON reader and canonical writer for the agent's
//! configuration file and health document.
//!
//! The reader accepts the RFC 8259 grammar under the project's strict profile
//! (docs/specs/agent-runtime.md section 3): UTF-8 without a byte-order mark, at
//! most [`MAX_INPUT_BYTES`] bytes, nesting depth at most [`MAX_DEPTH`], objects
//! with unique keys (compared after unescaping), integers within `i64` with no
//! fraction or exponent, no `NaN` or `Infinity`, no bytes after the value
//! other than whitespace, and strings without unpaired surrogates.
//!
//! The writer produces the canonical form: object keys sorted by their UTF-8
//! bytes (equal to Unicode code point order), no whitespace, and the shortest
//! escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other control characters
//! as a lowercase six-character `\u00xx` escape, every other character
//! written as UTF-8).
//!
//! This crate has no dependencies and no unsafe code. It serves the
//! configuration file and the health document only.

use std::collections::BTreeMap;
use std::fmt;

/// Largest accepted input in bytes.
pub const MAX_INPUT_BYTES: usize = 65_536;
/// Deepest accepted nesting of arrays and objects; a scalar has depth zero.
pub const MAX_DEPTH: usize = 8;

/// A parsed JSON value under the strict profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer within `i64`; `-0` reads as `0`.
    Integer(i64),
    /// A string, already unescaped.
    String(String),
    /// An array in document order.
    Array(Vec<Value>),
    /// An object; keys are unique and iterate in canonical (byte) order.
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// Returns the member `key` when `self` is an object holding it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|members| members.get(key))
    }

    /// Returns the members when `self` is an object.
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    /// Returns the items when `self` is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the text when `self` is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the integer when `self` is an integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the boolean when `self` is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// A rejected input, with the byte offset where the reader stopped.
///
/// Precedence: [`Error::TooLarge`] is decided from the length alone, then
/// [`Error::ByteOrderMark`], then [`Error::Utf8`] over the whole input, then
/// the grammar from the first byte onward, so the first offending byte in
/// document order decides among the remaining variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input is not valid UTF-8; `offset` is the first invalid byte.
    Utf8 {
        /// Byte offset.
        offset: usize,
    },
    /// The input starts with a UTF-8 byte-order mark.
    ByteOrderMark {
        /// Byte offset, always 0.
        offset: usize,
    },
    /// The input is longer than [`MAX_INPUT_BYTES`]; `offset` is the limit.
    TooLarge {
        /// Byte offset.
        offset: usize,
    },
    /// An array or object opens deeper than [`MAX_DEPTH`].
    TooDeep {
        /// Byte offset of the opening bracket.
        offset: usize,
    },
    /// An object repeats a key; `offset` is the repeated key's opening quote.
    DuplicateKey {
        /// Byte offset.
        offset: usize,
    },
    /// The input breaks the JSON grammar.
    Syntax {
        /// Byte offset.
        offset: usize,
    },
    /// A number has a fraction or exponent.
    NumberFormat {
        /// Byte offset of the `.`, `e` or `E`.
        offset: usize,
    },
    /// An integer lies outside `i64`; `offset` is the number's first byte.
    NumberRange {
        /// Byte offset.
        offset: usize,
    },
    /// Non-whitespace bytes follow the value.
    Trailing {
        /// Byte offset of the first such byte.
        offset: usize,
    },
    /// A `\u` escape forms an unpaired surrogate.
    Surrogate {
        /// Byte offset of the escape's backslash.
        offset: usize,
    },
    /// A string contains an unescaped control character (below U+0020).
    Control {
        /// Byte offset.
        offset: usize,
    },
}

impl Error {
    /// The byte offset where the reader stopped.
    pub fn offset(&self) -> usize {
        match *self {
            Error::Utf8 { offset }
            | Error::ByteOrderMark { offset }
            | Error::TooLarge { offset }
            | Error::TooDeep { offset }
            | Error::DuplicateKey { offset }
            | Error::Syntax { offset }
            | Error::NumberFormat { offset }
            | Error::NumberRange { offset }
            | Error::Trailing { offset }
            | Error::Surrogate { offset }
            | Error::Control { offset } => offset,
        }
    }

    /// The variant name, as the shared vectors spell it.
    pub fn name(&self) -> &'static str {
        match self {
            Error::Utf8 { .. } => "Utf8",
            Error::ByteOrderMark { .. } => "ByteOrderMark",
            Error::TooLarge { .. } => "TooLarge",
            Error::TooDeep { .. } => "TooDeep",
            Error::DuplicateKey { .. } => "DuplicateKey",
            Error::Syntax { .. } => "Syntax",
            Error::NumberFormat { .. } => "NumberFormat",
            Error::NumberRange { .. } => "NumberRange",
            Error::Trailing { .. } => "Trailing",
            Error::Surrogate { .. } => "Surrogate",
            Error::Control { .. } => "Control",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON {} at byte {}", self.name(), self.offset())
    }
}

impl std::error::Error for Error {}

/// Parses `input` under the strict profile.
///
/// The input is never modified. Memory use is bounded by the input length,
/// which is at most [`MAX_INPUT_BYTES`], and recursion by [`MAX_DEPTH`].
pub fn parse(input: &[u8]) -> Result<Value, Error> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge {
            offset: MAX_INPUT_BYTES,
        });
    }
    if input.starts_with(b"\xef\xbb\xbf") {
        return Err(Error::ByteOrderMark { offset: 0 });
    }
    let text = std::str::from_utf8(input).map_err(|e| Error::Utf8 {
        offset: e.valid_up_to(),
    })?;
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    reader.skip_whitespace();
    let value = reader.value(0)?;
    reader.skip_whitespace();
    if reader.at < reader.bytes.len() {
        return Err(Error::Trailing { offset: reader.at });
    }
    Ok(value)
}

/// Encodes `value` in canonical form.
///
/// The output is valid UTF-8 JSON. It re-parses to an equal value when its
/// nesting and length stay within [`MAX_DEPTH`] and [`MAX_INPUT_BYTES`]; the
/// writer itself applies neither limit.
pub fn encode(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Integer(n) => out.push_str(&n.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (index, (key, item)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX[code >> 4]));
                out.push(char::from(HEX[code & 0xf]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn syntax(&self) -> Error {
        Error::Syntax { offset: self.at }
    }

    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.syntax())
        }
    }

    /// Reads one value; `depth` is the number of enclosing containers.
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.syntax()),
        }
    }

    fn enter(&self, depth: usize) -> Result<usize, Error> {
        let inner = depth + 1;
        if inner > MAX_DEPTH {
            Err(Error::TooDeep { offset: self.at })
        } else {
            Ok(inner)
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        let inner = self.enter(depth)?;
        self.at += 1;
        let mut members = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.syntax());
            }
            let key_offset = self.at;
            let key = self.string()?;
            if members.contains_key(&key) {
                return Err(Error::DuplicateKey { offset: key_offset });
            }
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let item = self.value(inner)?;
            members.insert(key, item);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        let inner = self.enter(depth)?;
        self.at += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(inner)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, Error> {
        for &expected in word {
            if self.peek() != Some(expected) {
                return Err(self.syntax());
            }
            self.at += 1;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let digits_start = self.at;
        match self.peek() {
            Some(b'0') => {
                self.at += 1;
                if let Some(b'0'..=b'9') = self.peek() {
                    return Err(self.syntax());
                }
            }
            Some(b'1'..=b'9') => {
                while let Some(b'0'..=b'9') = self.peek() {
                    self.at += 1;
                }
            }
            _ => return Err(self.syntax()),
        }
        if let Some(b'.' | b'e' | b'E') = self.peek() {
            return Err(Error::NumberFormat { offset: self.at });
        }
        // Accumulate toward the sign so i64::MIN is representable.
        let mut n: i64 = 0;
        for &digit in &self.bytes[digits_start..self.at] {
            let d = i64::from(digit - b'0');
            n = n
                .checked_mul(10)
                .and_then(|n| {
                    if negative {
                        n.checked_sub(d)
                    } else {
                        n.checked_add(d)
                    }
                })
                .ok_or(Error::NumberRange { offset: start })?;
        }
        Ok(Value::Integer(n))
    }

    /// Reads a string starting at its opening quote.
    fn string(&mut self) -> Result<String, Error> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let run_start = self.at;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.at += 1;
            }
            // The input was validated as UTF-8 and the run ends before an
            // ASCII byte or at the end, so it is a whole-character slice.
            match std::str::from_utf8(&self.bytes[run_start..self.at]) {
                Ok(run) => out.push_str(run),
                Err(_) => return Err(Error::Utf8 { offset: run_start }),
            }
            match self.peek() {
                None => return Err(self.syntax()),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => self.escape(&mut out)?,
                Some(_) => return Err(Error::Control { offset: self.at }),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), Error> {
        let backslash = self.at;
        self.at += 1;
        let c = match self.peek() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.at += 1;
                let unit = self.hex4()?;
                let c = match unit {
                    0xd800..=0xdbff => {
                        if self.peek() != Some(b'\\') || self.bytes.get(self.at + 1) != Some(&b'u')
                        {
                            return Err(Error::Surrogate { offset: backslash });
                        }
                        self.at += 2;
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(Error::Surrogate { offset: backslash });
                        }
                        let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        char::from_u32(code).ok_or(Error::Surrogate { offset: backslash })?
                    }
                    0xdc00..=0xdfff => return Err(Error::Surrogate { offset: backslash }),
                    _ => char::from_u32(unit).ok_or(Error::Surrogate { offset: backslash })?,
                };
                out.push(c);
                return Ok(());
            }
            _ => return Err(self.syntax()),
        };
        self.at += 1;
        out.push(c);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut unit = 0u32;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(b @ b'0'..=b'9') => b - b'0',
                Some(b @ b'a'..=b'f') => b - b'a' + 10,
                Some(b @ b'A'..=b'F') => b - b'A' + 10,
                _ => return Err(self.syntax()),
            };
            unit = (unit << 4) | u32::from(digit);
            self.at += 1;
        }
        Ok(unit)
    }
}
