//! The checks Ever Platform runs on a statistics report body, in its order and with its answers:
//! the size limit, a strict JSON reader, the published schema in two passes (the envelope without
//! the per-product `oneOf`, then the product's own lists) and the calendar date of `sent_at`.
//!
//! The schema checks cover the JSON Schema keywords the statistics schema uses. Field errors are
//! sorted by path and code (byte order), one per (path, code), at most [`MAX_ERRORS`].

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use serde_json::{Map, Number, Value};

use super::{ErrorCode, FieldError, MAX_REPORT_BYTES, StatsRefusal};
use crate::schema::{Checker, Kind, child};

/// The deepest nesting a report may have (the schema needs four levels).
pub const MAX_DEPTH: usize = 16;

/// The most field errors one refusal lists.
pub const MAX_ERRORS: usize = 20;

// ------------------------------------------------------------------------------- strict JSON

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffenceKind {
    Syntax,
    Fraction,
    OutOfRange,
    DuplicateKey,
}

#[derive(Debug)]
struct Offence {
    path: String,
    kind: OffenceKind,
}

impl Offence {
    fn field_error(self) -> FieldError {
        let (code, message) = match self.kind {
            OffenceKind::Syntax => (
                ErrorCode::Type,
                "the body is not a JSON document of the expected shape",
            ),
            OffenceKind::Fraction => (
                ErrorCode::Type,
                "numbers are integers: no fraction, no exponent",
            ),
            OffenceKind::OutOfRange => (ErrorCode::Range, "the integer is out of range"),
            OffenceKind::DuplicateKey => (
                ErrorCode::DuplicateKey,
                "a key may appear once in an object",
            ),
        };
        FieldError {
            path: self.path,
            code,
            message: message.to_owned(),
        }
    }
}

fn syntax(path: &str) -> Offence {
    Offence {
        path: path.to_owned(),
        kind: OffenceKind::Syntax,
    }
}

/// Parses a body strictly: RFC 8259, plus no number with a fraction or an exponent, no integer
/// outside 64 bits, no key twice in one object and at most [`MAX_DEPTH`] levels.
fn strict_parse(body: &[u8]) -> Result<Value, Offence> {
    let text = std::str::from_utf8(body).map_err(|_| syntax(""))?;
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    reader.whitespace();
    let value = reader.value("", 0)?;
    reader.whitespace();
    if reader.at == reader.bytes.len() {
        Ok(value)
    } else {
        Err(syntax(""))
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8], value: Value, path: &str) -> Result<Value, Offence> {
        if self.bytes.get(self.at..self.at + word.len()) == Some(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(syntax(path))
        }
    }

    fn value(&mut self, path: &str, depth: usize) -> Result<Value, Offence> {
        if depth > MAX_DEPTH {
            return Err(syntax(path));
        }
        match self.peek() {
            Some(b'{') => self.object(path, depth),
            Some(b'[') => self.array(path, depth),
            Some(b'"') => self.string(path).map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true), path),
            Some(b'f') => self.literal(b"false", Value::Bool(false), path),
            Some(b'n') => self.literal(b"null", Value::Null, path),
            Some(b'-' | b'0'..=b'9') => self.number(path),
            _ => Err(syntax(path)),
        }
    }

    fn object(&mut self, path: &str, depth: usize) -> Result<Value, Offence> {
        self.at += 1;
        let mut map = Map::new();
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return Err(syntax(path));
            }
            let key = self.string(path)?;
            let here = child(path, &key);
            self.whitespace();
            if self.peek() != Some(b':') {
                return Err(syntax(path));
            }
            self.at += 1;
            self.whitespace();
            let value = self.value(&here, depth + 1)?;
            if map.contains_key(&key) {
                return Err(Offence {
                    path: here,
                    kind: OffenceKind::DuplicateKey,
                });
            }
            map.insert(key, value);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(syntax(path)),
            }
        }
    }

    fn array(&mut self, path: &str, depth: usize) -> Result<Value, Offence> {
        self.at += 1;
        let mut items = Vec::new();
        self.whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.whitespace();
            let here = child(path, &items.len().to_string());
            items.push(self.value(&here, depth + 1)?);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(syntax(path)),
            }
        }
    }

    fn hex4(&mut self, path: &str) -> Result<u32, Offence> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| syntax(path))?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(syntax(path));
        }
        let text = std::str::from_utf8(digits).map_err(|_| syntax(path))?;
        let value = u32::from_str_radix(text, 16).map_err(|_| syntax(path))?;
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self, path: &str) -> Result<String, Offence> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.at += 1;
            }
            // The text is UTF-8 and the run stops at an ASCII byte, so the slice is UTF-8 too.
            out.push_str(
                std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| syntax(path))?,
            );
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = self.peek().ok_or_else(|| syntax(path))?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4(path)?;
                            let scalar = if (0xD800..0xDC00).contains(&first) {
                                if self.bytes.get(self.at..self.at + 2) != Some(b"\\u") {
                                    return Err(syntax(path));
                                }
                                self.at += 2;
                                let second = self.hex4(path)?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return Err(syntax(path));
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            out.push(char::from_u32(scalar).ok_or_else(|| syntax(path))?);
                        }
                        _ => return Err(syntax(path)),
                    }
                }
                _ => return Err(syntax(path)),
            }
        }
    }

    fn number(&mut self, path: &str) -> Result<Value, Offence> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(syntax(path)),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(Offence {
                path: path.to_owned(),
                kind: OffenceKind::Fraction,
            });
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| syntax(path))?;
        let out_of_range = || Offence {
            path: path.to_owned(),
            kind: OffenceKind::OutOfRange,
        };
        if text.starts_with('-') {
            text.parse::<i64>()
                .map(|n| Value::Number(Number::from(n)))
                .map_err(|_| out_of_range())
        } else {
            text.parse::<u64>()
                .map(|n| Value::Number(Number::from(n)))
                .map_err(|_| out_of_range())
        }
    }
}

/// The field errors of a parsed report against a statistics schema (sorted, one per path and
/// code, at most [`MAX_ERRORS`]).
pub(crate) fn schema_errors(schema: &Value, document: &Value) -> Vec<FieldError> {
    let checker = Checker::new(schema);
    let mut envelope = schema.clone();
    if let Some(map) = envelope.as_object_mut() {
        map.remove("oneOf");
    }
    let mut found = Vec::new();
    checker.check(&envelope, document, "", &mut found);
    let products: Vec<&str> = schema
        .pointer("/properties/product/enum")
        .and_then(Value::as_array)
        .map(|v| v.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(product) = document.get("product").and_then(Value::as_str)
        && products.contains(&product)
        && let Some(lists) = schema.get("$defs").and_then(|d| d.get(product))
    {
        for section in ["counts", "features", "aggregates"] {
            if let (Some(value @ Value::Object(_)), Some(section_schema)) =
                (document.get(section), lists.get(section))
            {
                checker.check(section_schema, value, &format!("/{section}"), &mut found);
            }
        }
    }
    let mut seen = HashSet::new();
    let mut errors: Vec<FieldError> = Vec::new();
    for v in found {
        let code = if v.path == "/schema" && v.kind != Kind::Required {
            ErrorCode::SchemaUnknown
        } else {
            match v.kind {
                Kind::UnknownField => ErrorCode::UnknownField,
                Kind::Type | Kind::Shape => ErrorCode::Type,
                Kind::Pattern => ErrorCode::Pattern,
                Kind::Range => ErrorCode::Range,
                Kind::Required => ErrorCode::Required,
            }
        };
        if seen.insert((v.path.clone(), code)) {
            errors.push(FieldError {
                path: v.path,
                code,
                message: v.message,
            });
        }
    }
    errors.sort_by(|a, b| (&a.path, a.code.as_str()).cmp(&(&b.path, b.code.as_str())));
    errors.truncate(MAX_ERRORS);
    errors
}

/// Whether `YYYY-MM-DD` names a day that exists.
#[must_use]
pub fn is_calendar_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        text[0..4].parse::<u32>(),
        text[5..7].parse::<u32>(),
        text[8..10].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Runs the platform's checks on report bytes against a statistics schema.
pub(crate) fn check_bytes(schema: &Value, body: &[u8]) -> Result<Value, StatsRefusal> {
    if body.len() > MAX_REPORT_BYTES {
        return Err(StatsRefusal::new(
            413,
            "validation_failed",
            vec![FieldError {
                path: String::new(),
                code: ErrorCode::TooLarge,
                message: format!("the body is larger than {MAX_REPORT_BYTES} bytes"),
            }],
        ));
    }
    let document = strict_parse(body)
        .map_err(|o| StatsRefusal::new(422, "schema_violation", vec![o.field_error()]))?;
    let mut errors = schema_errors(schema, &document);
    if errors.is_empty()
        && !document
            .get("sent_at")
            .and_then(Value::as_str)
            .is_some_and(is_calendar_date)
    {
        errors.push(FieldError {
            path: "/sent_at".into(),
            code: ErrorCode::Range,
            message: "not a calendar date".into(),
        });
    }
    if errors.is_empty() {
        Ok(document)
    } else {
        Err(StatsRefusal::new(422, "schema_violation", errors))
    }
}

/// Every property name a schema declares, anywhere.
fn vocabulary(schema: &Value) -> BTreeSet<String> {
    fn collect(node: &Value, words: &mut BTreeSet<String>) {
        match node {
            Value::Object(map) => {
                if let Some(Value::Object(properties)) = map.get("properties") {
                    words.extend(properties.keys().cloned());
                }
                for value in map.values() {
                    collect(value, words);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect(item, words);
                }
            }
            _ => {}
        }
    }
    let mut words = BTreeSet::new();
    collect(schema, &mut words);
    words
}

/// A field path fit for a log line: a segment stays when the schema names it, or it is a currency
/// code or an array index; any other segment (an unknown key) becomes `*`.
pub(crate) fn redact_path(schema: &Value, path: &str) -> String {
    static WORDS: OnceLock<BTreeSet<String>> = OnceLock::new();
    let words = WORDS.get_or_init(|| vocabulary(schema));
    path.split('/')
        .skip(1)
        .map(|raw| {
            let segment = raw.replace("~1", "/").replace("~0", "~");
            let currency = segment.len() == 3 && segment.bytes().all(|b| b.is_ascii_uppercase());
            let index = !segment.is_empty()
                && segment.len() <= 2
                && segment.bytes().all(|b| b.is_ascii_digit());
            if currency || index || words.contains(&segment) {
                format!("/{raw}")
            } else {
                "/*".to_owned()
            }
        })
        .collect()
}
