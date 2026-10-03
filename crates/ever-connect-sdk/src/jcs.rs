//! RFC 8785 canonical JSON (JCS) for the shapes the key manifest needs: objects, arrays,
//! strings, booleans, nulls and integers. Member names sort by their UTF-16 code units, strings
//! are written as ECMAScript `JSON.stringify` writes them. A number with a fraction is refused
//! rather than written in a form the platform would not write.

use std::fmt::Write as _;

use serde_json::Value;

/// A value [`canonical_json`] cannot write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotCanonical;

impl std::fmt::Display for NotCanonical {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("canonical JSON: only integers are supported")
    }
}

impl std::error::Error for NotCanonical {}

/// The canonical JSON text of `value`.
///
/// # Errors
/// [`NotCanonical`] for a number that is not an integer.
pub fn canonical_json(value: &Value) -> Result<String, NotCanonical> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), NotCanonical> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let _ = write!(out, "{i}");
            } else if let Some(u) = n.as_u64() {
                let _ = write!(out, "{u}");
            } else {
                return Err(NotCanonical);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut names: Vec<&String> = map.keys().collect();
            names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, name) in names.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(&map[name], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string as ECMAScript `JSON.stringify` writes it (the string rules of RFC 8785).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::canonical_json;

    #[test]
    fn members_sort_by_utf16_and_strings_escape_as_ecmascript_does() {
        let v = json!({"b": [1, true, null], "a": "x\u{1}\"\\\n", "\u{e9}": 0, "\u{1f600}": -2, "\u{ff61}": 3});
        assert_eq!(
            canonical_json(&v).unwrap(),
            "{\"a\":\"x\\u0001\\\"\\\\\\n\",\"b\":[1,true,null],\"\u{e9}\":0,\"\u{1f600}\":-2,\"\u{ff61}\":3}"
        );
        assert!(canonical_json(&json!(1.5)).is_err());
    }
}
