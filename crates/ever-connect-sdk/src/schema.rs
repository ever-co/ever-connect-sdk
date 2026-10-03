//! A JSON Schema (2020-12) checker for the keywords the contract schemas use: `type`,
//! `properties`, `required`, `additionalProperties`, `propertyNames`, `minProperties` and
//! `maxProperties`, `enum`, `const`, `pattern`, `minLength` and `maxLength`, `minimum` and
//! `maximum`, `items`, `minItems` and `maxItems`, `uniqueItems`, `oneOf`, `anyOf`, `allOf`,
//! `not`, `if`/`then`/`else` and `$ref` into the same document. Annotations (`format`,
//! `description`, `title`, `$id`) are ignored, as the specification says. Every violation has its
//! JSON pointer and a kind, never the value checked. The TypeScript package carries the same
//! checker, so both languages give a document the same answer.

// Shared by several features: with only some of them, part of this module is unused.
#![cfg_attr(not(feature = "client"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock, PoisonError};

use serde_json::{Map, Value};

/// The JSON pointer of `key` under `path`.
pub(crate) fn child(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// What kind of rule a value broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kind {
    UnknownField,
    Type,
    Pattern,
    Range,
    Required,
    Shape,
}

/// One reason a value does not validate; the message never repeats the value.
#[derive(Debug, Clone)]
pub(crate) struct Violation {
    pub(crate) path: String,
    pub(crate) kind: Kind,
    pub(crate) message: String,
}

fn regex(pattern: &str) -> Option<fancy_regex::Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<fancy_regex::Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    let mut cache = cache.lock().unwrap_or_else(PoisonError::into_inner);
    cache
        .entry(pattern.to_owned())
        .or_insert_with(|| fancy_regex::Regex::new(pattern).ok())
        .clone()
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => {
            value.is_i64()
                || value.is_u64()
                || value
                    .as_f64()
                    .is_some_and(|f| f.fract() == 0.0 && f.is_finite())
        }
        _ => false,
    }
}

/// A checker over one schema document (`$ref`s resolve inside it).
pub(crate) struct Checker<'a> {
    root: &'a Value,
}

impl<'a> Checker<'a> {
    /// A checker whose `$ref`s resolve in `root`.
    pub(crate) const fn new(root: &'a Value) -> Self {
        Self { root }
    }

    fn resolve(&self, reference: &str) -> Option<&Value> {
        let (document, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        if !document.is_empty() {
            return None;
        }
        if fragment.is_empty() {
            Some(self.root)
        } else {
            self.root.pointer(fragment)
        }
    }

    pub(crate) fn fails(&self, schema: &Value, value: &Value) -> bool {
        let mut scratch = Vec::new();
        self.check(schema, value, "", &mut scratch);
        !scratch.is_empty()
    }

    pub(crate) fn check(&self, schema: &Value, value: &Value, at: &str, out: &mut Vec<Violation>) {
        let Some(schema) = schema.as_object() else {
            if schema == &Value::Bool(false) {
                out.push(violation(
                    at,
                    Kind::UnknownField,
                    "no value is allowed here",
                ));
            }
            return;
        };
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            match self.resolve(reference) {
                Some(target) => self.check(target, value, at, out),
                None => out.push(violation(at, Kind::Shape, "unresolvable reference")),
            }
        }
        let mut push = |kind: Kind, message: String| {
            out.push(Violation {
                path: at.to_owned(),
                kind,
                message,
            });
        };
        match schema.get("type") {
            Some(Value::String(expected)) if !type_matches(expected, value) => {
                push(Kind::Type, format!("expected {expected}"));
                return;
            }
            Some(Value::Array(options))
                if !options
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|t| type_matches(t, value)) =>
            {
                push(Kind::Type, "matches none of the allowed types".into());
                return;
            }
            _ => {}
        }
        if let Some(options) = schema.get("enum").and_then(Value::as_array)
            && !options.contains(value)
        {
            push(Kind::Pattern, "not one of the allowed values".into());
        }
        if let Some(expected) = schema.get("const")
            && expected != value
        {
            push(Kind::Pattern, "not the required constant".into());
        }
        if let Value::String(text) = value {
            let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
            if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
                && length > max
            {
                push(Kind::Pattern, format!("longer than {max} characters"));
            }
            if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
                && length < min
            {
                push(Kind::Pattern, format!("shorter than {min} characters"));
            }
            if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                match regex(pattern) {
                    Some(compiled) if compiled.is_match(text).unwrap_or(false) => {}
                    Some(_) => push(Kind::Pattern, "does not match the pattern".into()),
                    None => push(Kind::Shape, "the pattern does not compile".into()),
                }
            }
        }
        if let Some(number) = value.as_f64() {
            if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
                && number < min
            {
                push(Kind::Range, format!("below the minimum {min}"));
            }
            if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
                && number > max
            {
                push(Kind::Range, format!("above the maximum {max}"));
            }
        }
        if let Value::Array(items) = value {
            let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
                && count > max
            {
                push(Kind::Range, format!("more than {max} items"));
            }
            if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
                && count < min
            {
                push(Kind::Range, format!("fewer than {min} items"));
            }
            if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true)
                && items
                    .iter()
                    .enumerate()
                    .any(|(i, item)| items[..i].contains(item))
            {
                push(Kind::Range, "items are not unique".into());
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    self.check(item_schema, item, &child(at, &index.to_string()), out);
                }
            }
        }
        if let Value::Object(fields) = value {
            self.check_object(schema, fields, at, out);
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            for sub in all {
                self.check(sub, value, at, out);
            }
        }
        if let Some(any) = schema.get("anyOf").and_then(Value::as_array)
            && any.iter().all(|sub| self.fails(sub, value))
        {
            out.push(violation(at, Kind::Shape, "matches none of anyOf"));
        }
        if let Some(one) = schema.get("oneOf").and_then(Value::as_array) {
            let matching = one.iter().filter(|sub| !self.fails(sub, value)).count();
            if matching != 1 {
                out.push(Violation {
                    path: at.to_owned(),
                    kind: Kind::Shape,
                    message: format!("matches {matching} of oneOf, not exactly one"),
                });
            }
        }
        if let Some(negated) = schema.get("not")
            && !self.fails(negated, value)
        {
            out.push(violation(
                at,
                Kind::Shape,
                "matches a schema it must not match",
            ));
        }
        if let Some(condition) = schema.get("if") {
            let branch = if self.fails(condition, value) {
                schema.get("else")
            } else {
                schema.get("then")
            };
            if let Some(branch) = branch {
                self.check(branch, value, at, out);
            }
        }
    }

    fn check_object(
        &self,
        schema: &Map<String, Value>,
        fields: &Map<String, Value>,
        at: &str,
        out: &mut Vec<Violation>,
    ) {
        let count = u64::try_from(fields.len()).unwrap_or(u64::MAX);
        if let Some(max) = schema.get("maxProperties").and_then(Value::as_u64)
            && count > max
        {
            out.push(Violation {
                path: at.to_owned(),
                kind: Kind::Range,
                message: format!("more than {max} properties"),
            });
        }
        if let Some(min) = schema.get("minProperties").and_then(Value::as_u64)
            && count < min
        {
            out.push(Violation {
                path: at.to_owned(),
                kind: Kind::Range,
                message: format!("fewer than {min} properties"),
            });
        }
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !fields.contains_key(name) {
                    out.push(violation(&child(at, name), Kind::Required, "required"));
                }
            }
        }
        let names = schema.get("propertyNames");
        let properties = schema.get("properties").and_then(Value::as_object);
        let mut keys: Vec<&String> = fields.keys().collect();
        keys.sort();
        for name in keys {
            let field = &fields[name];
            let here = child(at, name);
            if let Some(name_schema) = names
                && self.fails(name_schema, &Value::String(name.clone()))
            {
                out.push(violation(
                    &here,
                    Kind::UnknownField,
                    "this key is not allowed here",
                ));
                continue;
            }
            match properties.and_then(|p| p.get(name)) {
                Some(field_schema) => self.check(field_schema, field, &here, out),
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => out.push(violation(
                        &here,
                        Kind::UnknownField,
                        "not allowed (the object is closed)",
                    )),
                    Some(extra @ Value::Object(_)) => self.check(extra, field, &here, out),
                    _ => {}
                },
            }
        }
    }
}

pub(crate) fn violation(at: &str, kind: Kind, message: &str) -> Violation {
    Violation {
        path: at.to_owned(),
        kind,
        message: message.to_owned(),
    }
}

/// Every violation of `value` against `schema` (resolved in `root`), one per (path, kind), sorted
/// by path and kind (byte order).
pub(crate) fn violations(root: &Value, value: &Value, schema: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    Checker::new(root).check(schema, value, "", &mut out);
    let mut seen = HashSet::new();
    out.retain(|v| seen.insert((v.path.clone(), v.kind)));
    out.sort_by(|a, b| {
        (a.path.as_bytes(), a.kind.as_str()).cmp(&(b.path.as_bytes(), b.kind.as_str()))
    });
    out
}

impl Kind {
    /// The spelling the TypeScript checker uses.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownField => "unknown_field",
            Self::Type => "type",
            Self::Pattern => "pattern",
            Self::Range => "range",
            Self::Required => "required",
            Self::Shape => "shape",
        }
    }
}
