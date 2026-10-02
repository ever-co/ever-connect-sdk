//! Fixture round trip, Rust side: every schema-bound fixture of `contracts/fixtures/index.json`
//! is validated with the `jsonschema` crate against the same schema the TypeScript side uses
//! (ajv), every valid typed fixture deserializes into the generated type and serializes back to
//! the same document, and the verdicts are written to `target/fixture-verdicts/rust.json` for
//! `tools/test/fixtures-roundtrip.mjs` to compare with the TypeScript verdicts.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod typed;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jsonschema::{Draft, Registry, Resource, Validator};
use serde_json::{Value, json};

const CONTRACT: &str = "https://ever-connect-sdk.invalid/contract.json";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read(path: impl AsRef<Path>) -> Value {
    let path = repo().join(path);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Drops `null` members, so an omitted optional and an explicit null compare equal.
fn strip_nulls(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), strip_nulls(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(strip_nulls).collect()),
        other => other.clone(),
    }
}

struct Schemas {
    registry: Registry<'static>,
    pending: BTreeMap<String, Value>,
    docs: BTreeMap<&'static str, String>,
    events: BTreeMap<String, String>,
    envelope: String,
}

fn load() -> Schemas {
    let spec = read("contracts/generated/ever-platform.v1.json");
    let contract = json!({ "$schema": "https://json-schema.org/draft/2020-12/schema", "components": { "schemas": spec["components"]["schemas"] } });
    let mut resources: Vec<(String, Resource)> = vec![(
        CONTRACT.to_owned(),
        Draft::Draft202012.create_resource(contract),
    )];
    let mut docs = BTreeMap::new();
    for (key, file) in [
        ("stats", "ever.stats.v1.json"),
        ("entitlement", "ever.entitlement.v1.json"),
        ("consent", "ever.consent.v1.json"),
        ("keyManifest", "ever.key-manifest.v1.json"),
    ] {
        let schema = read(format!("contracts/schemas/{file}"));
        let id = schema["$id"].as_str().unwrap().to_owned();
        docs.insert(key, id.clone());
        resources.push((id, Draft::Draft202012.create_resource(schema)));
    }
    let mut events = BTreeMap::new();
    let mut envelope = String::new();
    let dir = repo().join("contracts/schemas/events");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for path in files {
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let id = schema["$id"].as_str().unwrap().to_owned();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name == "envelope.schema.json" {
            envelope = id.clone();
        } else if let Some(event_type) = name.strip_suffix(".v1.schema.json") {
            events.insert(event_type.to_owned(), id.clone());
        }
        resources.push((id, Draft::Draft202012.create_resource(schema)));
    }
    let registry = Registry::new()
        .extend(resources)
        .unwrap()
        .prepare()
        .unwrap();
    let mut pending = BTreeMap::new();
    for op in read("contracts/openapi/pending-upstream.json")["operations"]
        .as_array()
        .unwrap()
    {
        if !op["request"].is_null() {
            pending.insert(
                op["operation_id"].as_str().unwrap().to_owned(),
                op["request"].clone(),
            );
        }
    }
    Schemas {
        registry,
        pending,
        docs,
        events,
        envelope,
    }
}

fn validator(schemas: &Schemas, schema: &Value) -> Validator {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_registry(&schemas.registry)
        .build(schema)
        .unwrap_or_else(|e| panic!("cannot compile {schema}: {e}"))
}

fn by_ref(schemas: &Schemas, uri: &str) -> Validator {
    validator(schemas, &json!({ "$ref": uri }))
}

#[test]
fn fixtures_roundtrip() {
    let schemas = load();
    let index = read("contracts/fixtures/index.json");
    let mut verdicts = BTreeMap::new();
    let mut problems = Vec::new();
    for entry in index["fixtures"].as_array().unwrap() {
        let file = entry["file"].as_str().unwrap();
        let kind = entry["kind"].as_str().unwrap();
        let schema = entry["schema"].as_str().unwrap();
        let expected = entry["valid"].as_bool().unwrap();
        let typed_expected = entry["typed"].as_bool().unwrap();
        let doc = read(format!("contracts/fixtures/{file}"));
        let valid = match kind {
            "component" => by_ref(
                &schemas,
                &format!("{CONTRACT}#/components/schemas/{schema}"),
            )
            .is_valid(&doc),
            "pending" => validator(&schemas, &schemas.pending[schema]).is_valid(&doc),
            "schema" => by_ref(&schemas, &schemas.docs[schema]).is_valid(&doc),
            "feed" => {
                let page = by_ref(
                    &schemas,
                    &format!("{CONTRACT}#/components/schemas/FeedResponse"),
                )
                .is_valid(&doc);
                let envelope = by_ref(&schemas, &schemas.envelope);
                let data = by_ref(&schemas, &schemas.events[schema]);
                page && doc["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|e| envelope.is_valid(e) && data.is_valid(&e["data"]))
            }
            other => panic!("{file}: unknown kind {other}"),
        };
        verdicts.insert(file.to_owned(), valid);
        if valid != expected {
            problems.push(format!(
                "{file}: jsonschema says valid={valid}, the index says {expected}"
            ));
        }
        if typed_expected {
            let results: Vec<(Value, Option<Result<Value, String>>)> = match kind {
                "component" => vec![(doc.clone(), typed::component(schema, &doc))],
                "schema" => vec![(doc.clone(), typed::schema(schema, &doc))],
                "feed" => {
                    let mut out = vec![(doc.clone(), typed::component("FeedResponse", &doc))];
                    for e in doc["events"].as_array().unwrap() {
                        out.push((e["data"].clone(), typed::event(schema, &e["data"])));
                    }
                    out
                }
                _ => vec![],
            };
            for (original, result) in results {
                match result {
                    None => problems.push(format!("{file}: no generated type for {kind} {schema}")),
                    Some(Err(e)) => problems.push(format!(
                        "{file}: does not deserialize into the generated type: {e}"
                    )),
                    Some(Ok(back)) => {
                        if strip_nulls(&back) != strip_nulls(&original) {
                            problems.push(format!("{file}: the typed round trip changed the document:\n  in:  {original}\n  out: {back}"));
                        }
                    }
                }
            }
        }
    }
    let out_dir = repo().join("target").join("fixture-verdicts");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        out_dir.join("rust.json"),
        serde_json::to_string_pretty(&verdicts).unwrap(),
    )
    .unwrap();
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
