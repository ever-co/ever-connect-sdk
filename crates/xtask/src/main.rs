//! Repository tasks of the Ever Connect SDK.
//!
//! `cargo run -p xtask -- typify <input.json> <output-dir>` turns the prepared schema bundle that
//! `tools/generate.mjs` writes into Rust types: one output file per bundle file, one module per
//! schema document inside it. The bundle is `{"files": [{"file": "openapi.rs", "modules":
//! [{"name": "...", "definitions": {"Name": <schema>}}]}]}`; references inside a module point at
//! `#/definitions/<Name>`. The output is formatted with `prettyplease`, so two runs are identical.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use schemars::schema::Schema;
use serde_json::Value;
use typify::{TypeSpace, TypeSpaceSettings};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, input, output] if cmd == "typify" => match typify_bundle(input, output) {
            Ok(written) => {
                for file in written {
                    eprintln!("xtask typify: wrote {file}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("xtask typify: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: cargo run -p xtask -- typify <input.json> <output-dir>");
            ExitCode::from(2)
        }
    }
}

fn typify_bundle(input: &str, output: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(input).map_err(|e| format!("cannot read {input}: {e}"))?;
    let bundle: Value = serde_json::from_str(&text).map_err(|e| format!("{input}: {e}"))?;
    let files = bundle
        .get("files")
        .and_then(Value::as_array)
        .ok_or("the bundle has no files array")?;
    let mut written = Vec::new();
    for file in files {
        let name = file
            .get("file")
            .and_then(Value::as_str)
            .ok_or("a bundle file has no name")?;
        let header = file.get("header").and_then(Value::as_str).unwrap_or("");
        let modules = file
            .get("modules")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{name}: no modules"))?;
        let mut source = String::new();
        source.push_str(header);
        for module in modules {
            let module_name = module
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{name}: a module has no name"))?;
            let doc = module.get("doc").and_then(Value::as_str).unwrap_or("");
            let code = typify_module(module_name, module)?;
            let _ = writeln!(source);
            for line in doc.lines() {
                let _ = writeln!(source, "/// {line}");
            }
            let _ = writeln!(source, "pub mod {module_name} {{");
            for line in code.lines() {
                if line.is_empty() {
                    source.push('\n');
                } else {
                    let _ = writeln!(source, "    {line}");
                }
            }
            let _ = writeln!(source, "}}");
        }
        let path = PathBuf::from(output).join(name);
        std::fs::write(&path, source)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        written.push(path.display().to_string());
    }
    Ok(written)
}

fn typify_module(name: &str, module: &Value) -> Result<String, String> {
    let definitions = module
        .get("definitions")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("module {name}: no definitions"))?;
    // BTreeMap: a stable order, whatever the JSON order was.
    let mut defs: BTreeMap<String, Schema> = BTreeMap::new();
    for (key, value) in definitions {
        let schema: Schema = serde_json::from_value(value.clone())
            .map_err(|e| format!("module {name}, definition {key}: {e}"))?;
        defs.insert(key.clone(), schema);
    }
    let mut settings = TypeSpaceSettings::default();
    settings.with_struct_builder(false);
    let mut space = TypeSpace::new(&settings);
    space
        .add_ref_types(defs)
        .map_err(|e| format!("module {name}: {e}"))?;
    if space.uses_chrono() || space.uses_regress() || space.uses_uuid() {
        return Err(format!(
            "module {name}: the generated types would need chrono, regress or uuid; strip the format and pattern keywords first"
        ));
    }
    let tokens = space.to_stream();
    let file: syn::File = syn::parse2(tokens).map_err(|e| format!("module {name}: {e}"))?;
    Ok(prettyplease::unparse(&file))
}
