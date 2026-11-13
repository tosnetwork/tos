// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Code-cell builder for migrating the RTOS VM test families (migrate/vmfam_rtos.py).
//!
//! The RTOS tests build their code cells with the RTOS assembler; to convert a test's cases into vm
//! contexts with the same code cells, the converter asks this program to build each cell the way
//! the test does. It is compiled against an RTOS tree (vmfam_rtos.py build-asm) and is not part of
//! the C++ build. One JSON request per stdin line, one JSON response per stdout line:
//!
//!   {"op":"asm","src":S}            compile_code_to_cell(S)
//!   {"op":"compile","src":S}        compile_code(S).into_cell()
//!   {"op":"concat","setup":S,"code":HEX,"bits":N|null,"tail":S|null}
//!                                   setup cell, then N raw bits of HEX, then the tail cell
//!   {"op":"code_cell","src":SPEC}   tests/reference code_cell: assembler source, raw:<bits>:<hex>[:<refs>]
//!                                   or ref:<spec>
//!   {"op":"libdict","cells":[HEX]}  a 256-bit HashmapE keyed by representation hash, value a reference
//!                                   to the cell; null root when empty
//!
//! Responses are {"boc":HEX} (null for an empty dictionary) or {"error":TEXT}. Requests are bounded
//! (one line at most 16 MiB, code_cell nesting at most 16).
use std::io::{BufRead, Write};

use rtos_block::{BuilderData, Cell, HashmapE, HashmapType, IBitstring};
use serde_json::{json, Value};

const MAX_LINE: usize = 16 << 20;
const MAX_NESTING: usize = 16;

type Result<T> = std::result::Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn text<'a>(request: &'a Value, key: &str) -> Result<&'a str> {
    request.get(key).and_then(Value::as_str).ok_or_else(|| format!("{key}: string required"))
}

fn boc(cell: &Cell) -> Result<String> {
    Ok(hex::encode(rtos_block::write_boc(cell).map_err(err)?))
}

fn read_cell(hex_text: &str) -> Result<Cell> {
    let bytes = hex::decode(hex_text).map_err(err)?;
    rtos_block::read_single_root_boc(bytes).map_err(err)
}

fn asm(source: &str) -> Result<Cell> {
    rtos_assembler::compile_code_to_cell(source).map_err(|e| format!("{source}: {e}"))
}

fn concat(request: &Value) -> Result<Cell> {
    let setup = asm(text(request, "setup")?)?;
    let mut builder = BuilderData::from_cell(&setup).map_err(err)?;
    let bytes = hex::decode(text(request, "code")?).map_err(err)?;
    let full = bytes.len().checked_mul(8).ok_or("code too long")?;
    let bits = match request.get("bits") {
        None | Some(Value::Null) => full,
        Some(value) => {
            let n = value.as_u64().ok_or("bits: integer required")?;
            usize::try_from(n).map_err(err)?
        }
    };
    if bits > full {
        return Err("bits exceed the code bytes".into());
    }
    builder.append_raw(&bytes, bits).map_err(err)?;
    if let Some(tail) = request.get("tail").and_then(Value::as_str) {
        let tail = asm(tail)?;
        builder.append_builder(&BuilderData::from_cell(&tail).map_err(err)?).map_err(err)?;
    }
    builder.into_cell().map_err(err)
}

fn code_cell(source: &str, depth: usize) -> Result<Cell> {
    if depth > MAX_NESTING {
        return Err("code_cell nesting too deep".into());
    }
    if let Some(inner) = source.strip_prefix("ref:") {
        let mut b = BuilderData::new();
        b.checked_append_reference(code_cell(inner, depth + 1)?).map_err(err)?;
        return b.into_cell().map_err(err);
    }
    let Some(raw) = source.strip_prefix("raw:") else {
        return asm(source);
    };
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(format!("{source}: raw:<bits>:<hex>[:<refs>] required"));
    }
    let bits = parts[0].parse::<usize>().map_err(err)?;
    let mut bytes = hex::decode(parts[1]).map_err(err)?;
    if bytes.is_empty() {
        bytes.push(0);
    }
    let mut b = BuilderData::with_raw(bytes, bits).map_err(err)?;
    let refs = match parts.get(2) {
        Some(r) => r.parse::<u8>().map_err(err)?,
        None => 0,
    };
    if refs > 4 {
        return Err(format!("{source}: at most 4 references"));
    }
    for i in 0..refs {
        let child = BuilderData::with_raw(vec![0x71 + i], 8).map_err(err)?;
        b.checked_append_reference(child.into_cell().map_err(err)?).map_err(err)?;
    }
    b.into_cell().map_err(err)
}

fn libdict(request: &Value) -> Result<Option<Cell>> {
    let cells = request.get("cells").and_then(Value::as_array).ok_or("cells: array required")?;
    let mut libraries = HashmapE::with_bit_len(256);
    for item in cells {
        let cell = read_cell(item.as_str().ok_or("cells: hex strings required")?)?;
        libraries.setref(cell.repr_hash().into(), cell.clone()).map_err(err)?;
    }
    Ok(libraries.data().cloned())
}

fn handle(line: &str) -> Result<Value> {
    let request: Value = serde_json::from_str(line).map_err(err)?;
    let cell = match text(&request, "op")? {
        "asm" => asm(text(&request, "src")?)?,
        "compile" => {
            let source = text(&request, "src")?;
            rtos_assembler::compile_code(source)
                .map_err(|e| format!("{source}: {e}"))?
                .into_cell()
                .map_err(err)?
        }
        "concat" => concat(&request)?,
        "code_cell" => code_cell(text(&request, "src")?, 0)?,
        "libdict" => {
            return match libdict(&request)? {
                Some(root) => Ok(json!({ "boc": boc(&root)? })),
                None => Ok(json!({ "boc": null })),
            };
        }
        other => return Err(format!("unknown op {other}")),
    };
    Ok(json!({ "boc": boc(&cell)? }))
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.len() > MAX_LINE => json!({ "error": "request too long" }),
            Ok(line) => handle(&line).unwrap_or_else(|e| json!({ "error": e })),
            Err(e) => json!({ "error": e.to_string() }),
        };
        if writeln!(out, "{response}").is_err() {
            std::process::exit(1);
        }
    }
}
