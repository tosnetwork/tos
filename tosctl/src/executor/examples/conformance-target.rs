// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Conformance target for the Rust VM and executor.
//!
//! Speaks the line protocol of test/conformance/README.md:
//!
//!     conformance-target --info     build identity and the harnesses provided
//!     conformance-target <harness>  one context JSON per stdin line, one effects JSON per
//!                                   stdout line, in order
//!
//! Harnesses: `vm` (one program on the Rust engine) and `txn` (one transaction through the Rust
//! executor). A context the adapter cannot represent exactly is refused with
//! `{"harness_error": ...}`; it is never approximated.
mod conformance_harnesses;

use std::{
    env,
    io::{self, BufRead, Write},
    panic,
};

use conformance_harnesses::{common, txn, vm};
use serde_json::{json, Value};

/// The reference refuses larger contexts too.
const MAX_CONTEXT_BYTES: usize = 16 << 20;

fn info() -> Value {
    let commit = env!("BUILD_GIT_COMMIT").trim();
    let commit =
        if commit.len() == 40 && commit.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            commit
        } else {
            ""
        };
    // The package build script records the commit but cannot tell whether the tree was clean,
    // so this target never claims a clean build and cannot be used to fill fixtures.
    json!({"reference_commit": commit, "dirty": true, "harnesses": ["txn", "vm"]})
}

/// Reads one line of at most `MAX_CONTEXT_BYTES`. `Ok(None)` at end of input; an oversized line
/// is consumed to its end and reported as `Some(Err(()))`.
fn next_line(input: &mut impl BufRead) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut seen_any = false;
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        seen_any = true;
        let (chunk, done) = match buffer.iter().position(|&b| b == b'\n') {
            Some(end) => (&buffer[..end], Some(end + 1)),
            None => (buffer, None),
        };
        if !oversized {
            if line.len().saturating_add(chunk.len()) > MAX_CONTEXT_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = done.unwrap_or(buffer.len());
        input.consume(consumed);
        if done.is_some() {
            break;
        }
    }
    if !seen_any {
        return Ok(None);
    }
    Ok(Some(if oversized { Err(()) } else { Ok(line) }))
}

fn respond(harness: &str, line: Result<Vec<u8>, ()>) -> Value {
    let Ok(bytes) = line else {
        return common::harness_error("context too large");
    };
    let context = match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return common::harness_error("context must be a JSON object"),
        Err(error) => return common::harness_error(&format!("context is not JSON: {error}")),
    };
    // A panic inside the VM or executor is a defect of the implementation under test, not a
    // refusal: it is reported as a response no harness accepts, so the runner counts it as a
    // mismatch and shows it.
    let outcome = panic::catch_unwind(|| match harness {
        "vm" => vm::run(&context),
        "txn" => txn::run(&context),
        other => Err(anyhow::anyhow!("unknown harness {other}")),
    });
    match outcome {
        Ok(Ok(effects)) => effects,
        Ok(Err(error)) => common::harness_error(&format!("{error:#}")),
        Err(_) => json!({"implementation_panic": true}),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some(mode) if args.len() == 2 => run(mode),
        _ => {
            eprintln!("usage: conformance-target <harness>|--info");
            2
        }
    };
    std::process::exit(code);
}

fn run(mode: &str) -> i32 {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    if mode == "--info" {
        return match writeln!(out, "{}", info()).and_then(|()| out.flush()) {
            Ok(()) => 0,
            Err(_) => 1,
        };
    }
    if mode != "vm" && mode != "txn" {
        eprintln!("unknown harness {mode}");
        return 2;
    }
    // Panics are reported per context; keep the default message off the protocol stream.
    panic::set_hook(Box::new(|info| eprintln!("implementation panic: {info}")));
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let line = match next_line(&mut input) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                eprintln!("cannot read the input: {error}");
                return 1;
            }
        };
        let effects = respond(mode, line);
        if writeln!(out, "{effects}").is_err() {
            return 1;
        }
    }
    match out.flush() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
