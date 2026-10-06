// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// TEST ONLY. The signing key and randomizer below are public deterministic
// fixtures. This executable must never be used for live funds or real secrets.
use chain_block::{BuilderData, Cell};
use contracts::{lms_fee_journal::FeeJournal, lms_fee_schedule::FeeRoute};
use serde::Deserialize;
use std::{
    env, fs,
    io::{BufRead, Write},
    path::PathBuf,
    process::Command,
};
use tos_vm::{
    executor::{Engine, gas::gas_state::Gas},
    stack::{Stack, StackItem, integer::IntegerData, savelist::SaveList},
};

#[derive(Deserialize)]
struct Input {
    mode: String,
    directory: PathBuf,
    tree: PathBuf,
    backend: PathBuf,
    vault: String,
    digest: String,
    public_key: String,
    epoch0: u32,
    opened_time: u32,
    proven_time: u32,
    leaf: u32,
    #[serde(default)]
    successor: bool,
}

fn chain(bytes: &[u8]) -> anyhow::Result<Cell> {
    let mut tail = None;
    for chunk in bytes.chunks(127).rev() {
        let mut b = BuilderData::new();
        b.append_raw(
            chunk,
            chunk.len().checked_mul(8).ok_or_else(|| anyhow::anyhow!("size overflow"))?,
        )?;
        if let Some(cell) = tail {
            b.checked_append_reference(cell)?;
        }
        tail = Some(b.into_cell()?);
    }
    tail.ok_or_else(|| anyhow::anyhow!("empty PQ byte chain"))
}

fn verify(leaf: u32, digest: &[u8; 32], signature: &[u8], key: &[u8]) -> anyhow::Result<bool> {
    let mut stack = Stack::new();
    stack.push(StackItem::int(IntegerData::from_unsigned_bytes_be(digest)));
    stack.push(StackItem::int(IntegerData::from_i64(i64::from(leaf))));
    stack.push(StackItem::Cell(chain(signature)?));
    stack.push(StackItem::Cell(chain(key)?));
    let mut code = BuilderData::new();
    code.append_raw(&[0xf9, 0x31, 0x03], 24)?;
    let mut vm = Engine::with_capabilities(0).setup_checked(
        code.into_cell()?,
        SaveList::new(),
        stack,
        Gas::test_with_limit(100_000),
        vec![],
    )?;
    vm.set_block_version(17);
    anyhow::ensure!(vm.execute()? == 0 && vm.stack().depth() == 1, "verification VM failed");
    Ok(vm.stack().get(0)?.as_integer_value(-1..=0)? == -1)
}

fn execute(
    input: Input,
    session: &mut Option<(FeeRoute, Vec<u8>, FeeJournal)>,
) -> anyhow::Result<serde_json::Value> {
    let digest: [u8; 32] =
        hex::decode(&input.digest)?.try_into().map_err(|_| anyhow::anyhow!("digest width"))?;
    let vault: [u8; 32] =
        hex::decode(&input.vault)?.try_into().map_err(|_| anyhow::anyhow!("vault width"))?;
    let public_key = hex::decode(&input.public_key)?;
    let mut network = [0; 32];
    network[31] = 123;
    let mut tree_id = [0; 32];
    tree_id[30..].copy_from_slice(&(if input.successor { 457u16 } else { 456u16 }).to_be_bytes());
    let route = FeeRoute { global_id: 42, network, vault, tree_id, epoch0: input.epoch0 };
    if session.is_none() {
        *session = Some((
            route,
            public_key.clone(),
            FeeJournal::open(&input.directory, route, input.opened_time)?,
        ));
    }
    let (bound_route, bound_key, journal) =
        session.as_mut().ok_or_else(|| anyhow::anyhow!("missing session"))?;
    anyhow::ensure!(*bound_route == route && *bound_key == public_key, "session route/key changed");
    if input.mode == "continuity" {
        let state = journal.observed_continuity(input.proven_time)?;
        return Ok(serde_json::json!({
            "global_id": state.route.global_id,
            "network": hex::encode(state.route.network),
            "vault": hex::encode(state.route.vault),
            "tree_id": hex::encode(state.route.tree_id),
            "epoch0": state.route.epoch0,
            "next_unreserved": state.next_unreserved,
            "last_proven_time": state.last_proven_time,
            "backend_calls": 0
        }));
    }
    if input.mode == "preview" {
        let plan = journal.preview(input.proven_time, 0)?;
        return Ok(serde_json::json!({"leaf": plan.leaf, "backend_calls": 0}));
    }
    let calls = std::cell::Cell::new(0u32);
    let result = match input.mode.as_str() {
        "sign" | "corrupt" => journal.sign_once(
            input.proven_time,
            0,
            input.leaf,
            digest,
            |leaf, message| {
                calls.set(
                    calls
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("call count overflow"))?,
                );
                let files = tempfile::tempdir()?;
                let msg = files.path().join("message");
                let sig = files.path().join("signature");
                fs::write(&msg, message)?;
                let output = Command::new(&input.backend)
                    .arg("sign")
                    .arg((if input.successor { "77" } else { "44" }).repeat(32))
                    .arg((if input.successor { "88" } else { "55" }).repeat(16))
                    .arg("20")
                    .arg(&input.tree)
                    .arg(leaf.to_string())
                    .arg(msg)
                    .arg("66".repeat(32))
                    .arg(&sig)
                    .output()?;
                anyhow::ensure!(output.status.success(), "public test signer failed");
                let mut bytes = fs::read(sig)?;
                if input.mode == "corrupt" {
                    let last =
                        bytes.last_mut().ok_or_else(|| anyhow::anyhow!("empty signature"))?;
                    *last ^= 1;
                }
                Ok(bytes)
            },
            |leaf, hash, signature| verify(leaf, hash, signature, &public_key),
        ),
        "retry" => journal.cached_signature(input.leaf, digest),
        _ => anyhow::bail!("unknown test operation"),
    };
    let report = if input.mode == "corrupt" {
        anyhow::ensure!(result.is_err(), "real verifier accepted corrupted output");
        anyhow::ensure!(
            journal.cached_signature(input.leaf, digest).is_err(),
            "invalid output cached"
        );
        let next = journal.preview(input.proven_time, 0)?.leaf;
        anyhow::ensure!(
            next == input.leaf.checked_add(1).ok_or_else(|| anyhow::anyhow!("leaf overflow"))?,
            "failed signing did not burn reservation"
        );
        serde_json::json!({"rejected": true, "backend_calls": calls.get(), "next_leaf": next})
    } else {
        let signature = result?;
        anyhow::ensure!(
            verify(input.leaf, &digest, &signature, &public_key)?,
            "cached signature failed real verification"
        );
        serde_json::json!({"signature": hex::encode(signature), "backend_calls": calls.get(), "verified": true})
    };
    Ok(report)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    let mut session = None;
    if args.len() == 2 && args[1] == "--serve-public-fixture" {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout().lock();
        for line in stdin.lock().lines() {
            let request: Input = serde_json::from_str(&line?)?;
            let response = match execute(request, &mut session) {
                Ok(result) => result,
                Err(error) => serde_json::json!({"error": format!("{error:#}")}),
            };
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
        return Ok(());
    }
    anyhow::ensure!(
        args.len() == 3,
        "usage: lms_fee_cache_fixture input.json output.json (PUBLIC TEST KEY ONLY)"
    );
    let input: Input = serde_json::from_slice(&fs::read(&args[1])?)?;
    fs::write(&args[2], serde_json::to_vec_pretty(&execute(input, &mut session)?)?)?;
    Ok(())
}
