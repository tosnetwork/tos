/* Copyright (C) 2025-2026 TOS Network. Licensed under GPLv3. */
//! Native transactions for highload cleanup and the actual lockup constructor ABI.
use base64::Engine;
use chain_block::{
    BuilderData, Cell, Deserializable, HashmapE, HashmapType, IBitstring, Message, MsgAddressInt,
    Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
const TOS: u64 = 1_000_000_000;
#[path = "fixtures/current_network.rs"]
mod current_network;
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}
fn smartcont() -> PathBuf {
    std::env::var_os("TOS_AUDIT_SMARTCONT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("crypto/smartcont"))
}
fn cell(f: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    f(&mut b);
    b.into_cell().unwrap()
}
fn dict(b: &mut BuilderData, value: Option<Cell>) {
    if let Some(v) = value {
        b.append_bit_one().unwrap();
        b.checked_append_reference(v).unwrap();
    } else {
        b.append_bit_zero().unwrap();
    }
}
fn deploy(bc: &mut Blockchain, code: Cell, data: Cell, amount: u64) -> MsgAddressInt {
    let init = StateInit::with_code_and_data(code, data);
    let address = MsgAddressInt::with_params(
        -1,
        init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0),
    )
    .unwrap();
    let funder = bc.treasury("funder", 10_000 * TOS).unwrap();
    bc.send_message(
        MessageBuilder::internal(funder.address(), &address, amount)
            .state_init(init)
            .bounce(false)
            .build(),
    )
    .unwrap()
    .expect_success();
    address
}
fn signed(key: &SigningKey, body: Cell) -> Cell {
    cell(|b| {
        b.append_raw(&key.sign(body.hash(0).as_slice()).to_bytes(), 512).unwrap();
        b.append_builder(&SliceData::load_cell(body).unwrap().as_builder().unwrap()).unwrap();
    })
}
fn external(addr: &MsgAddressInt, body: Cell) -> Message {
    MessageBuilder::external(addr).body(body).build()
}
fn highload_data(key: &SigningKey, now: u32, count: u64) -> Cell {
    let mut queries = HashmapE::with_bit_len(64);
    for i in 0..count {
        let id = ((u64::from(now) - 100) << 32) | i;
        queries
            .set(
                SliceData::load_cell(cell(|b| {
                    b.append_u64(id).unwrap();
                }))
                .unwrap(),
                &SliceData::default(),
            )
            .unwrap();
    }
    cell(|b| {
        b.append_u32(42).unwrap();
        b.append_u64(0).unwrap();
        b.append_u256(&key.verifying_key().to_bytes()).unwrap();
        dict(b, queries.data().cloned());
    })
}
fn highload_count(bc: &Blockchain, addr: &MsgAddressInt) -> usize {
    let mut d = SliceData::load_cell(bc.get_account(addr).unwrap().get_data().unwrap()).unwrap();
    d.move_by(32 + 64 + 256).unwrap();
    HashmapE::with_hashmap(64, d.get_next_dictionary().unwrap()).len().unwrap()
}
#[test]
fn highload_expired_backlog_is_bounded_and_replay_protection_survives() {
    let code = compile_func_with_stdlib(&[smartcont().join("highload-wallet-v2-code.fc")]).unwrap();
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let mut bc = Blockchain::with_global_version(current_network::global_version()).unwrap();
    bc.set_workchain(-1);
    let now = bc.now();
    let addr = deploy(&mut bc, code, highload_data(&key, now, 4_096), 100 * TOS);
    let make_query = |id| {
        signed(
            &key,
            cell(|b| {
                b.append_i32(42).unwrap();
                b.append_u32(42).unwrap();
                b.append_u64(id).unwrap();
                dict(b, None);
            }),
        )
    };
    for batch in 0..128u64 {
        let id = ((u64::from(now) + 3_600) << 32) | batch;
        let body = make_query(id);
        let out = bc
            .send_message(external(&addr, body.clone()))
            .expect("bounded cleanup accepts backlog");
        out.expect_success().expect_out_msgs(0);
        assert_eq!(
            highload_count(&bc, &addr),
            4_096 - (batch as usize + 1) * 32 + batch as usize + 1
        );
        if batch == 0 {
            let err = bc
                .send_message(external(&addr, body))
                .err()
                .expect("duplicate refused")
                .to_string();
            assert!(err.contains("exit code: 32"), "{err}");
        }
    }
    assert_eq!(highload_count(&bc, &addr), 128, "only fresh replay records remain");
    let old = ((u64::from(now) - 100) << 32) | 1;
    let err = bc
        .send_message(external(&addr, make_query(old)))
        .err()
        .expect("forgotten old id still refused")
        .to_string();
    assert!(err.contains("exit code: 35"), "{err}");
}
fn run(cmd: &mut Command) {
    let out = cmd.output().expect("native tool");
    assert!(
        out.status.success(),
        "{:?}\n{}\n{}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
fn public_key_text(key: &SigningKey) -> String {
    let mut bytes = vec![0x3e, 0xe6];
    bytes.extend(key.verifying_key().to_bytes());
    let mut crc = 0u16;
    for byte in &bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    bytes.extend(crc.to_be_bytes());
    base64::engine::general_purpose::URL_SAFE.encode(bytes)
}
#[test]
fn restricted_wallet_constructor_uses_seconds_and_enforces_every_unlock_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("auto")).unwrap();
    let smartcont = smartcont();
    let func = std::env::var_os("FUNC_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("build/crypto/func"));
    let fift = std::env::var_os("FIFT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("build/crypto/fift"));
    run(Command::new(func)
        .args(["-PS", "-o"])
        .arg(tmp.path().join("auto/restricted-wallet2-code.fif"))
        .arg(smartcont.join("stdlib.fc"))
        .arg(smartcont.join("restricted-wallet2-code.fc")));
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let base = tmp.path().join("lockup");
    let includes = format!(
        "{}:{}:{}",
        tmp.path().display(),
        root().join("crypto/fift/lib").display(),
        smartcont.display()
    );
    run(Command::new(fift)
        .arg(format!("-I{includes}"))
        .arg("-s")
        .arg(smartcont.join("new-restricted-wallet2.fif"))
        .arg(public_key_text(&key))
        .arg("1200")
        .arg(&base)
        .current_dir(tmp.path()));
    let bytes = std::fs::read(base.with_file_name("lockup-query.boc")).unwrap();
    let init_msg =
        Message::construct_from_cell(chain_block::read_single_root_boc(bytes).unwrap()).unwrap();
    let init = init_msg.state_init().expect("constructor StateInit");
    let mut d = SliceData::load_cell(init.data.clone().unwrap()).unwrap();
    assert_eq!(d.get_next_u32().unwrap(), 0);
    let pubkey = d.get_next_hash().unwrap();
    assert_eq!(d.get_next_u32().unwrap(), 0);
    let schedule = d.get_next_dictionary().unwrap().expect("schedule");
    let mut bc = Blockchain::with_global_version(current_network::global_version()).unwrap();
    bc.set_workchain(-1);
    let start = bc.now() + 1_000;
    // Only supply a fixture start timestamp; preserve the actual constructor's
    // code, public key and restriction dictionary byte-for-byte.
    let data = cell(|b| {
        b.append_u32(0).unwrap();
        b.append_u256(pubkey.as_slice()).unwrap();
        b.append_u32(start).unwrap();
        dict(b, Some(schedule));
    });
    let addr = deploy(&mut bc, init.code.clone().unwrap(), data, 1_201 * TOS);
    let bootstrap = cell(|b| {
        b.append_raw(&[0; 64], 512).unwrap();
        b.append_i32(42).unwrap();
        b.append_u32(0).unwrap();
        b.append_u32(u32::MAX).unwrap();
    });
    bc.send_message(external(&addr, bootstrap)).unwrap().expect_success();
    let balance = bc.get_account(&addr).unwrap().balance().unwrap().coins.as_u128();
    for (elapsed, reserved) in [
        (-1i64, 1_200u64),
        (0, 1_200),
        (92 * 86400 - 1, 1_200),
        (92 * 86400, 900),
        (183 * 86400 - 1, 900),
        (183 * 86400, 600),
        (366 * 86400 - 1, 600),
        (366 * 86400, 300),
        (548 * 86400 - 1, 300),
        (548 * 86400, 0),
    ] {
        let out = bc
            .run_get_method(&addr, "balance_at", vec![StackItem::int(i64::from(start) + elapsed)])
            .unwrap();
        assert_eq!(out.exit_code, 0, "constructor dictionary ABI at elapsed seconds: {elapsed}");
        assert_eq!(
            out.int_at(0),
            balance.saturating_sub(u128::from(reserved * TOS)) as i128,
            "elapsed seconds: {elapsed}"
        );
    }
    let recipient = bc.treasury("recipient", TOS).unwrap().address().clone();
    let transfer = MessageBuilder::internal(&addr, &recipient, 400 * TOS)
        .bounce(false)
        .build()
        .write_to_new_cell()
        .unwrap()
        .into_cell()
        .unwrap();
    let body = signed(
        &key,
        cell(|b| {
            b.append_i32(42).unwrap();
            b.append_u32(1).unwrap();
            b.append_u32(u32::MAX).unwrap();
            b.append_u8(1).unwrap();
            b.checked_append_reference(transfer).unwrap();
        }),
    );
    let before = bc.get_account(&addr).unwrap().get_data().unwrap().hash(0);
    bc.send_message(external(&addr, body.clone()))
        .unwrap()
        .expect_exit_code(0)
        .expect_aborted()
        .expect_out_msgs(0);
    assert_eq!(
        bc.get_account(&addr).unwrap().get_data().unwrap().hash(0),
        before,
        "failed locked transfer preserves seqno"
    );
    bc.set_now(start + 183 * 86400);
    bc.send_message(external(&addr, body)).unwrap().expect_success().expect_out_msgs(1);
}
