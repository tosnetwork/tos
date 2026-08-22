/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sandbox (offline TVM) tests for the `.tos` root resolver: compiles the
//! actual contract sources from `crypto/smartcont/dns/func` with the live
//! toolchain and checks the `dnsresolve` consumed-bit ABI against the
//! client-side validator in `contracts::dns`.

use chain_block::{BuilderData, Cell, MsgAddressInt, Serializable, SliceData, StateInit};
use contracts::dns::{self, DnsRecord, HopOutcome, HopResult};
use tos_sandbox::{Blockchain, GetMethodResult, MessageBuilder, compile_func};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;

fn root_code() -> Cell {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../crypto/smartcont/dns/func");
    let sources: Vec<_> = ["stdlib.fc", "tos-config.fc", "dns-utils.fc", "root-dns.fc"]
        .iter()
        .map(|f| dir.join(f))
        .collect();
    compile_func(&sources).expect("compile root-dns (needs build/crypto/func and fift)")
}

struct Fixture {
    bc: Blockchain,
    root: MsgAddressInt,
    collection: MsgAddressInt,
}

impl Fixture {
    fn new() -> Self {
        let mut bc = Blockchain::new().expect("blockchain");
        bc.set_workchain(-1);
        let deployer = bc.treasury("dns-deployer", 1_000 * TOS).expect("deployer");
        let collection =
            MsgAddressInt::with_standart(None, 0, [0xAB; 32].into()).expect("collection");
        let mut data = BuilderData::new();
        collection.write_to(&mut data).expect("data");
        let si = StateInit::with_code_and_data(root_code(), data.into_cell().expect("data cell"));
        let hash = si.write_to_new_cell().expect("cell").into_cell().expect("cell").hash(0);
        let root = MsgAddressInt::with_params(-1, hash).expect("root address");
        let deploy = MessageBuilder::internal(deployer.address(), &root, 2 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build();
        bc.send_message(deploy).expect("deploy").expect_success();
        Fixture { bc, root, collection }
    }

    fn dnsresolve(&self, query: &[u8]) -> GetMethodResult {
        let mut b = BuilderData::new();
        b.append_raw(query, query.len() * 8).expect("query bits");
        let slice = SliceData::load_cell(b.into_cell().expect("query cell")).expect("slice");
        self.bc
            .run_get_method(
                &self.root,
                "dnsresolve",
                vec![StackItem::Slice(slice), StackItem::int(0)],
            )
            .expect("dnsresolve")
    }
}

/// Convert a sandbox `(int, cell|null)` result into the client `HopResult`.
fn hop_result(res: &GetMethodResult) -> HopResult {
    res.expect_success();
    assert!(res.stack.len() >= 2, "dnsresolve must return (int, cell)");
    let used_bits = i64::try_from(res.int_at(res.stack.len() - 2)).expect("used_bits range");
    let value_item = &res.stack[res.stack.len() - 1];
    let value = if value_item.is_null() {
        None
    } else {
        Some(value_item.as_cell().expect("value cell").clone())
    };
    HopResult { used_bits, value }
}

#[test]
fn root_delegates_the_tos_zone() {
    let fx = Fixture::new();
    let query = b"tos\0alice\0";
    let hop = hop_result(&fx.dnsresolve(query));
    // "tos" is consumed up to the component boundary and the answer is the
    // delegated Collection, exactly as the client validator expects.
    match dns::validate_hop(query, &hop, 8).expect("hop must validate") {
        HopOutcome::Continue { next_resolver, remaining } => {
            assert_eq!(next_resolver, fx.collection);
            assert_eq!(remaining, b"\0alice\0");
        }
        other => panic!("expected delegation to the collection, got {other:?}"),
    }
    // and the raw record parses as dns_next_resolver
    let record = dns::parse_record(hop.value.as_ref().expect("record")).expect("parse");
    assert_eq!(record, DnsRecord::NextResolver { resolver: fx.collection.clone() });
}

#[test]
fn root_rejects_foreign_and_prefix_sharing_suffixes() {
    let fx = Fixture::new();
    for query in [&b"toz\0alice\0"[..], &b"tosx\0alice\0"[..], &b"me\0t\0"[..]] {
        let hop = hop_result(&fx.dnsresolve(query));
        assert_eq!(hop.used_bits, 0, "foreign suffix {query:?} must not resolve");
        assert!(hop.value.is_none());
        assert!(matches!(dns::validate_hop(query, &hop, 8).expect("hop"), HopOutcome::NotFound));
    }
}

#[test]
fn root_answers_the_self_query() {
    let fx = Fixture::new();
    // "." (a lone terminator) resolves to the root itself: 8 bits, no value
    let hop = hop_result(&fx.dnsresolve(b"\0"));
    assert_eq!(hop.used_bits, 8);
    assert!(hop.value.is_none());
    assert!(matches!(dns::validate_hop(b"\0", &hop, 8).expect("hop"), HopOutcome::Terminal(None)));
}
