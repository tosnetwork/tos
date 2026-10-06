/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Sandbox getter results rendered the way the node's `runGetMethodStd` serves them,
//! and read back through the same envelope decoding the chain provider applies.

use tos_vm::stack::StackItem;

/// A sandbox stack item rendered as the node's `runGetMethodStd` serializer
/// (`serialize_stack_entry_std` in `validator-engine/json-rpc-server-runmethod.cpp`)
/// renders it: a tuple is tested before a list, so a TVM null, which only the list
/// test accepts, becomes an empty `tvm.stackEntryList`, and a cons cell stays a
/// two-element tuple. This mirrors that code and is no evidence of it on its own;
/// `tests/fixtures/get_proposal` and `tests/fixtures/list_proposals` hold the node's
/// real answers.
pub fn as_served(item: &StackItem) -> serde_json::Value {
    use base64::Engine;
    let b64 = |cell: &chain_block::Cell| {
        base64::engine::general_purpose::STANDARD
            .encode(chain_block::write_boc(cell).expect("a boc"))
    };
    if item.is_null() {
        return serde_json::json!({
            "@type": "tvm.stackEntryList",
            "list": {"@type": "tvm.list", "elements": []}
        });
    }
    if let Ok(int) = item.as_integer() {
        return serde_json::json!({
            "@type": "tvm.stackEntryNumber",
            "number": {"@type": "tvm.numberDecimal", "number": int.to_string()}
        });
    }
    if let Ok(items) = item.as_tuple() {
        return serde_json::json!({
            "@type": "tvm.stackEntryTuple",
            "tuple": {"@type": "tvm.tuple", "elements": items.iter().map(as_served).collect::<Vec<_>>()}
        });
    }
    if let Ok(cell) = item.as_cell() {
        return serde_json::json!({
            "@type": "tvm.stackEntryCell",
            "cell": {"@type": "tvm.cell", "bytes": b64(cell)}
        });
    }
    panic!("the getter returned an item this test does not render: {item:?}");
}

/// A whole `runGetMethodStd` response carrying `stack` (top of stack last, as the
/// sandbox returns it), as the node writes it: top of stack first.
// Not every test binary that includes this module calls every helper.
#[allow(dead_code)]
pub fn served_response(stack: &[StackItem]) -> String {
    let served: Vec<serde_json::Value> = stack.iter().rev().map(as_served).collect();
    serde_json::json!({
        "ok": true,
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "@type": "smc.runResult",
            "gas_used": 0,
            "stack": served,
            "exit_code": 0,
            "last_transaction_id": null,
            "block_id": null
        }
    })
    .to_string()
}

/// A `runGetMethodStd` response read back as the chain provider reads it.
// Not every test binary that includes this module calls every helper.
#[allow(dead_code)]
pub fn read_response(response: &str) -> common::tvm_stack_parser::TvmStackParser {
    let value: serde_json::Value = serde_json::from_str(response).expect("a JSON response");
    let result: chain_rpc_client::v2::data_models::RunGetMethodRes =
        serde_json::from_value(value["result"].clone()).expect("a run result");
    contracts::chain_provider::stack_from_rpc(result.stack)
}
