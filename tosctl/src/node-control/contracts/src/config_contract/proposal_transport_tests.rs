/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::*;

const TWO_LIVE: &str = include_str!("../../tests/fixtures/list_proposals/two-live.json");
const EMPTY_LIVE: &str = include_str!("../../tests/fixtures/list_proposals/empty-live.json");

/// Runs `job` on a thread with the worker's stack, as the production path does.
fn on_worker_stack<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(job)
        .expect("spawn")
        .join()
        .expect("join")
}

// ─── Depth preflight ──────────────────────────────────────────────────────────

fn preflight(text: &str, limit: usize) -> Result<(), PreflightError> {
    depth_preflight(text.as_bytes(), limit)
}

#[test]
fn the_preflight_counts_brackets_outside_strings_only() {
    assert_eq!(preflight("[[[]]]", 3), Ok(()));
    assert_eq!(preflight("[[[[]]]]", 3), Err(PreflightError::TooDeep { at: 3, limit: 3 }));
    assert_eq!(preflight(r#"{"a":{"b":[1]}}"#, 3), Ok(()));
    assert_eq!(
        preflight(r#"{"a":{"b":[[1]]}}"#, 3),
        Err(PreflightError::TooDeep { at: 11, limit: 3 })
    );
    // Brackets inside strings are text.
    assert_eq!(preflight(r#"["[[[[{{{{"]"#, 1), Ok(()));
    assert_eq!(preflight(r#"["]]]]}}}}"]"#, 1), Ok(()));
    // A \uXXXX escape of a bracket is text, and its hex digits are never brackets.
    assert_eq!(preflight(r#"["\u005b\u007b\u005d"]"#, 1), Ok(()));
}

#[test]
fn a_quote_ends_a_string_only_after_an_even_run_of_backslashes() {
    // `\"` keeps the string open, so the brackets after it are text.
    assert_eq!(preflight(r#"["\"[[["]"#, 1), Ok(()));
    // `\\"` closes it (the backslash is escaped), so the bracket after it counts.
    assert_eq!(preflight(r#"["\\",["#, 1), Err(PreflightError::TooDeep { at: 6, limit: 1 }));
    // `\\\"` is an escaped backslash then an escaped quote: still open.
    assert_eq!(preflight(r#"["\\\"[[["]"#, 1), Ok(()));
    // `\\\\"` closes.
    assert_eq!(preflight(r#"["\\\\",["#, 1), Err(PreflightError::TooDeep { at: 8, limit: 1 }));
    // A run broken by another character starts over.
    assert_eq!(preflight(r#"["\\a\"[["]"#, 1), Ok(()));
}

#[test]
fn closing_more_than_opened_is_an_underflow() {
    assert_eq!(preflight("[]]", 4), Err(PreflightError::Underflow { at: 2 }));
    assert_eq!(preflight("}", 4), Err(PreflightError::Underflow { at: 0 }));
}

/// The preflight only bounds depth. Mismatched delimiters, unterminated strings and
/// trailing documents pass it and are refused by the parser that runs after it.
#[test]
fn what_the_preflight_leaves_to_the_parser_is_refused_there() {
    for text in
        [r#"[}"#, r#"{"a":[}]"#, r#"["unterminated"#, "{}{}", "{} [", "[1] 2", "[1,]", "\u{1}"]
    {
        assert!(preflight(text, 16).is_ok(), "{text:?} was refused by the preflight");
        assert!(parse_document(text).is_err(), "{text:?} was parsed");
    }
}

#[test]
fn parsing_refuses_one_level_past_the_limit_and_accepts_the_limit() {
    let at_limit = format!("{}{}", "[".repeat(MAX_JSON_DEPTH), "]".repeat(MAX_JSON_DEPTH));
    let past = format!("[{at_limit}]");
    on_worker_stack(move || {
        assert!(parse_document(&at_limit).is_ok());
        let error = parse_document(&past).expect_err("one level past the limit");
        assert!(error.contains(&format!("deeper than {MAX_JSON_DEPTH} levels")), "{error}");
    });
}

// ─── Limits pinned against the node's bytes ───────────────────────────────────

/// The size constants are measured from the node's real answer, not from a
/// representative encoding: the smallest number it prints and the tuple wrapper
/// of every cons cell.
#[test]
fn the_minimal_encodings_are_the_nodes_own_bytes() {
    let zero =
        r#"{"@type":"tvm.stackEntryNumber","number":{"@type":"tvm.numberDecimal","number":"0"}}"#;
    let open = r#"{"@type":"tvm.stackEntryTuple","tuple":{"@type":"tvm.tuple","elements":["#;
    let close = "]}}";
    assert!(TWO_LIVE.contains(zero) && TWO_LIVE.contains(open) && TWO_LIVE.contains(close));
    assert_eq!(MIN_NUMBER_BYTES, zero.len());
    // A cons cell is the wrapper, the comma between head and tail, and the close.
    assert_eq!(MIN_CONS_CELL_BYTES, open.len() + 1 + close.len());
    // A voter is a number of at least one digit.
    let one_digit_voter = format!("{open}{zero},");
    assert!(MIN_VOTER_LEVEL_BYTES <= one_digit_voter.len() + close.len());
    assert_eq!(MAX_JSON_DEPTH, 3 * MAX_RESPONSE_BYTES.div_ceil(MIN_VOTER_LEVEL_BYTES) + 64);
}

/// The fixed allowance covers everything around the deepest cons chain with room to
/// spare: the real two-proposal answer is far shallower than it.
#[test]
fn the_fixed_nesting_is_within_its_allowance() {
    let depth_of = |text: &str| {
        (1..).find(|limit| depth_preflight(text.as_bytes(), *limit).is_ok()).unwrap_or(0)
    };
    // Two outer cons cells: everything else is the envelope, the result, the stack,
    // the pair, the proposal and its parameter tuple.
    let two = depth_of(TWO_LIVE);
    let fixed = two - 3 * 2;
    assert!(fixed * 2 <= FIXED_NESTING_ALLOWANCE, "fixed nesting {fixed}");
    assert!(depth_of(EMPTY_LIVE) < fixed);
}

/// Malformed input reaches the limit far more cheaply than any valid answer: an
/// error or unknown field at two bytes per level. Its safety comes from the limit
/// itself (and the worker stack sized for it), not from minimum valid sizes.
#[test]
fn a_malformed_body_at_the_depth_limit_fits_in_far_fewer_bytes() {
    let error_envelope = format!(
        r#"{{"ok":false,"jsonrpc":"2.0","id":"x","code":500,"error":{}{}}}"#,
        "[".repeat(MAX_JSON_DEPTH - 1),
        "]".repeat(MAX_JSON_DEPTH - 1)
    );
    assert!(error_envelope.len() < MAX_RESPONSE_BYTES / 20);
    let past = error_envelope.replacen('[', "[[", 1).replacen(']', "]]", 1);
    on_worker_stack(move || {
        assert!(parse_document(&error_envelope).is_ok());
        assert!(parse_document(&past).is_err_and(|e| e.contains("deeper than")));
    });
}

// ─── Envelope ─────────────────────────────────────────────────────────────────

fn result_of(text: &str, status: u16, id: &str) -> Result<Json, String> {
    envelope_result(parse_document(text)?, status, id)
}

#[test]
fn the_envelope_rules_are_the_clients() {
    let ok = r#"{"ok":true,"jsonrpc":"2.0","id":"r1","result":{"a":1}}"#;
    assert!(result_of(ok, 200, "r1").is_ok());
    for (case, text, status) in [
        ("wrong id", ok, 200),
        ("missing id", r#"{"ok":true,"jsonrpc":"2.0","result":{}}"#, 200),
        ("numeric id", r#"{"ok":true,"jsonrpc":"2.0","id":1,"result":{}}"#, 200),
        ("wrong version", r#"{"ok":true,"jsonrpc":"1.0","id":"r1","result":{}}"#, 200),
        ("ok not a boolean", r#"{"ok":"yes","jsonrpc":"2.0","id":"r1","result":{}}"#, 200),
        ("no result", r#"{"ok":true,"jsonrpc":"2.0","id":"r1"}"#, 200),
        (
            "result and error",
            r#"{"ok":true,"jsonrpc":"2.0","id":"r1","result":{},"error":"e","code":500}"#,
            200,
        ),
        (
            "error with result",
            r#"{"ok":false,"jsonrpc":"2.0","id":"r1","result":{},"error":"e","code":500}"#,
            500,
        ),
        ("error without code", r#"{"ok":false,"jsonrpc":"2.0","id":"r1","error":"e"}"#, 500),
        ("a successful envelope on HTTP 500", ok, 500),
        (
            "duplicate result",
            r#"{"ok":true,"jsonrpc":"2.0","id":"r1","result":{},"result":{}}"#,
            200,
        ),
        ("duplicate id", r#"{"ok":true,"jsonrpc":"2.0","id":"r1","id":"r1","result":{}}"#, 200),
        (
            "duplicate nested key",
            r#"{"ok":true,"jsonrpc":"2.0","id":"r1","result":{"a":1,"a":2}}"#,
            200,
        ),
        ("trailing JSON", r#"{"ok":true,"jsonrpc":"2.0","id":"r1","result":{}} {}"#, 200),
        ("not an object", "[]", 200),
    ] {
        let id = if case == "wrong id" { "r2" } else { "r1" };
        assert!(result_of(text, status, id).is_err(), "{case} was accepted");
    }
    let refused = result_of(
        r#"{"ok":false,"jsonrpc":"2.0","id":"r1","error":"exit code 11","code":500}"#,
        500,
        "r1",
    )
    .expect_err("an error envelope");
    assert_eq!(refused, "the endpoint answered error 500: exit code 11");
}

/// An error envelope with deeply nested data is parsed and dropped on the worker and
/// becomes a bounded flat string.
#[test]
fn a_deep_error_envelope_becomes_a_bounded_message() {
    let deep = format!(
        r#"{{"ok":false,"jsonrpc":"2.0","id":"r1","code":500,"error":{}1{}}}"#,
        "[".repeat(1_000),
        "]".repeat(1_000)
    );
    assert_eq!(result_of(&deep, 500, "r1").expect_err("refused"), "error must be a string");
    let long = format!(
        r#"{{"ok":false,"jsonrpc":"2.0","id":"r1","code":500,"error":"{}"}}"#,
        "x".repeat(10_000)
    );
    assert!(result_of(&long, 500, "r1").expect_err("refused").chars().count() <= MAX_ERROR_CHARS);
}

// ─── The node's real answers through the worker's decoding ────────────────────

fn response(text: &str) -> RawRpcResponse {
    let value: serde_json::Value = serde_json::from_str(text).expect("fixture");
    let id = value["id"].to_string();
    RawRpcResponse {
        status: 200,
        text: text.replacen(&format!("\"id\":{id}"), "\"id\":\"r1\"", 1),
        request_id: "r1".into(),
    }
}

fn checkpoint_of(text: &str) -> MasterchainCheckpoint {
    let value: serde_json::Value = serde_json::from_str(text).expect("fixture");
    let block = &value["result"]["block_id"];
    let hash = |key: &str| {
        hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(block[key].as_str().expect("hash"))
                .expect("base64"),
        )
    };
    MasterchainCheckpoint {
        seqno: block["seqno"].as_u64().expect("seqno") as u32,
        root_hash: hash("root_hash"),
        file_hash: hash("file_hash"),
    }
}

#[test]
fn the_live_answers_decode_at_their_own_block_only() {
    let checkpoint = checkpoint_of(TWO_LIVE);
    let Ok(GetterOutcome::Answer(ProposalAnswer::List(proposals))) =
        decode_getter_response(&response(TWO_LIVE), ProposalRead::List, &checkpoint)
    else {
        panic!("the two-proposal answer decodes");
    };
    assert_eq!(proposals.len(), 2);
    assert_eq!(proposals[0].param.id, 1000);
    assert_eq!(proposals[1].param.id, 1001);
    let Ok(GetterOutcome::Answer(ProposalAnswer::List(none))) = decode_getter_response(
        &response(EMPTY_LIVE),
        ProposalRead::List,
        &checkpoint_of(EMPTY_LIVE),
    ) else {
        panic!("the empty answer decodes");
    };
    assert!(none.is_empty());
    // The same answer at any other checkpoint is refused.
    let other = MasterchainCheckpoint { seqno: checkpoint.seqno + 1, ..checkpoint.clone() };
    let refused = decode_getter_response(&response(TWO_LIVE), ProposalRead::List, &other);
    assert!(refused.is_err_and(|e| e.contains("another block")));
    let other = MasterchainCheckpoint { root_hash: "00".repeat(32), ..checkpoint };
    assert!(decode_getter_response(&response(TWO_LIVE), ProposalRead::List, &other).is_err());
}

#[test]
fn served_entries_the_node_never_writes_are_refused() {
    let checkpoint = checkpoint_of(TWO_LIVE);
    for (case, from, to) in [
        ("unknown type", "tvm.stackEntryTuple", "tvm.stackEntryMystery"),
        ("number without text", r#""number":"0""#, r#""number":0"#),
        ("tuple without elements", r#""elements":["#, r#""items":["#),
        ("nonzero exit code", r#""exit_code":0"#, r#""exit_code":11"#),
        ("exit code 1", r#""exit_code":0"#, r#""exit_code":1"#),
        ("exit code -13", r#""exit_code":0"#, r#""exit_code":-13"#),
    ] {
        let text = TWO_LIVE.replacen(from, to, 1);
        assert_ne!(text, TWO_LIVE, "{case}: the mutation did not apply");
        let result = decode_getter_response(&response(&text), ProposalRead::List, &checkpoint);
        assert!(result.is_err(), "{case} was accepted");
    }
}

/// Exit 13 is the one getter exit that sends a list read to stored state, and only
/// once the answer is from the checkpoint; a single-proposal read never does.
#[test]
fn only_exit_13_of_a_list_read_at_the_checkpoint_falls_back() {
    let checkpoint = checkpoint_of(TWO_LIVE);
    let exit13 = TWO_LIVE.replacen(r#""exit_code":0"#, r#""exit_code":13"#, 1);
    assert!(matches!(
        decode_getter_response(&response(&exit13), ProposalRead::List, &checkpoint),
        Ok(GetterOutcome::Exit13)
    ));
    let other = MasterchainCheckpoint { seqno: checkpoint.seqno + 1, ..checkpoint.clone() };
    assert!(
        decode_getter_response(&response(&exit13), ProposalRead::List, &other)
            .is_err_and(|e| e.contains("another block"))
    );
    for read in [ProposalRead::One([1; 32]), ProposalRead::Expiry([1; 32])] {
        assert!(
            decode_getter_response(&response(&exit13), read, &checkpoint)
                .is_err_and(|e| e.contains("exited with code 13"))
        );
    }
}

// ─── Destruction ──────────────────────────────────────────────────────────────

/// Far deeper than any parse can produce, on a stack far too small to drop it
/// recursively: a recursive drop aborts the test process.
const DROP_DEPTH: usize = 200_000;
const DROP_STACK: usize = 256 << 10;

#[test]
fn a_deep_json_tree_drops_without_recursion() {
    std::thread::Builder::new()
        .stack_size(DROP_STACK)
        .spawn(|| {
            let mut tree = Json::Null;
            for _ in 0..DROP_DEPTH {
                tree = Json::Array(vec![Json::Object(vec![("k".to_string(), tree)])]);
            }
            drop(tree);
        })
        .expect("spawn")
        .join()
        .expect("the tree dropped");
}

#[test]
fn a_deep_stack_is_dismantled_without_recursion() {
    std::thread::Builder::new()
        .stack_size(DROP_STACK)
        .spawn(|| {
            let mut entry = StackEntry::Tvm_StackEntryUnsupported;
            for index in 0..DROP_DEPTH {
                entry = if index % 2 == 0 {
                    StackEntry::Tvm_StackEntryTuple(stackentry::StackEntryTuple {
                        tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements: vec![entry] }),
                    })
                } else {
                    StackEntry::Tvm_StackEntryList(stackentry::StackEntryList {
                        list: List::Tvm_List(list::List { elements: vec![entry] }),
                    })
                };
            }
            dismantle(vec![entry]);
        })
        .expect("spawn")
        .join()
        .expect("the stack was dismantled");
}

/// Converting a served stack nested far past any answer does not recurse either.
#[test]
fn a_deep_served_stack_converts_without_recursion() {
    std::thread::Builder::new()
        .stack_size(DROP_STACK)
        .spawn(|| {
            let mut served = Json::Object(vec![
                ("@type".to_string(), Json::String("tvm.stackEntryNumber".to_string())),
                (
                    "number".to_string(),
                    Json::Object(vec![("number".to_string(), Json::String("1".to_string()))]),
                ),
            ]);
            for _ in 0..DROP_DEPTH {
                served = Json::Object(vec![
                    ("@type".to_string(), Json::String("tvm.stackEntryTuple".to_string())),
                    (
                        "tuple".to_string(),
                        Json::Object(vec![("elements".to_string(), Json::Array(vec![served]))]),
                    ),
                ]);
            }
            let converted = convert_stack(vec![served]).expect("converts");
            dismantle(converted);
        })
        .expect("spawn")
        .join()
        .expect("converted");
}
