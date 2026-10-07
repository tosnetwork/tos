/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The bounded proposal-read path end to end, over HTTP through the real client:
//! the deepest answers the limits admit, malformed and partial ones, admission
//! under cancellation and exhaustion, and the worker stack.
//!
//! The stack controls run the read in a child process (this binary, re-executed),
//! because a stack overflow aborts the process: a control passes when a too-small
//! stack dies of exactly that overflow, on the worker, and the production stack
//! (and a quarter of it) does not.

use chain_block::{BuilderData, Cell, HashmapE, HashmapType, IBitstring, MsgAddressInt, SliceData};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use contracts::config_contract::proposal_transport::{
    Admission, MAX_JSON_DEPTH, MAX_RESPONSE_BYTES, ProposalAnswer, ProposalRead,
    WORKER_STACK_BYTES, read_proposals_with,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod served;
use served::{Reply, ServedNode, block_json, masterchain_info};

const SEQNO: u32 = 4242;
const CONFIG: &str = "-1:5555555555555555555555555555555555555555555555555555555555555555";
const CODE: &[u8] = include_bytes!("fixtures/list_proposals/config-code.boc");

// ─── Served answers, built as text (never as a recursive value) ───────────────

const NIL: &str = r#"{"@type":"tvm.stackEntryList","list":{"@type":"tvm.list","elements":[]}}"#;
const OPEN: &str = r#"{"@type":"tvm.stackEntryTuple","tuple":{"@type":"tvm.tuple","elements":["#;
const CLOSE: &str = "]}}";

fn number(value: impl std::fmt::Display) -> String {
    format!(
        r#"{{"@type":"tvm.stackEntryNumber","number":{{"@type":"tvm.numberDecimal","number":"{value}"}}}}"#
    )
}

fn tuple(elements: &[String]) -> String {
    format!("{OPEN}{}{CLOSE}", elements.join(","))
}

/// `cons(heads[0], cons(heads[1], ... null))` without recursion.
fn cons_chain(heads: &[String]) -> String {
    let mut text = String::new();
    for head in heads {
        text.push_str(OPEN);
        text.push_str(head);
        text.push(',');
    }
    text.push_str(NIL);
    for _ in heads {
        text.push_str(CLOSE);
    }
    text
}

fn proposal(voters: &str) -> String {
    tuple(&[
        number(1_900_000_000u32),
        number(0),
        tuple(&[number(7), NIL.to_string(), number(-1)]),
        number(1),
        voters.to_string(),
        number(100),
        number(3),
        number(0),
        number(0),
    ])
}

fn result_with(stack: &str) -> String {
    format!(
        r#"{{"@type":"smc.runResult","gas_used":0,"stack":[{stack}],"exit_code":0,"last_transaction_id":null,"block_id":{}}}"#,
        block_json(SEQNO)
    )
}

fn envelope(result: &str) -> String {
    format!(r#"{{"ok":true,"jsonrpc":"2.0","id":"@@ID@@","result":{result}}}"#)
}

/// A list answer with `count` proposals, the last carrying `voters` voters.
fn list_answer(count: usize, voters: usize) -> String {
    let voter_chain = cons_chain(&(0..voters).map(number).collect::<Vec<_>>());
    let pairs: Vec<String> = (1..=count)
        .map(|hash| {
            let voters = if hash == count { voter_chain.as_str() } else { NIL };
            tuple(&[number(hash), proposal(voters)])
        })
        .collect();
    envelope(&result_with(&cons_chain(&pairs)))
}

/// The deepest valid answer within the byte limit: one proposal whose voter chain
/// takes every byte the limit leaves.
fn deepest_valid_answer() -> (String, usize) {
    let fixed = list_answer(1, 0).len() + 64;
    let mut voters = 0usize;
    let mut size = 0usize;
    loop {
        let next = 160 + number(voters).len() - number(0).len();
        if fixed + size + next > MAX_RESPONSE_BYTES {
            break;
        }
        size += next;
        voters += 1;
    }
    let answer = list_answer(1, voters);
    assert!(answer.len() <= MAX_RESPONSE_BYTES, "{}", answer.len());
    (answer, voters)
}

/// A stack whose one entry is plain arrays nested to `depth` levels in all: not a
/// stack entry at all, at the most nesting the preflight lets through when `depth`
/// is the limit.
fn nested_arrays_answer(depth: usize) -> String {
    // The envelope, the result and the stack array are the first three levels.
    let arrays = depth - 3;
    envelope(&result_with(&format!("{}{}", "[".repeat(arrays), "]".repeat(arrays))))
}

fn deepest_malformed_answer() -> String {
    nested_arrays_answer(MAX_JSON_DEPTH)
}

/// A deep valid prefix (a long voter chain) cut off before it closes: the parser
/// builds the deep partial tree, then fails, and drops it.
fn partial_answer() -> String {
    let (full, _) = deepest_valid_answer();
    let cut = full.len() * 9 / 10;
    let mut cut = cut;
    while !full.is_char_boundary(cut) {
        cut -= 1;
    }
    full[..cut].to_string()
}

/// Valid JSON, valid stack entries, nested past anything a proposal has: converted
/// into a deep stack, refused by the decoder, then dropped.
fn deep_conversion_answer() -> String {
    let levels = (MAX_RESPONSE_BYTES - 4_096) / (OPEN.len() + number(1).len() + 1 + CLOSE.len());
    let mut text = String::new();
    for _ in 0..levels {
        text.push_str(OPEN);
        text.push_str(&number(1));
        text.push(',');
    }
    text.push_str(&number(2));
    for _ in 0..levels {
        text.push_str(CLOSE);
    }
    let answer = envelope(&result_with(&text));
    assert!(answer.len() <= MAX_RESPONSE_BYTES);
    answer
}

// ─── A node and a read ────────────────────────────────────────────────────────

fn too_large() -> Reply {
    Reply::raw(200, " ".repeat(MAX_RESPONSE_BYTES + 1))
}

async fn node(getter: Reply, account: Reply) -> ServedNode {
    ServedNode::start(move |method, _| match method {
        "getMasterchainInfo" => masterchain_info(SEQNO),
        "runGetMethodStd" => getter.clone(),
        "getAddressInformation" => account.clone(),
        _ => Reply::raw(404, "{}"),
    })
    .await
}

/// A generous watchdog: a read that has not finished by then is a hang, reported as
/// a failure rather than left to stall the suite. Timing is recorded, not gated.
const WATCHDOG: Duration = Duration::from_secs(300);

async fn read(node: &ServedNode, admission: &Admission) -> anyhow::Result<ProposalAnswer> {
    let client = ClientJsonRpc::connect(node.url.clone(), None)?;
    let address: MsgAddressInt = CONFIG.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::time::timeout(
        WATCHDOG,
        read_proposals_with(&client, &address, ProposalRead::List, admission),
    )
    .await
    .unwrap_or_else(|_| panic!("a proposal read hung past the {WATCHDOG:?} watchdog"))
}

fn production() -> Admission {
    Admission::new(2, Duration::from_secs(30), WORKER_STACK_BYTES)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

fn listed(answer: ProposalAnswer) -> Vec<contracts::ConfigProposal> {
    match answer {
        ProposalAnswer::List(list) => list,
        _ => panic!("a list read answered something else"),
    }
}

// ─── A stored account for the large-state path ────────────────────────────────

fn cell(fill: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut builder = BuilderData::new();
    fill(&mut builder);
    builder.into_cell().expect("cell")
}

/// A chain of `depth` cells, each referencing the next.
fn deep_cell(depth: usize) -> Cell {
    let mut current = cell(|c| {
        c.append_u8(1).unwrap();
    });
    for _ in 1..depth {
        let child = current;
        current = cell(|c| {
            c.checked_append_reference(child).unwrap();
        });
    }
    current
}

/// Account data holding one proposal whose value is `value`.
fn account_with_value(value: Cell) -> Vec<u8> {
    let proposal = cell(|p| {
        p.append_u8(0xf3).unwrap();
        p.append_i32(7).unwrap();
        p.append_bit_one().unwrap();
        p.checked_append_reference(value).unwrap();
        p.append_bit_zero().unwrap();
    });
    let status = SliceData::load_cell(cell(|s| {
        s.append_u8(0xce).unwrap();
        s.append_u32(1_900_000_000).unwrap();
        s.checked_append_reference(proposal).unwrap();
        s.append_bit_zero().unwrap();
        s.append_bit_zero().unwrap();
        s.append_i64(100).unwrap();
        s.append_raw(&[1u8; 32], 256).unwrap();
        s.append_u8(3).unwrap();
        s.append_u8(0).unwrap();
        s.append_u8(0).unwrap();
    }))
    .unwrap();
    let mut votes = HashmapE::with_bit_len(256);
    votes.set(SliceData::from_raw(vec![0x42; 32], 256), &status).unwrap();
    let data = cell(|d| {
        d.checked_append_reference(Cell::default()).unwrap();
        d.append_bit_one().unwrap();
        d.checked_append_reference(votes.data().cloned().unwrap()).unwrap();
    });
    chain_block::write_boc(&data).unwrap()
}

fn account_reply(data: &[u8]) -> Reply {
    Reply::ok(served::account_result(CODE, data, block_json(SEQNO)))
}

// ─── The deepest answers through the whole path ──────────────────────────────

#[test]
fn a_list_beyond_the_old_ceiling_and_a_full_voter_set_decode() {
    let runtime = runtime();
    runtime.block_on(async {
        let node = node(Reply::raw(200, list_answer(300, 21)), Reply::raw(500, "{}")).await;
        let list = listed(read(&node, &production()).await.expect("read"));
        assert_eq!(list.len(), 300);
        assert_eq!(list[299].voters, (0..21).collect::<Vec<u16>>());
        assert_eq!(node.calls(), vec!["getMasterchainInfo", "runGetMethodStd"]);
    });
}

#[test]
fn the_deepest_valid_answer_within_the_byte_limit_decodes_in_bounded_time() {
    let (answer, voters) = deepest_valid_answer();
    let runtime = runtime();
    runtime.block_on(async {
        let node = node(Reply::raw(200, answer), Reply::raw(500, "{}")).await;
        let started = Instant::now();
        let list = listed(read(&node, &production()).await.expect("read"));
        let elapsed = started.elapsed();
        assert_eq!(list[0].voters.len(), voters);
        println!("deepest valid answer: {voters} voters, decoded in {elapsed:?}");
    });
}

#[test]
fn malformed_partial_and_deep_answers_are_refused_in_bounded_time() {
    let runtime = runtime();
    for (case, answer) in [
        ("malformed at the depth limit", deepest_malformed_answer()),
        ("partial deep tree", partial_answer()),
        ("deep conversion", deep_conversion_answer()),
    ] {
        runtime.block_on(async {
            let node =
                node(Reply::raw(200, answer), account_reply(&account_with_value(Cell::default())))
                    .await;
            let started = Instant::now();
            let error = read(&node, &production())
                .await
                .err()
                .unwrap_or_else(|| panic!("{case} was accepted"));
            let elapsed = started.elapsed();
            println!("{case}: refused in {elapsed:?}: {error:#}");
            assert!(error.to_string().chars().count() < 1024, "{case}: unbounded error");
            assert!(
                !node.calls().contains(&"getAddressInformation".to_string()),
                "{case} fell back"
            );
        });
    }
}

#[test]
fn past_the_depth_limit_is_refused_before_parsing() {
    let answer = nested_arrays_answer(MAX_JSON_DEPTH + 1);
    let runtime = runtime();
    runtime.block_on(async {
        let node = node(Reply::raw(200, answer), Reply::raw(500, "{}")).await;
        let error = read(&node, &production()).await.err().expect("too deep");
        assert!(
            error.to_string().contains(&format!("deeper than {MAX_JSON_DEPTH} levels")),
            "{error:#}"
        );
    });
}

#[test]
fn the_byte_limit_is_a_clean_error_and_the_list_falls_back_to_state() {
    let runtime = runtime();
    runtime.block_on(async {
        // Exactly at the limit the body is read.
        // The served id replaces the 8-byte placeholder with a quoted 36-byte UUID.
        let mut at_limit = list_answer(1, 0);
        at_limit.push_str(&" ".repeat(MAX_RESPONSE_BYTES - at_limit.len() - 30));
        let node1 = node(Reply::raw(200, at_limit), Reply::raw(500, "{}")).await;
        assert_eq!(listed(read(&node1, &production()).await.expect("at the limit")).len(), 1);

        // One byte over, the getter's answer is refused whole and the list is read
        // from the stored account at the same block.
        let data = account_with_value(Cell::default());
        let node2 = node(too_large(), account_reply(&data)).await;
        let list = listed(read(&node2, &production()).await.expect("from state"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].hash, [0x42; 32]);
        assert_eq!(
            node2.calls(),
            vec!["getMasterchainInfo", "runGetMethodStd", "getAddressInformation"]
        );

        // Both too large: an error naming both, never a partial list.
        let node3 = node(too_large(), too_large()).await;
        let error = read(&node3, &production()).await.err().expect("both too large");
        let text = error.to_string();
        assert!(
            text.contains("list_proposals answer exceeds") && text.contains("stored account"),
            "{text}"
        );
        assert!(text.contains("paginated or incremental state reads"), "{text}");
    });
}

// ─── Admission ────────────────────────────────────────────────────────────────

/// Fifty reads of the deepest answer, each dropped at a different moment: before
/// admission, while fetching, and while its worker runs. A dropped read never
/// releases a running worker's permit, so no more than two workers ever exist, and
/// once they drain the admission serves again.
#[test]
fn cancelled_reads_never_exceed_the_worker_budget() {
    let (answer, _) = deepest_valid_answer();
    let runtime = runtime();
    runtime.block_on(async {
        let node = Arc::new(node(Reply::raw(200, answer), Reply::raw(500, "{}")).await);
        let admission = Arc::new(Admission::new(2, Duration::from_secs(30), WORKER_STACK_BYTES));
        let mut handles = Vec::new();
        for index in 0..50u64 {
            let node = node.clone();
            let admission = admission.clone();
            let task = tokio::spawn(async move { read(&node, &admission).await });
            handles.push((task, Duration::from_millis(index * 7 % 120)));
        }
        for (task, after) in handles {
            tokio::time::sleep(after / 10).await;
            task.abort();
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while admission.worker_counts().0 > 0 {
            assert!(Instant::now() < deadline, "workers did not drain");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (live, most) = admission.worker_counts();
        println!("cancellation burst: most workers alive at once = {most}");
        assert_eq!(live, 0);
        assert!(most <= 2, "{most} workers were alive at once");
        assert!(most >= 1, "no read reached a worker: the burst measured nothing");
        assert!(read(&node, &admission).await.is_ok(), "the admission did not recover");
    });
}

/// With every permit held by a read still fetching, the next read waits for the
/// admission timeout and is refused as busy.
#[test]
fn an_exhausted_admission_refuses_as_busy() {
    let runtime = runtime();
    runtime.block_on(async {
        let slow = ServedNode::start(|method, _| match method {
            "getMasterchainInfo" => masterchain_info(SEQNO),
            _ => {
                // Long enough that a late timer under a loaded host still fires first.
                std::thread::sleep(Duration::from_secs(8));
                Reply::raw(200, list_answer(1, 0))
            }
        })
        .await;
        let slow = Arc::new(slow);
        let admission = Arc::new(Admission::new(1, Duration::from_millis(300), WORKER_STACK_BYTES));
        let first = {
            let (slow, admission) = (slow.clone(), admission.clone());
            tokio::spawn(async move { read(&slow, &admission).await })
        };
        // The first read asks for the getter only once it holds the one permit.
        while !slow.calls().contains(&"runGetMethodStd".to_string()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let started = Instant::now();
        let second = read(&slow, &admission).await;
        let waited = started.elapsed();
        let error =
            second.err().unwrap_or_else(|| panic!("the second read was admitted after {waited:?}"));
        assert!(error.to_string().contains("busy"), "{error:#}");
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        println!("busy refusal after {waited:?}");
        assert!(first.await.expect("join").is_ok());
    });
}

// ─── Worker stack controls (in a child process) ───────────────────────────────

fn on_large_stack<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(job)
        .expect("spawn")
        .join()
        .expect("join")
}

const CHILD_CASE: &str = "PROPOSAL_READ_STACK_CASE";
const CHILD_STACK: &str = "PROPOSAL_READ_STACK_BYTES";

fn child_answer(case: &str) -> (Reply, Reply) {
    let empty_account = || account_reply(&account_with_value(Cell::default()));
    match case {
        "deepest-valid" => (Reply::raw(200, deepest_valid_answer().0), Reply::raw(500, "{}")),
        "malformed-max-depth" => (Reply::raw(200, deepest_malformed_answer()), empty_account()),
        "partial" => (Reply::raw(200, partial_answer()), empty_account()),
        "deep-conversion" => (Reply::raw(200, deep_conversion_answer()), empty_account()),
        // Built on a large stack: the cell library writes a deep BOC recursively.
        // Cells are at most 2048 deep, and the vote dictionary, the status and the
        // proposal sit above the value: this is about the deepest account there is.
        "state-deep-cell" => {
            (too_large(), account_reply(&on_large_stack(|| account_with_value(deep_cell(2_040)))))
        }
        "state-deepest-value" => {
            (too_large(), account_reply(&on_large_stack(|| account_with_value(deep_cell(1_024)))))
        }
        other => panic!("unknown case {other}"),
    }
}

/// The child half: runs one case under the stack the parent chose. Does nothing
/// when run as an ordinary test.
#[test]
fn stack_child() {
    let (Ok(case), Ok(stack)) = (std::env::var(CHILD_CASE), std::env::var(CHILD_STACK)) else {
        return;
    };
    let stack: usize = stack.parse().expect("stack bytes");
    let runtime = runtime();
    runtime.block_on(async {
        let (getter, account) = child_answer(&case);
        let node = node(getter, account).await;
        let admission = Admission::new(1, Duration::from_secs(30), stack);
        let outcome = read(&node, &admission).await;
        println!("CHILD DONE {case} ok={}", outcome.is_ok());
    });
}

struct ChildRun {
    exited: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_child(case: &str, stack: usize) -> ChildRun {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "stack_child", "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, case)
        .env(CHILD_STACK, stack.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("child runs");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + WATCHDOG;
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{case} hung past the {WATCHDOG:?} watchdog");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    ChildRun {
        exited: status.code(),
        signal: status.signal(),
        stdout: out.join().expect("stdout"),
        stderr: err.join().expect("stderr"),
    }
}

/// Each case, whether its read succeeds, and whether it completes on a tiny stack.
/// The parser recurses once per JSON level and the cell library once per cell level,
/// so every deep case needs the worker stack; only a shallow account does not.
const CASES: [(&str, bool, bool); 6] = [
    ("deepest-valid", true, false),
    ("malformed-max-depth", false, false),
    ("partial", false, false),
    ("deep-conversion", false, false),
    ("state-deep-cell", false, false),
    ("state-deepest-value", true, true),
];

const TINY_STACK: usize = 128 << 10;

/// Every case completes on a quarter of the production stack with the expected
/// outcome, in this build profile. Every deep case dies on a tiny stack of exactly a
/// worker stack overflow, nothing else, so the worker stack is what carries it; the
/// shallow control completes there, so the tiny stack itself is not the failure.
#[test]
fn the_worker_stack_is_sized_with_margin_and_is_load_bearing() {
    for (case, succeeds, shallow) in CASES {
        let quarter = run_child(case, WORKER_STACK_BYTES / 4);
        assert_eq!(quarter.exited, Some(0), "{case} on a quarter stack: {}", quarter.stderr);
        let done = format!("CHILD DONE {case} ok={succeeds}");
        assert!(quarter.stdout.contains(&done), "{case}: {}", quarter.stdout);

        let tiny = run_child(case, TINY_STACK);
        if shallow {
            assert_eq!(tiny.exited, Some(0), "{case} on a tiny stack: {}", tiny.stderr);
            assert!(tiny.stdout.contains(&done), "{case}: {}", tiny.stdout);
        } else {
            assert_eq!(
                tiny.signal,
                Some(6),
                "{case} on a tiny stack did not abort: {:?}",
                tiny.exited
            );
            assert!(
                tiny.stderr.contains("thread 'proposal-read' (")
                    && tiny.stderr.contains("has overflowed its stack"),
                "{case} aborted for another reason: {}",
                tiny.stderr
            );
            assert!(!tiny.stdout.contains("CHILD DONE"), "{case} finished on a tiny stack");
        }
    }
}

/// Not a gate: finds the smallest stack each case completes on, to size the worker
/// stack from. Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn measure_worker_stack() {
    for (case, _, _) in CASES {
        let (mut low, mut high) = (16usize << 10, WORKER_STACK_BYTES);
        while high - low > (16 << 10) {
            let middle = low + (high - low) / 2;
            if run_child(case, middle).exited == Some(0) {
                high = middle;
            } else {
                low = middle;
            }
        }
        println!("STACK {case}: completes on {} KiB", high >> 10);
    }
}

/// Not a gate: full-pipeline timings for the record, with the SHA-256 of each input.
/// Run with `--release --ignored --nocapture`.
#[test]
#[ignore]
fn measure_refusal_times() {
    use sha2::{Digest, Sha256};
    let runtime = runtime();
    let cases: Vec<(&str, String)> = vec![
        ("deepest-valid", deepest_valid_answer().0),
        ("malformed-max-depth", deepest_malformed_answer()),
        ("partial", partial_answer()),
        ("deep-conversion", deep_conversion_answer()),
    ];
    for (case, answer) in cases {
        let digest = hex::encode(Sha256::digest(answer.as_bytes()));
        let bytes = answer.len();
        runtime.block_on(async {
            let node = node(Reply::raw(200, answer), Reply::raw(500, "{}")).await;
            let mut timings = Vec::new();
            for _ in 0..5 {
                let started = Instant::now();
                let outcome = read(&node, &production()).await;
                timings.push(started.elapsed());
                assert!(outcome.is_ok() == (case == "deepest-valid"), "{case}");
            }
            timings.sort();
            println!(
                "TIME {case} bytes={bytes} sha256={digest} median={:?} max={:?}",
                timings[2], timings[4]
            );
        });
    }
}

// ─── Review controls ──────────────────────────────────────────────────────────

/// A list answer whose result carries an unused object of `keys` distinct keys,
/// with the last key repeated when `duplicate` is set.
fn wide_object_answer(keys: usize, duplicate: bool) -> String {
    let mut object = String::from("{");
    for index in 0..keys {
        if index > 0 {
            object.push(',');
        }
        object.push_str(&format!("\"k{index}\":0"));
    }
    if duplicate {
        object.push_str(&format!(",\"k{}\":0", keys - 1));
    }
    object.push('}');
    let answer = list_answer(1, 0).replacen(
        "\"gas_used\":0",
        &format!("\"extra\":{object},\"gas_used\":0"),
        1,
    );
    assert!(answer.len() <= MAX_RESPONSE_BYTES, "{}", answer.len());
    answer
}

/// A wide object is checked for duplicate keys in n log n: the widest that fits is
/// accepted when its keys are distinct and refused for a duplicate at its very
/// end. Timing is recorded, not gated.
#[test]
fn a_wide_object_is_checked_for_duplicates_end_to_end() {
    let runtime = runtime();
    for (keys, duplicate) in [(60_000, false), (60_000, true)] {
        let answer = wide_object_answer(keys, duplicate);
        let bytes = answer.len();
        runtime.block_on(async {
            let node = node(Reply::raw(200, answer), Reply::raw(500, "{}")).await;
            let started = Instant::now();
            let outcome = read(&node, &production()).await;
            let elapsed = started.elapsed();
            println!("wide object: {keys} keys, duplicate={duplicate}, {bytes} bytes, {elapsed:?}");
            if duplicate {
                let error = outcome.err().expect("a duplicate key is refused");
                assert!(error.to_string().contains("duplicate key \"k59999\""), "{error:#}");
            } else {
                assert_eq!(listed(outcome.expect("distinct keys are accepted")).len(), 1);
            }
        });
    }
}

/// Twenty reads under a two-permit admission against a node that answers the
/// checkpoint slowly: no more than two checkpoint requests are ever in flight, so
/// the admission bounds every response a read buffers, the checkpoint included.
#[test]
fn admission_bounds_the_checkpoint_request_too() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let in_flight = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let runtime = runtime();
    runtime.block_on(async {
        let (counter, peak) = (in_flight.clone(), most.clone());
        let node = Arc::new(
            ServedNode::start(move |method, _| match method {
                "getMasterchainInfo" => {
                    let now = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(300));
                    counter.fetch_sub(1, Ordering::SeqCst);
                    masterchain_info(SEQNO)
                }
                "runGetMethodStd" => Reply::raw(200, list_answer(1, 0)),
                _ => Reply::raw(404, "{}"),
            })
            .await,
        );
        let admission = Arc::new(Admission::new(2, Duration::from_secs(60), WORKER_STACK_BYTES));
        let reads: Vec<_> = (0..20)
            .map(|_| {
                let (node, admission) = (node.clone(), admission.clone());
                tokio::spawn(async move { read(&node, &admission).await.map(|_| ()) })
            })
            .collect();
        for read in reads {
            read.await.expect("join").expect("read");
        }
    });
    let most = most.load(std::sync::atomic::Ordering::SeqCst);
    println!("checkpoint requests in flight at once: {most}");
    assert!(most <= 2, "{most} checkpoint requests were in flight under two permits");
    assert!(most >= 1, "no checkpoint request was observed");
}

/// An oversized error response is an error, never a reason to fall back: with a
/// declared length or chunked. An oversized successful one still falls back.
#[test]
fn an_oversized_error_response_never_falls_back() {
    let runtime = runtime();
    let big = || " ".repeat(MAX_RESPONSE_BYTES + 1);
    let account = || account_reply(&account_with_value(Cell::default()));
    for (case, getter, falls_back) in [
        ("503 declared", Reply::raw(503, big()), false),
        ("503 chunked", Reply::raw(503, big()).chunked(), false),
        ("404 chunked", Reply::raw(404, big()).chunked(), false),
        ("200 declared", Reply::raw(200, big()), true),
        ("200 chunked", Reply::raw(200, big()).chunked(), true),
    ] {
        runtime.block_on(async {
            let node = node(getter, account()).await;
            let outcome = read(&node, &production()).await;
            let fell_back = node.calls().contains(&"getAddressInformation".to_string());
            assert_eq!(fell_back, falls_back, "{case}: {:?}", outcome.as_ref().err());
            assert_eq!(outcome.is_ok(), falls_back, "{case}: {:?}", outcome.as_ref().err());
        });
    }
}
