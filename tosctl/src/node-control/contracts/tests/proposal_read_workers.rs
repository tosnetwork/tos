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

/// Waits for `condition`, failing the test (rather than hanging it) after a minute.
async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

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
        assert!(error.to_string().contains("rpc_error_category=too_deep"), "{error:#}");
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
        // The getter is held until the test opens the gate, so the first read keeps
        // its permit for as long as the test needs, with no sleep to tune.
        let (hold, gate) = served::Gate::guarded();
        let slow = ServedNode::start(move |method, _| match method {
            "getMasterchainInfo" => masterchain_info(SEQNO),
            _ => {
                hold.wait();
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
        wait_until("the first read to ask for the getter", || {
            slow.calls().contains(&"runGetMethodStd".to_string())
        })
        .await;
        let started = Instant::now();
        let second = read(&slow, &admission).await;
        let waited = started.elapsed();
        let error =
            second.err().unwrap_or_else(|| panic!("the second read was admitted after {waited:?}"));
        assert!(error.to_string().contains("busy"), "{error:#}");
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        println!("busy refusal after {waited:?}");
        gate.open();
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
                // The same object with distinct keys is accepted, so the repeated key
                // is what is refused (an envelope failure: no other endpoint here).
                let error = outcome.err().expect("a duplicate key is refused");
                assert!(
                    error.to_string().contains("rpc_error_category=malformed_json"),
                    "{error:#}"
                );
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

// ─── Endpoint failover ────────────────────────────────────────────────────────

/// A node answering the checkpoint and the account normally and the getter with
/// `getter`.
async fn endpoint(getter: Reply) -> ServedNode {
    node(getter, account_reply(&account_with_value(Cell::default()))).await
}

/// A list read through a client over `nodes`, with the getter tried on `nodes[0]`
/// first. (The client's round-robin cursor gives the checkpoint request the first
/// configured endpoint and the getter the next, so `nodes[0]` is configured second.)
async fn read_over(nodes: &[&ServedNode]) -> anyhow::Result<ProposalAnswer> {
    let mut urls: Vec<(String, Option<String>)> =
        nodes.iter().map(|node| (node.url.clone(), None)).collect();
    urls.rotate_right(1);
    let client = ClientJsonRpc::connect_many(urls, None)?;
    let address: MsgAddressInt = CONFIG.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::time::timeout(
        WATCHDOG,
        read_proposals_with(&client, &address, ProposalRead::List, &production()),
    )
    .await
    .unwrap_or_else(|_| panic!("a proposal read hung past the {WATCHDOG:?} watchdog"))
}

fn getter_requests(nodes: &[&ServedNode]) -> Vec<serde_json::Value> {
    nodes.iter().flat_map(|node| node.requests_for("runGetMethodStd")).collect()
}

fn account_reads(nodes: &[&ServedNode]) -> usize {
    nodes.iter().map(|node| node.requests_for("getAddressInformation").len()).sum()
}

/// Every endpoint was asked at most once, with one request id and one set of
/// pinned parameters.
fn assert_one_request_per_endpoint(nodes: &[&ServedNode]) {
    for node in nodes {
        assert!(node.requests_for("runGetMethodStd").len() <= 1, "an endpoint was asked twice");
    }
    let requests = getter_requests(nodes);
    assert!(!requests.is_empty());
    for request in &requests {
        assert_eq!(request["id"], requests[0]["id"], "the request id changed between attempts");
        assert_eq!(request["params"], requests[0]["params"], "the parameters changed");
        assert_eq!(request["params"]["seqno"], SEQNO, "the checkpoint is not pinned");
    }
}

fn small_error(status: u16) -> Reply {
    Reply::raw(status, r#"{"ok":false,"jsonrpc":"2.0","id":"@@ID@@","error":"busy","code":500}"#)
}

fn big(status: u16) -> Reply {
    Reply::raw(status, " ".repeat(MAX_RESPONSE_BYTES + 1))
}

/// A non-success status on the first endpoint, small or oversized, fails over to
/// the next, which answers: the read succeeds from it and never touches state.
#[test]
fn an_http_error_fails_over_to_the_next_endpoint() {
    let runtime = runtime();
    for (case, first) in [
        ("small 503", small_error(503)),
        ("small 500", small_error(500)),
        ("small 429", small_error(429)),
        ("small 404", small_error(404)),
        ("oversized 503", big(503)),
        ("oversized 429", big(429)),
        ("oversized 200", big(200)),
    ] {
        runtime.block_on(async {
            let failing = endpoint(first).await;
            let serving = endpoint(Reply::raw(200, list_answer(2, 0))).await;
            let nodes = [&failing, &serving];
            let list = listed(read_over(&nodes).await.unwrap_or_else(|e| panic!("{case}: {e:#}")));
            assert_eq!(list.len(), 2, "{case}");
            assert_eq!(failing.requests_for("runGetMethodStd").len(), 1, "{case}: not tried first");
            assert_eq!(serving.requests_for("runGetMethodStd").len(), 1, "{case}");
            assert_eq!(account_reads(&nodes), 0, "{case} read the stored state");
            assert_one_request_per_endpoint(&nodes);
        });
    }
}

/// When no endpoint serves a bounded successful answer, the read is "too large"
/// (and may read stored state) only if some endpoint answered successfully with an
/// oversized body. HTTP errors alone, of any size, are a failure.
#[test]
fn only_an_oversized_success_makes_the_answer_too_large() {
    let runtime = runtime();
    for (case, replies, falls_back) in [
        ("all oversized 200", vec![big(200), big(200)], true),
        ("oversized 200 then 503", vec![big(200), small_error(503)], true),
        ("503 then oversized 200", vec![small_error(503), big(200)], true),
        ("oversized 200 then oversized 500", vec![big(200), big(500)], true),
        ("all HTTP errors, small then oversized", vec![small_error(503), big(500)], false),
        ("all HTTP errors, oversized then small", vec![big(502), small_error(429)], false),
        ("single oversized 200", vec![big(200)], true),
        ("single small 503", vec![small_error(503)], false),
    ] {
        runtime.block_on(async {
            let mut nodes = Vec::new();
            for reply in replies {
                nodes.push(endpoint(reply).await);
            }
            let refs: Vec<&ServedNode> = nodes.iter().collect();
            let outcome = read_over(&refs).await;
            assert_eq!(
                account_reads(&refs) > 0,
                falls_back,
                "{case}: {:?}",
                outcome.as_ref().err()
            );
            if falls_back {
                assert_eq!(listed(outcome.unwrap_or_else(|e| panic!("{case}: {e:#}"))).len(), 1);
            } else {
                let error = outcome.err().unwrap_or_else(|| panic!("{case} was accepted"));
                assert!(
                    format!("{error:#}").contains("all chain-rpc endpoints failed"),
                    "{case}: {error:#}"
                );
            }
            for node in &refs {
                assert_eq!(
                    node.requests_for("runGetMethodStd").len(),
                    1,
                    "{case}: an endpoint was skipped"
                );
            }
            assert_one_request_per_endpoint(&refs);
        });
    }
}

/// A non-success status is reported under its fixed category, from the status
/// alone, whatever its body says; the body is not read as an answer.
#[test]
fn an_http_error_is_reported_by_its_status_category() {
    let runtime = runtime();
    let answer_body = list_answer(1, 0);
    for (case, reply, category) in [
        ("503 with an error envelope", small_error(503), "http_server_error"),
        ("500 with a valid answer", Reply::raw(500, answer_body.clone()), "http_server_error"),
        ("429", small_error(429), "rate_limit"),
        ("404 with a valid answer", Reply::raw(404, answer_body.clone()), "http_client_error"),
        ("302", Reply::raw(302, answer_body.clone()), "http_non_success"),
    ] {
        runtime.block_on(async {
            let node = endpoint(reply).await;
            let error =
                read_over(&[&node]).await.err().unwrap_or_else(|| panic!("{case} was accepted"));
            assert!(
                format!("{error:#}").contains(&format!("rpc_error_category={category}")),
                "{case}: {error:#}"
            );
            assert_eq!(account_reads(&[&node]), 0, "{case}");
        });
    }
}

/// An answer whose result is read at `seqno` instead of the checkpoint.
fn at_block(answer: &str, seqno: u32) -> String {
    let changed = answer.replace(&format!("\"seqno\":{SEQNO}"), &format!("\"seqno\":{seqno}"));
    assert_ne!(changed, answer);
    changed
}

fn with_exit(answer: &str, code: i32) -> String {
    let changed = answer.replacen("\"exit_code\":0", &format!("\"exit_code\":{code}"), 1);
    assert_ne!(changed, answer);
    changed
}

/// Each endpoint-specific failure of the first endpoint's answer moves the read to
/// the next endpoint, which answers: the read succeeds from it, under the same
/// id and parameters, without touching stored state.
#[test]
fn an_endpoint_specific_answer_failure_fails_over() {
    let valid = list_answer(2, 0);
    let runtime = runtime();
    for (case, first) in [
        (
            "an error envelope",
            Reply::raw(
                200,
                r#"{"ok":false,"jsonrpc":"2.0","id":"@@ID@@","error":"node failure","code":500}"#,
            ),
        ),
        ("malformed JSON", Reply::raw(200, "{\"ok\":true,")),
        ("trailing data", Reply::raw(200, format!("{valid} {{}}"))),
        ("a mismatched id", Reply::raw(200, valid.replace("\"@@ID@@\"", "\"another\""))),
        ("no result", Reply::raw(200, r#"{"ok":true,"jsonrpc":"2.0","id":"@@ID@@"}"#)),
        (
            "a duplicate envelope key",
            Reply::raw(200, valid.replacen("{\"ok\":true,", "{\"ok\":true,\"ok\":true,", 1)),
        ),
        ("over-deep garbage", Reply::raw(200, nested_arrays_answer(MAX_JSON_DEPTH + 1))),
        ("another block", Reply::raw(200, at_block(&valid, SEQNO - 1))),
        ("no block", Reply::raw(200, valid.replacen("\"block_id\":", "\"block\":", 1))),
        (
            "exit 13 from another block",
            Reply::raw(200, with_exit(&at_block(&valid, SEQNO + 1), 13)),
        ),
    ] {
        runtime.block_on(async {
            let failing = endpoint(first).await;
            let serving = endpoint(Reply::raw(200, valid.clone())).await;
            let nodes = [&failing, &serving];
            let list = listed(read_over(&nodes).await.unwrap_or_else(|e| panic!("{case}: {e:#}")));
            assert_eq!(list.len(), 2, "{case}");
            assert_eq!(failing.requests_for("runGetMethodStd").len(), 1, "{case}: not tried first");
            assert_eq!(serving.requests_for("runGetMethodStd").len(), 1, "{case}: not retried");
            assert_eq!(account_reads(&nodes), 0, "{case} read stored state");
            assert_one_request_per_endpoint(&nodes);
        });
    }
}

/// A valid envelope at the checkpoint settles the read: a non-zero exit or a result
/// the strict decoder refuses ends it without asking the next endpoint, and exit
/// 13 of the list goes to stored state.
#[test]
fn a_valid_envelope_at_the_checkpoint_settles_the_read() {
    let valid = list_answer(2, 0);
    let runtime = runtime();
    for (case, first, expect) in [
        ("exit 11", Reply::raw(200, with_exit(&valid, 11)), "exited with code 11"),
        (
            "a stack the decoder refuses",
            Reply::raw(200, valid.replacen("\"number\":\"1900000000\"", "\"number\":\"-5\"", 1)),
            "proposal expiry",
        ),
        (
            "a result without a stack",
            Reply::raw(200, valid.replacen("\"stack\":[", "\"stock\":[", 1)),
            "no stack",
        ),
    ] {
        runtime.block_on(async {
            let settling = endpoint(first).await;
            let other = endpoint(Reply::raw(200, valid.clone())).await;
            let nodes = [&settling, &other];
            let error =
                read_over(&nodes).await.err().unwrap_or_else(|| panic!("{case} was accepted"));
            assert!(format!("{error:#}").contains(expect), "{case}: {error:#}");
            assert_eq!(
                other.requests_for("runGetMethodStd").len(),
                0,
                "{case}: the next endpoint was asked"
            );
            assert_eq!(account_reads(&nodes), 0, "{case} read stored state");
        });
    }
    runtime.block_on(async {
        let exit13 = endpoint(Reply::raw(200, with_exit(&valid, 13))).await;
        let other = endpoint(Reply::raw(200, valid.clone())).await;
        let nodes = [&exit13, &other];
        let list = listed(read_over(&nodes).await.expect("read from stored state"));
        assert_eq!(list.len(), 1);
        assert_eq!(other.requests_for("runGetMethodStd").len(), 0, "the getter was asked again");
        assert_eq!(account_reads(&nodes), 1);
    });
    // A retryable failure first, then a terminal answer: the read stops there.
    runtime.block_on(async {
        let retry = endpoint(Reply::raw(200, "{\"ok\":true,")).await;
        let terminal = endpoint(Reply::raw(200, with_exit(&valid, 11))).await;
        let third = endpoint(Reply::raw(200, valid.clone())).await;
        let nodes = [&retry, &terminal, &third];
        let error = read_over(&nodes).await.err().expect("refused");
        assert!(format!("{error:#}").contains("exited with code 11"), "{error:#}");
        assert_eq!(third.requests_for("runGetMethodStd").len(), 0);
        assert_eq!(account_reads(&nodes), 0);
    });
}

/// With no valid envelope from any endpoint, only an oversized successful answer
/// makes the read too large; envelope failures and HTTP errors never do.
#[test]
fn envelope_failures_never_make_the_answer_too_large() {
    let envelope = || {
        Reply::raw(
            200,
            r#"{"ok":false,"jsonrpc":"2.0","id":"@@ID@@","error":"node failure","code":500}"#,
        )
    };
    let runtime = runtime();
    for (case, replies, falls_back) in [
        ("envelope error then oversized 200", vec![envelope(), big(200)], true),
        ("oversized 200 then envelope error", vec![big(200), envelope()], true),
        ("envelope error then 503", vec![envelope(), small_error(503)], false),
        ("503 then envelope error", vec![small_error(503), envelope()], false),
        ("all envelope errors", vec![envelope(), Reply::raw(200, "{")], false),
    ] {
        runtime.block_on(async {
            let mut nodes = Vec::new();
            for reply in replies {
                nodes.push(endpoint(reply).await);
            }
            let refs: Vec<&ServedNode> = nodes.iter().collect();
            let outcome = read_over(&refs).await;
            assert_eq!(
                account_reads(&refs) > 0,
                falls_back,
                "{case}: {:?}",
                outcome.as_ref().err()
            );
            if !falls_back {
                let error = outcome.err().unwrap_or_else(|| panic!("{case} was accepted"));
                assert!(
                    format!("{error:#}").contains("all chain-rpc endpoints failed"),
                    "{case}: {error:#}"
                );
            }
            assert_one_request_per_endpoint(&refs);
        });
    }
}

/// One read's attempts run one at a time under its one permit: three endpoints
/// whose answers each take a worker to refuse never have two workers alive.
#[test]
fn a_reads_attempts_never_overlap() {
    let (deep, _) = deepest_valid_answer();
    let runtime = runtime();
    runtime.block_on(async {
        let first = endpoint(Reply::raw(200, at_block(&deep, SEQNO - 1))).await;
        let second = endpoint(Reply::raw(200, at_block(&deep, SEQNO - 2))).await;
        let third = endpoint(Reply::raw(200, list_answer(1, 0))).await;
        let nodes = [&first, &second, &third];
        let admission = Admission::new(2, Duration::from_secs(30), WORKER_STACK_BYTES);
        let mut urls: Vec<(String, Option<String>)> =
            nodes.iter().map(|n| (n.url.clone(), None)).collect();
        urls.rotate_right(1);
        let client = ClientJsonRpc::connect_many(urls, None).expect("client");
        let address: MsgAddressInt = CONFIG.parse().expect("address");
        let list = listed(
            read_proposals_with(&client, &address, ProposalRead::List, &admission)
                .await
                .expect("read"),
        );
        assert_eq!(list.len(), 1);
        assert_eq!(admission.worker_counts(), (0, 1), "attempts overlapped");
    });
}

/// Cancelling a read while its worker runs leaves the permit with the worker until
/// it ends; cancelling it between attempts, with no worker running, frees it.
#[test]
fn cancellation_releases_the_permit_only_when_no_work_is_running() {
    let (deep, _) = deepest_valid_answer();
    let runtime = runtime();
    runtime.block_on(async {
        let address: MsgAddressInt = CONFIG.parse().expect("address");
        let admission = Arc::new(Admission::new(1, Duration::from_millis(50), WORKER_STACK_BYTES));
        let quick = endpoint(Reply::raw(200, list_answer(1, 0))).await;
        let quick_client =
            Arc::new(ClientJsonRpc::connect(quick.url.clone(), None).expect("client"));

        // During a worker: the slow-to-refuse answer keeps the worker busy.
        let busy = endpoint(Reply::raw(200, at_block(&deep, SEQNO - 1))).await;
        let client = Arc::new(ClientJsonRpc::connect(busy.url.clone(), None).expect("client"));
        let task = {
            let (client, admission, address) = (client.clone(), admission.clone(), address.clone());
            tokio::spawn(async move {
                read_proposals_with(&client, &address, ProposalRead::List, &admission)
                    .await
                    .map(|_| ())
            })
        };
        wait_until("the read's worker to start", || admission.worker_counts().0 > 0).await;
        task.abort();
        let _ = task.await;
        // The worker outlives the cancelled read; while it lives, its permit is not
        // free. (The free count is read before the live count, and a worker drops
        // its live mark before its permit.)
        let mut samples_while_working = 0;
        loop {
            let idle = admission.idle_permits();
            if admission.worker_counts().0 == 0 {
                break;
            }
            assert_eq!(idle, 0, "a cancelled read freed the permit of a running worker");
            samples_while_working += 1;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(samples_while_working > 0, "the worker ended before the control could look");
        assert_eq!(admission.idle_permits(), 1);
        assert!(
            read_proposals_with(&quick_client, &address, ProposalRead::List, &admission)
                .await
                .is_ok()
        );

        // Between attempts: the second endpoint is slow to answer HTTP, no worker runs.
        let failing = endpoint(small_error(503)).await;
        let (hold, gate) = served::Gate::guarded();
        let slow = ServedNode::start(move |method, _| match method {
            "getMasterchainInfo" => masterchain_info(SEQNO),
            _ => {
                hold.wait();
                Reply::raw(200, list_answer(1, 0))
            }
        })
        .await;
        // The checkpoint takes the first configured endpoint and the getter starts at
        // the second: the failing one, then the slow one.
        let urls = vec![(slow.url.clone(), None), (failing.url.clone(), None)];
        let client = Arc::new(ClientJsonRpc::connect_many(urls, None).expect("client"));
        let task = {
            let (client, admission, address) = (client.clone(), admission.clone(), address.clone());
            tokio::spawn(async move {
                read_proposals_with(&client, &address, ProposalRead::List, &admission)
                    .await
                    .map(|_| ())
            })
        };
        wait_until("the second attempt to reach the slow endpoint", || {
            !slow.requests_for("runGetMethodStd").is_empty()
        })
        .await;
        assert_eq!(admission.worker_counts().0, 0);
        assert_eq!(
            admission.idle_permits(),
            0,
            "the read does not hold its permit between attempts"
        );
        task.abort();
        let _ = task.await;
        assert_eq!(
            admission.idle_permits(),
            1,
            "a read cancelled between attempts kept its permit"
        );
        // Let the held request finish, so the node's handler thread ends.
        gate.open();
        assert!(
            read_proposals_with(&quick_client, &address, ProposalRead::List, &admission)
                .await
                .is_ok()
        );
    });
}

// ─── Gated test cleanup ───────────────────────────────────────────────────────

const GATED_CHILD: &str = "PROPOSAL_READ_GATED_CHILD";
const INTENDED_FAILURE: &str = "intended failure before the gate opens";

/// The child half: holds a read on a gated handler, then fails an assertion before
/// opening the gate. Does nothing when run as an ordinary test.
#[test]
fn gated_child() {
    if std::env::var(GATED_CHILD).is_err() {
        return;
    }
    let runtime = runtime();
    runtime.block_on(async {
        let (hold, _gate) = served::Gate::guarded();
        let node = Arc::new(
            ServedNode::start(move |method, _| match method {
                "getMasterchainInfo" => masterchain_info(SEQNO),
                _ => {
                    hold.wait();
                    Reply::raw(200, list_answer(1, 0))
                }
            })
            .await,
        );
        let admission = Arc::new(production());
        let reading = {
            let (node, admission) = (node.clone(), admission.clone());
            tokio::spawn(async move { read(&node, &admission).await.map(|_| ()) })
        };
        wait_until("the read to reach the gated handler", || {
            node.calls().contains(&"runGetMethodStd".to_string())
        })
        .await;
        let _keep = reading;
        panic!("{INTENDED_FAILURE}");
    });
}

/// A gated test that fails before it opens its gate ends promptly with that
/// failure: the guard opens the gate as the test unwinds, so the blocked handler
/// returns and the runtime shuts down, well inside the gate's own deadline.
#[test]
fn a_gated_test_that_fails_early_ends_promptly() {
    use std::io::Read;
    let started = Instant::now();
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "gated_child", "--nocapture", "--test-threads=1"])
        .env(GATED_CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("child runs");
    let mut stderr = child.stderr.take().expect("stderr");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let watchdog = served::GATE_DEADLINE * 3;
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break status;
        }
        if started.elapsed() > watchdog {
            let _ = child.kill();
            panic!("the gated child hung past {watchdog:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let elapsed = started.elapsed();
    let stderr = reader.join().expect("stderr");
    assert_eq!(status.code(), Some(101), "the child did not fail as a test: {stderr}");
    assert!(stderr.contains(INTENDED_FAILURE), "the child failed for another reason: {stderr}");
    assert!(
        elapsed < served::GATE_DEADLINE / 3,
        "the child took {elapsed:?} to end: its handler waited out the gate deadline"
    );
}
