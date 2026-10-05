//! Pool snapshots and other proven reads, driven through the production
//! provider ([`ProvenGetterProvider`]) with the real `tos-proof-verify`
//! executable and proof material recorded from a running network.
//!
//! The recorded material is real: the anchor is that network's masterchain
//! zerostate, the chain is its post-quantum finality proofs, and the account
//! and configuration proofs are the lite-server's answers. Re-verifying it
//! needs no network. Tampering with it is how these tests present a dishonest
//! endpoint.
//!
//! That network has no nominator pool running the current pool code (its one
//! pool account runs an older code whose `get_pool_data` throws), so the
//! successful proven reads use the elector, and the pool snapshot is shown to
//! refuse when its getters fail locally. A stand-in verifier
//! (`fixtures/proven-reads/fake_verifier.py`) covers what the provider does
//! with an answer: decoding a pool snapshot and refusing every answer that is
//! not bound to its request.
//!
//! The verifier is found through `TOS_PROOF_VERIFY`, or at
//! `build/lite-client/proof-verify/tos-proof-verify`; build it with
//! `cmake --build build --target tos-proof-verify`. Its absence fails these
//! tests rather than skipping them.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use chain_block::{
    Account, CurrencyCollection, Deserializable, MsgAddressInt, Serializable, read_single_root_boc,
    write_boc,
};
use common::app_config::ProofVerifierConfig;
use contracts::MasterchainCheckpoint;
use contracts::{
    GetMethodArg, GetMethodCall, ProvenGetterProvider, ProvenGetterResults, ReadPolicy,
    read_proven_nominator_pool_snapshot,
};

const ELECTOR: &str = "-1:3333333333333333333333333333333333333333333333333333333333333333";
const POOL: &str = "0:599c2b80cc3bafe785dacefcfb4fc9f56c0ce879ddf6089831c0ab26dbf53f6a";
/// The block the historical material answers for.
const TARGET_SEQNO: u32 = 638197;
const TARGET_ROOT: &str = "23ff07a2936c414cf1e0723604e3845a3a67fa13d4440726fa274d50d30e161b";
const TARGET_FILE: &str = "c3518978f0d4ce7dbd726c6b98508fbf5f577b58dca55f34290c26b340515235";
const TARGET_UTIME: u32 = 1791201441;
/// The verifier's clock when each live recording was made.
const LIVE_A_NOW: i64 = 1791201443;
const LIVE_B_NOW: i64 = 1791201494;
const LIVE_B_SEQNO: u32 = 638326;
const LIVE_MAX_AGE: u32 = 600;

// ───────────────────────── harness ─────────────────────────

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures() -> PathBuf {
    manifest_dir().join("tests/fixtures/proven-reads")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn verifier() -> PathBuf {
    if let Some(path) = std::env::var_os("TOS_PROOF_VERIFY") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute() && path.is_file(), "TOS_PROOF_VERIFY={}", path.display());
        return path;
    }
    let built = manifest_dir().join("../../../../build/lite-client/proof-verify/tos-proof-verify");
    let built = built.canonicalize().unwrap_or_else(|_| {
        panic!(
            "the proof verifier is needed: build it with `cmake --build build --target \
             tos-proof-verify`, or set TOS_PROOF_VERIFY to its absolute path"
        )
    });
    built
}

fn find_on_path(program: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH");
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{program} is needed on PATH"))
}

/// Writes an executable without this process ever holding it open for
/// writing: tests run in parallel, and a write descriptor inherited by a
/// concurrently forked child makes executing the file fail as busy.
fn write_executable(path: &Path, text: &str) {
    let source = path.with_extension("source");
    std::fs::write(&source, text).unwrap();
    let status = std::process::Command::new(find_on_path("install"))
        .args(["-m", "755"])
        .arg(&source)
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "installing {} failed", path.display());
}

/// A shared library that pins `time()` for the process it is preloaded into.
fn fixed_clock_library() -> PathBuf {
    static LIBRARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    LIBRARY
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("tos-fixed-clock-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let library = dir.join("fixed_clock.so");
            let status = std::process::Command::new(find_on_path("cc"))
                .args(["-shared", "-fPIC", "-O2", "-o"])
                .arg(&library)
                .arg(fixtures().join("fixed_clock.c"))
                .status()
                .expect("compile the fixed clock");
            assert!(status.success(), "compiling the fixed clock failed");
            library
        })
        .clone()
}

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// A material directory holding exactly `files`.
    fn material(&self, files: &[(&str, Vec<u8>)]) -> PathBuf {
        let dir = self.path("material");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        dir
    }

    /// The real verifier, with its clock pinned to `now` when given.
    fn real_verifier(&self, now: Option<i64>) -> PathBuf {
        match now {
            None => verifier(),
            Some(now) => {
                let wrapper = self.path("verifier-at-fixed-time");
                write_executable(
                    &wrapper,
                    &format!(
                        "#!/bin/sh\nLD_PRELOAD='{}' TOS_FIXED_CLOCK={now} exec '{}' \"$@\"\n",
                        fixed_clock_library().display(),
                        verifier().display()
                    ),
                );
                wrapper
            }
        }
    }

    /// The stand-in verifier with `behaviour`.
    fn fake_verifier(&self, behaviour: serde_json::Value) -> PathBuf {
        let behaviour_path = self.path("behaviour.json");
        std::fs::write(&behaviour_path, behaviour.to_string()).unwrap();
        let wrapper = self.path("fake-verifier");
        write_executable(
            &wrapper,
            &format!(
                "#!/bin/sh\nexec '{}' '{}' '{}' \"$@\"\n",
                find_on_path("python3").display(),
                fixtures().join("fake_verifier.py").display(),
                behaviour_path.display()
            ),
        );
        wrapper
    }

    fn config(&self, executable: PathBuf, material: PathBuf, live: bool) -> ProofVerifierConfig {
        ProofVerifierConfig {
            executable,
            anchor_file: fixtures().join("anchor.json"),
            liteserver_config: None,
            material_dir: Some(material),
            live_state_file: live.then(|| self.path("live-state.json")),
            live_max_age_seconds: live.then_some(LIVE_MAX_AGE),
            timeout_seconds: 60,
            min_interval_ms: 0,
        }
    }
}

fn address(text: &str) -> MsgAddressInt {
    MsgAddressInt::from_str(text).unwrap()
}

fn target() -> MasterchainCheckpoint {
    MasterchainCheckpoint {
        seqno: TARGET_SEQNO,
        root_hash: TARGET_ROOT.to_owned(),
        file_hash: TARGET_FILE.to_owned(),
    }
}

fn historical() -> ReadPolicy {
    ReadPolicy::Historical(target())
}

fn elector_calls() -> Vec<GetMethodCall> {
    vec![
        GetMethodCall::new("active_election_id"),
        GetMethodCall::new("past_election_ids"),
        GetMethodCall {
            method: "compute_returned_stake".to_owned(),
            args: vec![GetMethodArg::Int("5".to_owned())],
        },
    ]
}

fn historical_material() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("chain-0000.tl", fixture("chain-anchor-to-638197.tl")),
        ("account.tl", fixture("elector-account-638197.tl")),
        ("exec-config.tl", fixture("exec-config-638197.tl")),
    ]
}

fn with_file(
    mut files: Vec<(&'static str, Vec<u8>)>,
    name: &'static str,
    bytes: Vec<u8>,
) -> Vec<(&'static str, Vec<u8>)> {
    files.retain(|(existing, _)| *existing != name);
    files.push((name, bytes));
    files
}

async fn read_elector(
    case: &Case,
    executable: PathBuf,
    files: Vec<(&'static str, Vec<u8>)>,
    policy: ReadPolicy,
    clock: Option<i64>,
) -> anyhow::Result<ProvenGetterResults> {
    let live = policy == ReadPolicy::Live;
    let material = case.material(&files);
    let mut provider = ProvenGetterProvider::new(&case.config(executable, material, live)).unwrap();
    if let Some(now) = clock {
        provider = provider.with_clock(Arc::new(move || now));
    }
    provider.run(&address(ELECTOR), &elector_calls(), &policy).await
}

fn assert_refused<T: std::fmt::Debug>(result: anyhow::Result<T>, expected: &str) {
    match result {
        Ok(value) => panic!("expected a refusal containing {expected:?}, got {value:?}"),
        Err(error) => {
            let text = format!("{error:#}");
            assert!(text.contains(expected), "refused for another reason: {text}");
        }
    }
}

/// The values the elector's proven state yields at the target block.
fn assert_elector_values(results: &ProvenGetterResults) {
    assert_eq!(results.results.len(), 3);
    assert_eq!(results.results[0].stack.i64(0).unwrap(), 1791201524, "active_election_id");
    let past = results.results[1].stack.list_or_empty(0).unwrap();
    assert_eq!(past.i64(0).unwrap(), 1790945281, "past_election_ids");
    assert_eq!(results.results[2].stack.i64(0).unwrap(), 0, "compute_returned_stake(5)");
    assert_eq!(results.account.address, ELECTOR);
    assert_eq!(
        results.account.state_hash,
        "7d5d8d3096cfcdddf75fd2516c7ae610c7f041decb61c9afa04e728bc4c284bc"
    );
}

// ─────────────── TL editing of a recorded account answer ───────────────

/// `liteServer.accountState id shardblk shard_proof proof state`.
struct AccountAnswer {
    constructor: [u8; 4],
    id: [u8; 80],
    shard_block: [u8; 80],
    shard_proof: Vec<u8>,
    proof: Vec<u8>,
    state: Vec<u8>,
}

fn read_tl_bytes(data: &[u8], offset: &mut usize) -> Vec<u8> {
    let (length, header) = if data[*offset] < 254 {
        (data[*offset] as usize, 1)
    } else {
        let mut bytes = [0u8; 4];
        bytes[..3].copy_from_slice(&data[*offset + 1..*offset + 4]);
        (u32::from_le_bytes(bytes) as usize, 4)
    };
    let start = *offset + header;
    let value = data[start..start + length].to_vec();
    *offset = start + length + (4 - (header + length) % 4) % 4;
    value
}

fn write_tl_bytes(out: &mut Vec<u8>, value: &[u8]) {
    let header = if value.len() < 254 {
        out.push(value.len() as u8);
        1
    } else {
        out.push(254);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes()[..3]);
        4
    };
    out.extend_from_slice(value);
    out.extend(std::iter::repeat_n(0u8, (4 - (header + value.len()) % 4) % 4));
}

impl AccountAnswer {
    fn parse(data: &[u8]) -> Self {
        let mut offset = 4 + 80 + 80;
        let shard_proof = read_tl_bytes(data, &mut offset);
        let proof = read_tl_bytes(data, &mut offset);
        let state = read_tl_bytes(data, &mut offset);
        assert_eq!(offset, data.len(), "the whole answer was parsed");
        Self {
            constructor: data[0..4].try_into().unwrap(),
            id: data[4..84].try_into().unwrap(),
            shard_block: data[84..164].try_into().unwrap(),
            shard_proof,
            proof,
            state,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.constructor);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.shard_block);
        write_tl_bytes(&mut out, &self.shard_proof);
        write_tl_bytes(&mut out, &self.proof);
        write_tl_bytes(&mut out, &self.state);
        out
    }

    fn with_account(mut self, edit: impl FnOnce(&mut Account)) -> Self {
        let cell = read_single_root_boc(&self.state).unwrap();
        let mut account = Account::construct_from_cell(cell).unwrap();
        edit(&mut account);
        self.state = write_boc(&account.serialize().unwrap()).unwrap();
        self
    }
}

fn elector_with_account(edit: impl FnOnce(&mut Account)) -> Vec<u8> {
    AccountAnswer::parse(&fixture("elector-account-638197.tl")).with_account(edit).serialize()
}

fn edited_elector(edit: impl FnOnce(&mut AccountAnswer)) -> Vec<u8> {
    let mut answer = AccountAnswer::parse(&fixture("elector-account-638197.tl"));
    edit(&mut answer);
    answer.serialize()
}

// ───── control: wrong shard, wrong account, altered state, substituted context ─────

#[tokio::test]
async fn a_proven_read_runs_every_getter_on_the_proven_account() {
    let case = Case::new();
    let results =
        read_elector(&case, verifier(), historical_material(), historical(), None).await.unwrap();
    assert_elector_values(&results);
    assert!(!results.live);
    assert_eq!(results.checkpoint, target());
    assert_eq!(results.block_gen_utime, TARGET_UTIME);
}

#[tokio::test]
async fn re_encoding_an_unaltered_account_changes_nothing() {
    // Positive control for the edits below: the TL and account round trip
    // alone must not disturb verification.
    let case = Case::new();
    let account = elector_with_account(|_| {});
    assert_eq!(account, fixture("elector-account-638197.tl"), "round trip is byte-exact");
    let files = with_file(historical_material(), "account.tl", account);
    let results = read_elector(&case, verifier(), files, historical(), None).await.unwrap();
    assert_elector_values(&results);
}

#[tokio::test]
async fn an_altered_balance_is_refused() {
    let case = Case::new();
    let account = elector_with_account(|account| {
        account.set_balance(CurrencyCollection::with_coins(1));
    });
    let files = with_file(historical_material(), "account.tl", account);
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "account is not proven at the target",
    );
}

#[tokio::test]
async fn altered_account_code_is_refused() {
    let case = Case::new();
    let account = elector_with_account(|account| {
        let data = account.get_data().unwrap();
        assert!(account.set_code(data), "code replaced");
    });
    let files = with_file(historical_material(), "account.tl", account);
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "account is not proven at the target",
    );
}

#[tokio::test]
async fn altered_account_data_is_refused() {
    let case = Case::new();
    let account = elector_with_account(|account| {
        assert!(account.set_data(chain_block::Cell::default()), "data replaced");
    });
    let files = with_file(historical_material(), "account.tl", account);
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "account is not proven at the target",
    );
}

#[tokio::test]
async fn another_accounts_proof_is_refused() {
    // The endpoint answers the elector request with the pool's proven state.
    let case = Case::new();
    let files = with_file(historical_material(), "account.tl", fixture("pool-account-638197.tl"));
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "account is not proven at the target",
    );
}

/// The basechain pool's own material reaches its getters (which throw on
/// this network), so a refusal before them is the shard check's.
async fn read_pool(
    case: &Case,
    account: Vec<u8>,
) -> anyhow::Result<contracts::NominatorPoolSnapshot> {
    let material = case.material(&[
        ("chain-0000.tl", fixture("chain-anchor-to-638197.tl")),
        ("account.tl", account),
        ("exec-config.tl", fixture("exec-config-638197.tl")),
    ]);
    let provider = ProvenGetterProvider::new(&case.config(verifier(), material, false)).unwrap();
    read_proven_nominator_pool_snapshot(&provider, &address(POOL), &historical()).await
}

#[tokio::test]
async fn a_pool_whose_getter_fails_locally_has_no_snapshot() {
    let case = Case::new();
    assert_refused(
        read_pool(&case, fixture("pool-account-638197.tl")).await,
        "get-method get_pool_data failed with exit code 11",
    );
}

#[tokio::test]
async fn a_basechain_account_proven_through_another_shard_is_refused() {
    for (what, edit) in [
        (
            "shard prefix",
            Box::new(|bytes: &mut [u8; 80]| {
                bytes[4..12].copy_from_slice(&0x4000_0000_0000_0000u64.to_le_bytes())
            }) as Box<dyn Fn(&mut [u8; 80])>,
        ),
        ("shard seqno", Box::new(|bytes: &mut [u8; 80]| bytes[12] ^= 1)),
        ("shard root hash", Box::new(|bytes: &mut [u8; 80]| bytes[16] ^= 1)),
    ] {
        let case = Case::new();
        let mut answer = AccountAnswer::parse(&fixture("pool-account-638197.tl"));
        edit(&mut answer.shard_block);
        let result = read_pool(&case, answer.serialize()).await;
        let text = format!("{:#}", result.expect_err(what));
        assert!(text.contains("account is not proven at the target"), "{what}: {text}");
    }
}

#[tokio::test]
async fn a_masterchain_account_proven_from_a_shard_block_is_refused() {
    let case = Case::new();
    let pool = AccountAnswer::parse(&fixture("pool-account-638197.tl"));
    let account = edited_elector(|answer| answer.shard_block = pool.shard_block);
    let files = with_file(historical_material(), "account.tl", account);
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "account proof omits its shard proof",
    );
}

#[tokio::test]
async fn configuration_from_another_block_is_refused() {
    let case = Case::new();
    let files =
        with_file(historical_material(), "exec-config.tl", fixture("live-638326/exec-config.tl"));
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "execution configuration",
    );
}

#[tokio::test]
async fn missing_execution_configuration_is_refused() {
    let case = Case::new();
    let mut files = historical_material();
    files.retain(|(name, _)| *name != "exec-config.tl");
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "execution configuration proof is missing",
    );
}

#[tokio::test]
async fn an_endpoint_cannot_supply_execution_context_or_results() {
    // There is no place in the material for a context, a stack or a verdict:
    // anything of the kind is refused, never read.
    for name in ["c7.tl", "context.json", "get-methods.json", "result.json"] {
        let case = Case::new();
        let files = with_file(historical_material(), name, b"{\"status\":\"verified\"}".to_vec());
        assert_refused(
            read_elector(&case, verifier(), files, historical(), None).await,
            &format!("material directory has an unexpected entry {name}"),
        );
    }
}

#[tokio::test]
async fn live_material_is_refused_in_a_historical_read() {
    let case = Case::new();
    let files = with_file(
        historical_material(),
        "masterchain-info.tl",
        fixture("live-638197/masterchain-info.tl"),
    );
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "historical mode does not accept live material",
    );
}

#[tokio::test]
async fn a_historical_read_of_another_block_is_refused() {
    let case = Case::new();
    let mut other = target();
    other.root_hash = "ab".repeat(32);
    assert_refused(
        read_elector(&case, verifier(), historical_material(), ReadPolicy::Historical(other), None)
            .await,
        "proof chain does not end at the exact target block",
    );
}

#[tokio::test]
async fn a_truncated_proof_chain_is_refused() {
    let case = Case::new();
    let mut chain = fixture("chain-anchor-to-638197.tl");
    chain.truncate(chain.len() / 2);
    let files = with_file(historical_material(), "chain-0000.tl", chain);
    assert_refused(
        read_elector(&case, verifier(), files, historical(), None).await,
        "proof chain response is not the expected lite API answer",
    );
}

// ───── control: live rollback, same-height conflict, expiry; historical stays valid ─────

fn live_a_material() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("masterchain-info.tl", fixture("live-638197/masterchain-info.tl")),
        ("chain-0000.tl", fixture("chain-anchor-to-638197.tl")),
        ("account.tl", fixture("elector-account-638197.tl")),
        ("exec-config.tl", fixture("live-638197/exec-config.tl")),
    ]
}

fn live_b_material() -> Vec<(&'static str, Vec<u8>)> {
    ["masterchain-info.tl", "chain-0000.tl", "descent-0000.tl", "account.tl", "exec-config.tl"]
        .into_iter()
        .map(|name| (name, fixture(&format!("live-638326/{name}"))))
        .collect()
}

/// A live state record whose head is `head`.
fn live_state_with_head(seqno: u32, root: &str, file: &str, utime: u32) -> String {
    let anchor: serde_json::Value = serde_json::from_slice(&fixture("anchor.json")).unwrap();
    serde_json::json!({
        "interface": "tos-proof-verify-state/1",
        "anchor": anchor,
        "head": {"workchain": -1, "shard": "8000000000000000", "seqno": seqno,
                 "root_hash": root, "file_hash": file, "gen_utime": utime},
    })
    .to_string()
}

#[tokio::test]
async fn a_fresh_live_read_is_accepted_and_committed() {
    let case = Case::new();
    let executable = case.real_verifier(Some(LIVE_A_NOW));
    let results =
        read_elector(&case, executable, live_a_material(), ReadPolicy::Live, Some(LIVE_A_NOW))
            .await
            .unwrap();
    assert!(results.live);
    assert_eq!(results.checkpoint, target());
    assert_elector_values(&results);
    let state = std::fs::read_to_string(case.path("live-state.json")).unwrap();
    assert!(state.contains(TARGET_ROOT), "the verified head is recorded: {state}");
}

#[tokio::test]
async fn a_live_read_extending_the_verified_head_is_accepted() {
    let case = Case::new();
    std::fs::write(case.path("live-state.json"), fixture("live-state-at-638197.json")).unwrap();
    let executable = case.real_verifier(Some(LIVE_B_NOW));
    let results =
        read_elector(&case, executable, live_b_material(), ReadPolicy::Live, Some(LIVE_B_NOW))
            .await
            .unwrap();
    assert_eq!(results.checkpoint.seqno, LIVE_B_SEQNO);
}

#[tokio::test]
async fn a_live_rollback_below_the_verified_head_is_refused() {
    let case = Case::new();
    std::fs::write(
        case.path("live-state.json"),
        live_state_with_head(LIVE_B_SEQNO, &"82".repeat(32), &"9c".repeat(32), 1791201493),
    )
    .unwrap();
    let executable = case.real_verifier(Some(LIVE_A_NOW));
    assert_refused(
        read_elector(&case, executable, live_a_material(), ReadPolicy::Live, Some(LIVE_A_NOW))
            .await,
        "rollback refused",
    );
}

#[tokio::test]
async fn a_live_block_conflicting_with_the_verified_head_is_refused() {
    let case = Case::new();
    std::fs::write(
        case.path("live-state.json"),
        live_state_with_head(TARGET_SEQNO, &"ab".repeat(32), TARGET_FILE, TARGET_UTIME),
    )
    .unwrap();
    let executable = case.real_verifier(Some(LIVE_A_NOW));
    assert_refused(
        read_elector(&case, executable, live_a_material(), ReadPolicy::Live, Some(LIVE_A_NOW))
            .await,
        "conflicts with the verified head at the same height",
    );
}

#[tokio::test]
async fn an_expired_live_observation_is_refused_by_the_verifier() {
    let case = Case::new();
    let now = LIVE_A_NOW + i64::from(LIVE_MAX_AGE) + 10;
    let executable = case.real_verifier(Some(now));
    assert_refused(
        read_elector(&case, executable, live_a_material(), ReadPolicy::Live, Some(now)).await,
        "above the maximum age",
    );
    assert!(!case.path("live-state.json").exists(), "nothing is committed for a refused read");
}

#[tokio::test]
async fn an_expired_live_observation_is_refused_by_the_local_clock() {
    // The verifier's clock accepts it; the consumer's own clock does not.
    let case = Case::new();
    let executable = case.real_verifier(Some(LIVE_A_NOW));
    let late = LIVE_A_NOW + i64::from(LIVE_MAX_AGE) + 10;
    assert_refused(
        read_elector(&case, executable, live_a_material(), ReadPolicy::Live, Some(late)).await,
        "old by the local clock",
    );
}

#[tokio::test]
async fn historical_evidence_stays_valid_at_any_age() {
    // The real clock is long past the material's time; an explicitly
    // historical read does not care.
    let case = Case::new();
    let results = read_elector(
        &case,
        case.real_verifier(Some(LIVE_A_NOW + 365 * 24 * 3600)),
        historical_material(),
        historical(),
        Some(LIVE_A_NOW + 365 * 24 * 3600),
    )
    .await
    .unwrap();
    assert_elector_values(&results);
}

// ───── control: helper failure, malformed output, mismatched binding ─────

fn pool_stacks() -> serde_json::Value {
    let int = |value: &str| serde_json::json!({"type": "int", "value": value});
    let nil = serde_json::json!({"type": "null"});
    let nominator = |key: &str, amount: &str| serde_json::json!({"type": "tuple", "items": [int(key), int(amount), int("25"), int("0")]});
    serde_json::json!({
        "get_pool_data": [
            int("1"), int("2"), int("3000"), int("2000"), int("2748"), int("3567"),
            int("4000"), int("40"), int("1000"), int("100"), nil.clone(), nil.clone(),
            int("999"), int("17"), int("2"), int("1234"), int("3600"), nil.clone(),
        ],
        "list_nominators": [{"type": "tuple", "items": [
            nominator("43981", "700"),
            {"type": "tuple", "items": [nominator("4660", "800"), nil.clone()]},
        ]}],
    })
}

fn behaviour(mutation: &str) -> serde_json::Value {
    serde_json::json!({
        "stacks": pool_stacks(),
        "mutation": mutation,
        "target": {"seqno": TARGET_SEQNO, "root_hash": TARGET_ROOT, "file_hash": TARGET_FILE},
        "gen_utime": TARGET_UTIME,
        "now": LIVE_A_NOW,
    })
}

async fn pool_through(
    case: &Case,
    executable: PathBuf,
    policy: ReadPolicy,
) -> anyhow::Result<contracts::NominatorPoolSnapshot> {
    let material = case.material(&[]);
    let provider =
        ProvenGetterProvider::new(&case.config(executable, material, policy == ReadPolicy::Live))
            .unwrap()
            .with_clock(Arc::new(|| LIVE_A_NOW));
    read_proven_nominator_pool_snapshot(&provider, &address(POOL), &policy).await
}

#[tokio::test]
async fn a_bound_answer_becomes_a_pool_snapshot() {
    for policy in [historical(), ReadPolicy::Live] {
        let case = Case::new();
        let snapshot = pool_through(&case, case.fake_verifier(behaviour("none")), policy.clone())
            .await
            .unwrap();
        assert_eq!(snapshot.checkpoint, target());
        assert_eq!(snapshot.pool.state, 1);
        assert_eq!(snapshot.pool.nominators_count, 2);
        assert_eq!(snapshot.pool.stake_amount_sent, 3000);
        assert_eq!(snapshot.pool.validator_address[31], 0xbc);
        assert_eq!(snapshot.pool.controller_address[31], 0xef);
        assert_eq!(snapshot.pool.stake_held_for, 3600);
        assert_eq!(snapshot.nominators.len(), 2);
        assert_eq!(snapshot.nominators[0].amount, 700);
        assert_eq!(snapshot.nominators[1].amount, 800);
        assert_eq!(snapshot.proof.account_state_hash, "5a".repeat(32));
        assert_eq!(snapshot.proof.live, policy == ReadPolicy::Live);
    }
}

#[tokio::test]
async fn a_missing_verifier_yields_no_snapshot() {
    let case = Case::new();
    assert_refused(
        pool_through(&case, case.path("not-installed"), historical()).await,
        "cannot start the proof verifier",
    );
}

#[tokio::test]
async fn a_verifier_that_does_not_answer_in_time_yields_no_snapshot() {
    let case = Case::new();
    let material = case.material(&[]);
    let mut config = case.config(case.fake_verifier(behaviour("sleep")), material, false);
    config.timeout_seconds = 2;
    let provider = ProvenGetterProvider::new(&config).unwrap();
    assert_refused(
        read_proven_nominator_pool_snapshot(&provider, &address(POOL), &historical()).await,
        "did not answer within",
    );
}

/// Every way an answer can fail to be a verified answer to this request.
const UNBOUND_ANSWERS: &[(&str, &str)] = &[
    ("nonzero_exit", "proof verifier refused (exit 1)"),
    ("refusal", "test refusal"),
    ("status", "did not verify the read"),
    ("interface", "speaks another interface"),
    ("malformed", "malformed or incomplete"),
    ("partial", "malformed or incomplete"),
    ("empty", "not one line"),
    ("trailing", "malformed or incomplete"),
    ("two_lines", "not one JSON object"),
    ("missing:get_methods", "malformed or incomplete"),
    ("missing:account", "malformed or incomplete"),
    ("missing:target", "malformed or incomplete"),
    ("missing:anchor", "malformed or incomplete"),
    ("missing:request_sha256", "malformed or incomplete"),
    ("missing:execution_context", "malformed or incomplete"),
    ("anchor", "started from another anchor"),
    ("request_hash", "answered another request"),
    ("target", "answered for another block"),
    ("target_seqno", "answered for another block"),
    ("mode", "did a live read"),
    ("live_evidence", "historical read carries live evidence"),
    ("account", "read another account"),
    ("inactive", "proven account is not active"),
    ("shard_workchain", "another workchain"),
    ("method", "ran get_other_data for get_pool_data"),
    ("method_order", "ran list_nominators for get_pool_data"),
    ("method_id", "another method id"),
    ("args", "with other arguments"),
    ("method_count", "ran 1 get-methods, 2 were requested"),
    ("exit_code", "exited with 11"),
    ("stack_type", "no decoder accepts"),
];

#[tokio::test]
async fn an_answer_not_bound_to_the_request_yields_no_snapshot() {
    for (mutation, expected) in UNBOUND_ANSWERS {
        let case = Case::new();
        let result =
            pool_through(&case, case.fake_verifier(behaviour(mutation)), historical()).await;
        match result {
            Ok(snapshot) => panic!("{mutation}: accepted {snapshot:?}"),
            Err(error) => {
                let text = format!("{error:#}");
                assert!(text.contains(expected), "{mutation}: refused for another reason: {text}");
            }
        }
    }
}

#[tokio::test]
async fn a_live_answer_not_bound_to_the_live_policy_yields_no_snapshot() {
    for (mutation, expected) in [
        ("mode", "did a historical read"),
        ("max_age", "applied another maximum age"),
        ("missing:live", "carries no live evidence"),
    ] {
        let case = Case::new();
        let result =
            pool_through(&case, case.fake_verifier(behaviour(mutation)), ReadPolicy::Live).await;
        let text = format!("{:#}", result.expect_err(mutation));
        assert!(text.contains(expected), "{mutation}: refused for another reason: {text}");
    }
}

#[tokio::test]
async fn a_masterchain_answer_from_another_block_yields_no_snapshot() {
    let case = Case::new();
    let material = case.material(&[]);
    let provider = ProvenGetterProvider::new(&case.config(
        case.fake_verifier(behaviour("shard_block")),
        material,
        false,
    ))
    .unwrap();
    assert_refused(
        provider
            .run(&address(ELECTOR), &[GetMethodCall::new("get_pool_data")], &historical())
            .await,
        "masterchain account was proven from another block",
    );
}

#[tokio::test]
async fn the_request_names_the_account_both_methods_and_the_exact_block() {
    let case = Case::new();
    let log = case.path("requests.jsonl");
    let mut behaviour = behaviour("none");
    behaviour["log"] = log.display().to_string().into();
    pool_through(&case, case.fake_verifier(behaviour), historical()).await.unwrap();
    let logged: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&log).unwrap().trim()).unwrap();
    assert_eq!(
        logged["request"],
        serde_json::json!({
            "mode": "historical",
            "target": {"seqno": TARGET_SEQNO, "root_hash": TARGET_ROOT, "file_hash": TARGET_FILE},
            "account": POOL,
            "get_methods": [
                {"method": "get_pool_data", "args": []},
                {"method": "list_nominators", "args": []},
            ],
        })
    );
    assert_eq!(
        logged["options"]["--anchor"],
        fixtures().join("anchor.json").display().to_string(),
        "the anchor is the locally provisioned file"
    );
    assert!(logged["options"].get("--state").is_none(), "a historical read keeps no live state");
}

// ───── a real lite-server (opt-in) ─────

/// Reads the elector's proven state from a running lite-server, live. Needs
/// `TOS_PROOF_LITESERVER` (a lite client config), `TOS_PROOF_ZEROSTATE` (the
/// network's masterchain zerostate file, obtained independently) and the
/// verifier. One verifier run, its queries spaced by 300 ms.
#[tokio::test]
#[ignore = "needs a running lite-server: set TOS_PROOF_LITESERVER and TOS_PROOF_ZEROSTATE"]
async fn a_live_read_from_a_real_lite_server() {
    let liteserver = PathBuf::from(std::env::var("TOS_PROOF_LITESERVER").unwrap());
    let zerostate = PathBuf::from(std::env::var("TOS_PROOF_ZEROSTATE").unwrap());
    let case = Case::new();
    let anchor = std::process::Command::new(verifier())
        .arg("anchor")
        .arg("--zerostate")
        .arg(&zerostate)
        .output()
        .unwrap();
    assert!(anchor.status.success(), "{}", String::from_utf8_lossy(&anchor.stdout));
    std::fs::write(case.path("anchor.json"), &anchor.stdout).unwrap();
    let config = ProofVerifierConfig {
        executable: verifier(),
        anchor_file: case.path("anchor.json"),
        liteserver_config: Some(liteserver),
        material_dir: None,
        live_state_file: Some(case.path("live-state.json")),
        live_max_age_seconds: Some(LIVE_MAX_AGE),
        timeout_seconds: 300,
        min_interval_ms: 300,
    };
    let provider = ProvenGetterProvider::new(&config).unwrap();
    let results = provider.run(&address(ELECTOR), &elector_calls(), &ReadPolicy::Live).await;
    let results = results.unwrap();
    println!(
        "live proven read: block {} ({}), age {} s, account state {}, active_election_id {}, \
         gas {:?}",
        results.checkpoint.seqno,
        results.checkpoint.root_hash,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(u64::from(results.block_gen_utime)),
        results.account.state_hash,
        results.results[0].stack.i64(0).unwrap(),
        results.results.iter().map(|r| r.gas_used).collect::<Vec<_>>(),
    );
    assert!(results.live);
    assert_eq!(results.account.address, ELECTOR);
    let pool =
        read_proven_nominator_pool_snapshot(&provider, &address(POOL), &ReadPolicy::Live).await;
    println!(
        "live pool snapshot: {:?}",
        pool.as_ref().map(|s| &s.checkpoint).map_err(|e| format!("{e:#}"))
    );
}
