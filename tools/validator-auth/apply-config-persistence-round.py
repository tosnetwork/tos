from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


# The registry and the consumed external-message sequence number are one state
# transition. commit() checkpoints c4, so parameter 46 must be in c4 before the
# checkpoint is taken. Otherwise an out-of-gas exit after commit() can expose a
# successful native apply while the committed data still contains the old
# registry.
config = ROOT / "crypto/smartcont/config-code.fc"
old_order = """    store_data(cfg_dict, stored_seqno, public_key, vote_dict);\n    commit();\n    set_conf_param(46, registry);\n    return ();\n"""
new_order = """    store_data(cfg_dict, stored_seqno, public_key, vote_dict);\n    set_conf_param(46, registry);\n    commit();\n    return ();\n"""
replace_once(config, old_order, new_order, "config commit ordering")

# config-code.fc is frozen against the original production baseline. The whole
# validator-auth branch is already one declared insertion at original offset
# 20671, so changing its inserted bytes preserves the additive boundary: the
# baseline file still reconstructs exactly by applying this insertion record.
manifest_path = ROOT / "doc/validator-auth-p0-native-insertions.json"
manifest = json.loads(manifest_path.read_text())
entries = manifest["insertions"]["crypto/smartcont/config-code.fc"]
entry = next((item for item in entries if item["offset"] == 20671), None)
if entry is None:
    raise RuntimeError("config insertion at original offset 20671 is missing")
if entry["text"].count(old_order) != 1:
    raise RuntimeError("config insertion ordering anchor is not unique")
entry["text"] = entry["text"].replace(old_order, new_order, 1)
manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")

# Carry the native authority through the real transaction executor. This is a
# host-process input, not a contract register or c7 field, and therefore cannot
# be constructed by the contract being executed.
executor = ROOT / "tosctl/src/executor/src/transaction_executor.rs"
replace_once(
    executor,
    "    sync::{Arc, LazyLock},\n",
    "    sync::{Arc, LazyLock, Mutex},\n",
    "executor mutex import",
)
replace_once(
    executor,
    "    pub trace_callback: Option<Arc<tos_vm::executor::TraceCallback>>,\n    pub behavior_modifiers: Option<BehaviorModifiers>,\n",
    "    pub trace_callback: Option<Arc<tos_vm::executor::TraceCallback>>,\n"
    "    /// Native transaction authority supplied by the host process. Contract\n"
    "    /// registers and c7 cannot construct or replace this value.\n"
    "    pub validator_auth_host: Option<\n"
    "        Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    >,\n"
    "    pub behavior_modifiers: Option<BehaviorModifiers>,\n",
    "executor host parameter",
)
replace_once(
    executor,
    "        vm.set_block_version(self.config().block_version());\n        if let Some(modifiers) = params.behavior_modifiers.clone() {\n",
    "        vm.set_block_version(self.config().block_version());\n"
    "        if let Some(host) = params.validator_auth_host.clone() {\n"
    "            vm.set_validator_auth_host(host);\n"
    "        }\n"
    "        if let Some(modifiers) = params.behavior_modifiers.clone() {\n",
    "executor host installation",
)

# The sandbox exposes the same host-only input so integration tests cross the
# ordinary transaction executor and its real action phase instead of simulating
# either phase around a bare VM.
sandbox = ROOT / "tosctl/src/sandbox/src/blockchain.rs"
replace_once(
    sandbox,
    "use std::mem;\n",
    "use std::mem;\nuse std::sync::{Arc, Mutex};\n",
    "sandbox sync import",
)
replace_once(
    sandbox,
    "    tos_method_id, Account, ConfigParams, CurrencyCollection, Deserializable, McStateExtra,\n"
    "    MerkleProof, Message, MsgAddressInt, Serializable, ShardIdent, ShardStateUnsplit,\n"
    "    SizeLimitsConfig, Transaction,\n",
    "    tos_method_id, Account, ConfigParam8, ConfigParamEnum, ConfigParams, CurrencyCollection,\n"
    "    Deserializable, GlobalVersion, McStateExtra, MerkleProof, Message, MsgAddressInt,\n"
    "    Serializable, ShardIdent, ShardStateUnsplit, SizeLimitsConfig, Transaction,\n",
    "sandbox config imports",
)
replace_once(
    sandbox,
    "    transaction_log: Vec<(MsgAddressInt, Transaction)>,\n}",
    "    transaction_log: Vec<(MsgAddressInt, Transaction)>,\n"
    "    validator_auth_host: Option<\n"
    "        Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>,\n"
    "    >,\n}"
,
    "sandbox host field",
)
init_anchor = "            transaction_log: Vec::new(),\n        })"
if sandbox.read_text().count(init_anchor) != 4:
    raise RuntimeError("sandbox constructor count changed")
sandbox.write_text(
    sandbox.read_text().replace(
        init_anchor,
        "            transaction_log: Vec::new(),\n            validator_auth_host: None,\n        })",
    )
)
replace_once(
    sandbox,
    "    /// Create a version-pinned sandbox whose configuration admits standard\n",
    "    /// Create a version-pinned sandbox with an explicit capability mask.\n"
    "    /// This is a local executor fixture; it does not activate a network.\n"
    "    pub fn with_global_version_and_capabilities(\n"
    "        global_version: u32,\n"
    "        capabilities: u64,\n"
    "    ) -> SandboxResult<Self> {\n"
    "        let base = BlockchainConfig::default_with_global_version(global_version)\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        let mut config = base.raw_config().clone();\n"
    "        config\n"
    "            .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {\n"
    "                global_version: GlobalVersion { version: global_version, capabilities },\n"
    "            }))\n"
    "            .map_err(|e| SandboxError::ConfigError(e.to_string()))?;\n"
    "        Self::with_config(config)\n"
    "    }\n\n"
    "    /// Create a version-pinned sandbox whose configuration admits standard\n",
    "sandbox capability constructor",
)
replace_once(
    sandbox,
    "    pub fn set_account(&mut self, address: MsgAddressInt, account: Account) {\n"
    "        self.accounts.insert(address.to_string(), account);\n"
    "    }\n",
    "    pub fn set_account(&mut self, address: MsgAddressInt, account: Account) {\n"
    "        self.accounts.insert(address.to_string(), account);\n"
    "    }\n\n"
    "    /// Install a host-only validator-auth authority for subsequent local\n"
    "    /// transactions. Snapshots deliberately do not persist this authority.\n"
    "    pub fn set_validator_auth_host(\n"
    "        &mut self,\n"
    "        host: Option<Arc<Mutex<dyn tos_vm::validator_auth_host::ValidatorAuthHost>>>,\n"
    "    ) {\n"
    "        self.validator_auth_host = host;\n"
    "    }\n",
    "sandbox host setter",
)
replace_once(
    sandbox,
    "            last_tr_lt: self.next_lt,\n            ..ExecuteParams::default()\n",
    "            last_tr_lt: self.next_lt,\n"
    "            validator_auth_host: self.validator_auth_host.clone(),\n"
    "            ..ExecuteParams::default()\n",
    "sandbox host propagation",
)

# Real action-phase evidence lives beside the existing sandbox lifecycle tests.
# The cells are exported by the C++ built-contract fixture so both languages run
# the same code, update, evidence, old registry and expected new registry.
rust_test = ROOT / "tosctl/src/node-control/contracts/tests/native_registry_sandbox.rs"
marker = "mod config_persistence_action_phase {"
if marker in rust_test.read_text():
    raise RuntimeError("config persistence action-phase module already exists")
module = r'''

mod config_persistence_action_phase {
    use super::*;
    use chain_block::{
        Account, CurrencyCollection, GlobalCapabilities, HashmapE, HashmapType, SizeLimitsConfig,
        TrComputePhase, DICT_HASH_MIN_CELLS,
    };
    use std::{
        fs,
        io::Write,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };
    use tos_vm::validator_auth_host::ValidatorAuthHost;

    const CONFIG_BALANCE: u64 = 10_000_000_000_000;
    const ACTION_LIMIT_FAILURE: i32 = 50;

    struct Cells {
        contract: Cell,
        before: Cell,
        after: Cell,
        update: Cell,
        evidence: Cell,
        body: Cell,
        empty_data: Cell,
        old_data: Cell,
    }

    fn read_cell(root: &Path, name: &str) -> Cell {
        read_single_root_boc(fs::read(root.join(name)).expect("fixture cell bytes"))
            .expect("fixture cell boc")
    }

    fn cells() -> Cells {
        let root = PathBuf::from(
            std::env::var("P0_CONFIG_PERSISTENCE_CELLS")
                .expect("P0_CONFIG_PERSISTENCE_CELLS must name exported built-contract cells"),
        );
        Cells {
            contract: read_cell(&root, "contract.boc"),
            before: read_cell(&root, "before.boc"),
            after: read_cell(&root, "after.boc"),
            update: read_cell(&root, "update.boc"),
            evidence: read_cell(&root, "evidence.boc"),
            body: read_cell(&root, "body.boc"),
            empty_data: read_cell(&root, "data-empty.boc"),
            old_data: read_cell(&root, "data-old.boc"),
        }
    }

    struct Host {
        expected_update: Cell,
        expected_evidence: Cell,
        returned_registry: Cell,
        applies: Arc<AtomicUsize>,
    }

    impl ValidatorAuthHost for Host {
        fn checkpoint(
            &mut self,
            charge: &mut dyn FnMut(i64) -> chain_block::Status,
        ) -> chain_block::Result<Cell> {
            charge(10)?;
            BuilderData::new().into_cell()
        }

        fn apply(
            &mut self,
            update: Cell,
            evidence: Cell,
            charge: &mut dyn FnMut(i64) -> chain_block::Status,
        ) -> chain_block::Result<Cell> {
            charge(10)?;
            assert_eq!(update.hash(0), self.expected_update.hash(0), "update operand changed");
            assert_eq!(evidence.hash(0), self.expected_evidence.hash(0), "evidence operand changed");
            self.applies.fetch_add(1, Ordering::SeqCst);
            Ok(self.returned_registry.clone())
        }
    }

    fn parameter(data: &Cell, index: u32) -> Option<Cell> {
        let slice = SliceData::load_cell(data.clone()).expect("contract data");
        let root = slice.reference(0).expect("config dictionary root");
        let dict = HashmapE::with_hashmap(32, Some(root));
        let entry = dict.get(index.write_to_bitstring().expect("config key")).expect("config lookup")?;
        entry.reference_opt(0)
    }

    fn same_cell(left: Option<Cell>, right: &Cell) -> bool {
        left.is_some_and(|cell| cell.hash(0) == right.hash(0))
    }

    fn setup(initial_data: Cell, fixture: &Cells) -> (Blockchain, MsgAddressInt, Arc<AtomicUsize>) {
        let capabilities = 0x1ee | GlobalCapabilities::CapValidatorAuth as u64;
        let mut bc = Blockchain::with_global_version_and_capabilities(16, capabilities)
            .expect("version-pinned blockchain");
        let address = MsgAddressInt::standard(-1, [0x77; 32].into());
        let state_init = StateInit::with_code_and_data(fixture.contract.clone(), initial_data);
        let account = Account::active(
            address.clone(),
            CurrencyCollection::with_coins(CONFIG_BALANCE),
            0,
            bc.now(),
            state_init,
            DICT_HASH_MIN_CELLS,
        )
        .expect("configuration account");
        bc.set_account(address.clone(), account);

        let applies = Arc::new(AtomicUsize::new(0));
        let host: Arc<Mutex<dyn ValidatorAuthHost>> = Arc::new(Mutex::new(Host {
            expected_update: fixture.update.clone(),
            expected_evidence: fixture.evidence.clone(),
            returned_registry: fixture.after.clone(),
            applies: applies.clone(),
        }));
        bc.set_validator_auth_host(Some(host));
        (bc, address, applies)
    }

    fn send(bc: &mut Blockchain, address: &MsgAddressInt, body: Cell) -> SendResult {
        bc.send_message(MessageBuilder::external(address).body(body).build())
            .expect("configuration transaction")
    }

    fn persisted_data(bc: &Blockchain, address: &MsgAddressInt) -> Cell {
        bc.get_account(address)
            .expect("configuration account remains present")
            .get_data()
            .expect("configuration account data")
    }

    #[test]
    fn accepted_registry_persists_after_action_phase() {
        const NAME: &str = "accepted_registry_persists_after_action_phase";
        println!("SETUP_OK {NAME}");
        std::io::stdout().flush().unwrap();
        let fixture = cells();
        assert!(parameter(&fixture.empty_data, 46).is_none(), "fixture starts without parameter 46");
        let (mut bc, address, applies) = setup(fixture.empty_data.clone(), &fixture);
        let result = send(&mut bc, &address, fixture.body.clone());
        result.expect_success().expect_exit_code(0);
        assert_eq!(applies.load(Ordering::SeqCst), 1, "native apply must execute exactly once");
        let data = persisted_data(&bc, &address);
        assert!(same_cell(parameter(&data, 46), &fixture.after), "action phase did not persist the new registry");
        println!("CASE_PASS {NAME}");
    }

    #[test]
    fn refused_action_phase_rolls_registry_back() {
        const NAME: &str = "refused_action_phase_rolls_registry_back";
        println!("SETUP_OK {NAME}");
        std::io::stdout().flush().unwrap();
        let fixture = cells();
        assert!(same_cell(parameter(&fixture.old_data, 46), &fixture.before), "fixture must contain the old registry");
        let (mut bc, address, applies) = setup(fixture.old_data.clone(), &fixture);
        let mut limits = SizeLimitsConfig::default();
        limits.max_mc_acc_state_cells = 1;
        bc.set_size_limits_config(limits).expect("tight account limit");

        let result = send(&mut bc, &address, fixture.body.clone());
        result.expect_aborted().expect_exit_code(0);
        let descr = result.read_primary_description();
        let TrComputePhase::Vm(compute) = descr.compute_ph else {
            panic!("registry update did not execute in compute phase");
        };
        assert!(compute.success, "registry compute phase did not commit");
        let action = descr.action.expect("action phase must run");
        assert!(!action.success, "tight account limit must refuse the action phase");
        assert_eq!(action.result_code, ACTION_LIMIT_FAILURE, "unexpected action refusal");
        assert_eq!(applies.load(Ordering::SeqCst), 1, "native apply must execute before rollback");

        let data = persisted_data(&bc, &address);
        assert_eq!(data.hash(0), fixture.old_data.hash(0), "aborted action phase persisted compute data");
        assert!(same_cell(parameter(&data, 46), &fixture.before), "aborted action phase half-applied the registry");
        println!("CASE_PASS {NAME}");
    }
}
'''
rust_test.write_text(rust_test.read_text() + module)

# A compiled contract mutation harness: one mutation removes installation
# entirely; the second preserves final live c4 but moves installation back after
# commit, which must kill only the checkpoint-ordering cases (plus any measured
# companions). Every other case is run independently.
cpp_mutations = ROOT / "test/validator-auth-implementation/config_contract_persistence_mutations.py"
if cpp_mutations.exists():
    raise RuntimeError("config contract persistence mutation harness already exists")
cpp_mutations.write_text(r'''"""Compile registry persistence mutants and measure their exact case blast radius."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/config-code.fc"
BINARY = ROOT / "build-p0/test/validator-auth-implementation/test-p0-config-contract"
FUNC = ROOT / "build-p0/crypto/func"
FIFT = ROOT / "build-p0/crypto/fift"

MUTATIONS = [
    (
        "registry-installation",
        "registry-c4-installs-parameter-46",
        "    set_conf_param(46, registry);\n",
        "    ;; registry installation removed by compiled mutation\n",
        [
            "registry-c4-replaces-old-parameter-46",
            "registry-checkpoint-installs-before-interruption",
            "registry-checkpoint-replaces-before-interruption",
        ],
    ),
    (
        "registry-installed-before-commit",
        "registry-checkpoint-installs-before-interruption",
        "    set_conf_param(46, registry);\n    commit();\n",
        "    commit();\n    set_conf_param(46, registry);\n",
        ["registry-checkpoint-replaces-before-interruption"],
    ),
]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)


def compile_contract(out: Path) -> bool:
    out.mkdir(parents=True, exist_ok=True)
    fif = out / "config-code.fif"
    boc = out / "config-code.boc"
    first = run([str(FUNC), "-PS", "-o", str(fif), str(ROOT / "crypto/smartcont/stdlib.fc"), str(SOURCE)])
    (out / "compile.stdout").write_text(first.stdout)
    (out / "compile.stderr").write_text(first.stderr)
    if first.returncode != 0:
        return False
    assemble = out / "assemble.fif"
    assemble.write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    second = run([str(FIFT), "-I", str(ROOT / "crypto/fift/lib"), "-s", str(assemble)])
    (out / "assemble.stdout").write_text(second.stdout)
    (out / "assemble.stderr").write_text(second.stderr)
    return second.returncode == 0 and boc.is_file() and boc.stat().st_size > 0


def invoke(boc: Path, case: str) -> subprocess.CompletedProcess[str]:
    return run([str(BINARY), str(boc), case])


def passed(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 0
        and result.stderr == ""
        and f"CASE_PASS {case}" in result.stdout.splitlines()
        and result.stdout.splitlines()[-1:] == ["SUMMARY cases=1 passed=1"]
    )


def failed_named(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines()[:1] == [f"SETUP_OK {case}"]
        and result.stderr.splitlines()[-1:] == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    baseline_dir = out / "baseline"
    if not compile_contract(baseline_dir):
        print("BASELINE_COMPILE_FAILED", file=sys.stderr)
        return 1
    baseline_boc = baseline_dir / "config-code.boc"
    listed = run([str(BINARY), str(baseline_boc), "--list"])
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or listed.stderr or not cases:
        print("CASE_INVENTORY_FAILED", file=sys.stderr)
        return 1
    baseline = {case: invoke(baseline_boc, case) for case in cases}
    if not all(passed(result, case) for case, result in baseline.items()):
        print("BASELINE_NOT_PASSING", file=sys.stderr)
        return 1

    records = []
    failures = 0
    try:
        for guard, named_case, before, after, declared in MUTATIONS:
            current = SOURCE.read_text()
            if current != original or current.count(before) != 1:
                print(f"ANCHOR_NOT_UNIQUE {guard} {current.count(before)}", file=sys.stderr)
                failures += 1
                continue
            changed = current.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            mutant_dir = out / guard
            compiled = compile_contract(mutant_dir)
            observed = []
            results = {}
            if compiled:
                boc = mutant_dir / "config-code.boc"
                for case in cases:
                    result = invoke(boc, case)
                    results[case] = result
                    if not passed(result, case):
                        observed.append(case)
            named_result = results.get(named_case)
            named_failed = named_result is not None and failed_named(named_result, named_case)
            observed_companions = [case for case in observed if case != named_case]
            isolated = sorted(observed_companions) == sorted(declared)

            SOURCE.write_text(original)
            restore_dir = out / f"{guard}-restored"
            restored_compiled = compile_contract(restore_dir)
            restored = restored_compiled and all(
                passed(invoke(restore_dir / "config-code.boc", case), case) for case in cases
            )
            record = {
                "guard": guard,
                "case": named_case,
                "edit_reached_source": reached,
                "compiled": compiled,
                "named_assertion_failed": named_failed,
                "declared_companions": declared,
                "observed_companions": observed_companions,
                "only_declared_cases_broke": isolated,
                "restored_baseline": restored,
                "source_unchanged": SOURCE.read_text() == original,
                "named_returncode": None if named_result is None else named_result.returncode,
                "named_stdout": "" if named_result is None else named_result.stdout,
                "named_stderr": "" if named_result is None else named_result.stderr,
            }
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(
                record[key]
                for key in (
                    "edit_reached_source",
                    "compiled",
                    "named_assertion_failed",
                    "only_declared_cases_broke",
                    "restored_baseline",
                    "source_unchanged",
                )
            ):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
''')

# Two Rust mutations prove the integration seam and rollback observation. The
# first removes the host injection; the second deliberately leaks committed
# compute data into the real account before a rejecting action phase finishes.
rust_mutations = ROOT / "test/validator-auth-implementation/config_action_phase_mutations.py"
if rust_mutations.exists():
    raise RuntimeError("config action-phase mutation harness already exists")
rust_mutations.write_text(r'''"""Compile action-phase mutants and require the named sandbox evidence to fail."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/executor/src/transaction_executor.rs"
MANIFEST = ROOT / "tosctl/src/node-control/contracts/Cargo.toml"
CASES = [
    "config_persistence_action_phase::accepted_registry_persists_after_action_phase",
    "config_persistence_action_phase::refused_action_phase_rolls_registry_back",
]
MUTATIONS = [
    (
        "transaction-host-injected",
        CASES[0],
        "        if let Some(host) = params.validator_auth_host.clone() {\n"
        "            vm.set_validator_auth_host(host);\n"
        "        }\n",
        "",
        [CASES[1]],
    ),
    (
        "action-refusal-rolls-back-data",
        CASES[1],
        "        if let Some(new_data) = new_data {\n"
        "            acc_copy.set_data(new_data);\n"
        "        }\n"
        "        if !is_special && !check_account_size_limits(limits, &mut acc_copy)? {\n",
        "        if let Some(new_data) = new_data {\n"
        "            acc_copy.set_data(new_data.clone());\n"
        "            acc.set_data(new_data);\n"
        "        }\n"
        "        if !is_special && !check_account_size_limits(limits, &mut acc_copy)? {\n",
        [],
    ),
]


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def compile_tests(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run(
        ["cargo", "test", "--manifest-path", str(MANIFEST), "--test", "native_registry_sandbox", "--no-run"],
        env,
    )


def run_case(case: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(MANIFEST),
            "--test",
            "native_registry_sandbox",
            case,
            "--",
            "--exact",
            "--nocapture",
        ],
        env,
    )


def passed(result: subprocess.CompletedProcess[str], case: str) -> bool:
    short = case.split("::")[-1]
    return result.returncode == 0 and f"CASE_PASS {short}" in result.stdout


def failed_named(result: subprocess.CompletedProcess[str], case: str) -> bool:
    short = case.split("::")[-1]
    return result.returncode != 0 and f"SETUP_OK {short}" in result.stdout and "FAILED" in result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["P0_CONFIG_PERSISTENCE_CELLS"] = str(args.cells.resolve())

    original = SOURCE.read_text()
    baseline_compile = compile_tests(env)
    if baseline_compile.returncode != 0:
        (out / "baseline-compile.stderr").write_text(baseline_compile.stderr)
        print("BASELINE_COMPILE_FAILED", file=sys.stderr)
        return 1
    if not all(passed(run_case(case, env), case) for case in CASES):
        print("BASELINE_NOT_PASSING", file=sys.stderr)
        return 1

    records = []
    failures = 0
    try:
        for guard, named_case, before, after, declared in MUTATIONS:
            current = SOURCE.read_text()
            if current != original or current.count(before) != 1:
                print(f"ANCHOR_NOT_UNIQUE {guard} {current.count(before)}", file=sys.stderr)
                failures += 1
                continue
            changed = current.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compile_result = compile_tests(env)
            compiled = compile_result.returncode == 0
            results = {}
            observed = []
            if compiled:
                for case in CASES:
                    result = run_case(case, env)
                    results[case] = result
                    if not passed(result, case):
                        observed.append(case)
            named_result = results.get(named_case)
            named_failed = named_result is not None and failed_named(named_result, named_case)
            companions = [case for case in observed if case != named_case]
            isolated = sorted(companions) == sorted(declared)

            SOURCE.write_text(original)
            restored_compile = compile_tests(env)
            restored = restored_compile.returncode == 0 and all(
                passed(run_case(case, env), case) for case in CASES
            )
            record = {
                "guard": guard,
                "case": named_case,
                "edit_reached_source": reached,
                "compiled": compiled,
                "named_assertion_failed": named_failed,
                "declared_companions": declared,
                "observed_companions": companions,
                "only_declared_cases_broke": isolated,
                "restored_baseline": restored,
                "source_unchanged": SOURCE.read_text() == original,
                "named_returncode": None if named_result is None else named_result.returncode,
                "named_stdout": "" if named_result is None else named_result.stdout,
                "named_stderr": "" if named_result is None else named_result.stderr,
            }
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(
                record[key]
                for key in (
                    "edit_reached_source",
                    "compiled",
                    "named_assertion_failed",
                    "only_declared_cases_broke",
                    "restored_baseline",
                    "source_unchanged",
                )
            ):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
''')

# Extend the permanent focused workflow so this evidence remains reproducible
# after the one-shot completion route removes itself.
workflow = ROOT / ".github/workflows/validator-auth-config-persistence.yml"
replace_once(
    workflow,
    "          assert ids == ['dependencies', 'structure', 'build', 'measure', 'evidence']\n",
    "          assert ids == ['dependencies', 'structure', 'build', 'measure', 'cpp_mutations', 'rust_action', 'rust_mutations', 'frozen', 'evidence']\n",
    "workflow structure ids",
)
replace_once(
    workflow,
    "      - name: Retain exact measurements and built contract cells\n"
    "        id: evidence\n",
    "      - name: Run compiled configuration-contract mutations\n"
    "        id: cpp_mutations\n"
    "        run: |\n"
    "          set +e\n"
    "          python3 test/validator-auth-implementation/config_contract_persistence_mutations.py --out artifacts/config-persistence/cpp-mutations\n"
    "          rc=$?\n"
    "          printf '%s\\n' \"$rc\" > artifacts/config-persistence/cpp-mutations.exit\n"
    "          echo \"CPP_MUTATIONS_EXIT=$rc\"\n"
    "          exit \"$rc\"\n"
    "      - name: Run real action-phase persistence and rollback evidence\n"
    "        id: rust_action\n"
    "        run: |\n"
    "          set +e\n"
    "          export P0_CONFIG_PERSISTENCE_CELLS=\"$PWD/artifacts/config-persistence/cells\"\n"
    "          cargo test --manifest-path tosctl/src/node-control/contracts/Cargo.toml --test native_registry_sandbox config_persistence_action_phase -- --nocapture\n"
    "          rc=$?\n"
    "          printf '%s\\n' \"$rc\" > artifacts/config-persistence/rust-action.exit\n"
    "          echo \"RUST_ACTION_EXIT=$rc\"\n"
    "          exit \"$rc\"\n"
    "      - name: Run compiled action-phase mutations\n"
    "        id: rust_mutations\n"
    "        run: |\n"
    "          set +e\n"
    "          python3 test/validator-auth-implementation/config_action_phase_mutations.py --cells artifacts/config-persistence/cells --out artifacts/config-persistence/rust-mutations\n"
    "          rc=$?\n"
    "          printf '%s\\n' \"$rc\" > artifacts/config-persistence/rust-mutations.exit\n"
    "          echo \"RUST_MUTATIONS_EXIT=$rc\"\n"
    "          exit \"$rc\"\n"
    "      - name: Verify frozen production reconstruction\n"
    "        id: frozen\n"
    "        run: |\n"
    "          set +e\n"
    "          mkdir -p artifacts/config-persistence/production\n"
    "          python3 test/validator-auth-p0/check_production.py --out artifacts/config-persistence/production\n"
    "          production_rc=$?\n"
    "          python3 test/validator-auth-p0/freeze_record.py\n"
    "          freeze_rc=$?\n"
    "          printf '%s\\n' \"$production_rc\" > artifacts/config-persistence/check-production.exit\n"
    "          printf '%s\\n' \"$freeze_rc\" > artifacts/config-persistence/freeze-record.exit\n"
    "          echo \"CHECK_PRODUCTION_EXIT=$production_rc\"\n"
    "          echo \"FREEZE_RECORD_EXIT=$freeze_rc\"\n"
    "          test \"$production_rc\" -eq 0 -a \"$freeze_rc\" -eq 0\n"
    "      - name: Retain exact measurements and built contract cells\n"
    "        id: evidence\n",
    "workflow final evidence anchor",
)

print("CONFIG_PERSISTENCE_PATCH_OK")
