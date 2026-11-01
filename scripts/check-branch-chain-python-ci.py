#!/usr/bin/env python3
"""Pin branch CI coverage for the Python suite and a real PQ chain boot."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REQUIRED_NATIVE_TARGETS = {
    "gen_fif",
    "test-node-store-fixture",
    "create-state",
    "toslibjson",
    "generate-random-id",
    "tos-pq-consensus-key",
    "dht-server",
    "validator-engine-console",
    "validator-engine",
    "tos-wallet-index",
    "tos-wallet-index-snapshot",
    "tos-wallet-index-dump",
    "wallet-index-source-fixture",
    "test-wallet-index-source",
    "test-pq-lite-forward-proof",
    "test-pending-finality-cache",
    "test-c04-real-state-proof",
    "tos-proof-verify",
    "test-proof-verify",
    "test-get-method-context",
    "test-control-getter",
    "test-control-getter-budget",
    "test-control-getter-query",
    "test-control-getter-transport",
    "proof-verify-fs-shim",
    "test-n5-manager-db-fixture",
    "test-consensus",
    "test-notarize-after-transient-resolve",
    "test-skip-after-finality-backlog",
    "test-signing-ledger",
    "test-decision-log-restart",
    "test-candidate-window-durability",
    "test-counted-finalizations",
    "test-unfinalized-count-resolver",
    "test-state-resolver-teardown",
    "test-custom-overlay-relay-dedup",
    "test-pq-consensus-key-rotation",
    "test-fsync-dir-failure-shim",
    # Executables that link the consensus custody through validator-disk and
    # validator-hardfork; the full-tree build runs only for pull requests into main.
    "create-hardfork",
    "test-tos-collator",
    "test-apply-block-readback-latency",
    # Answered refusals, download deadlines, consensus retries, group
    # retirement and block acceptance.
    "test-download-refusal-answers",
    "test-consensus-retry-backoff",
    "test-bridge-retirement",
    "test-block-accepter",
    "test-rldp2-refusal-lifetime",
}

# The deterministic production-actor cases for a skip timeout that expires while finality
# is behind, and for a skip or final vote Pool refuses before its intent. A registration
# that drops one still matches the '^a142-backlog-' selector.
BACKLOG_SKIP_MODES = (
    "stall-recovers",
    "short-hold",
    "final-redrive",
    "superseded-deferral",
    "notar-rearm",
    "repeated-toggle",
    "shutdown-pending",
    "many-windows-behind",
    "race-refused-then-clear",
    "race-clear-before-refusal",
    "race-final-after-clear",
    "race-new-window",
    "race-notar-rearm",
    "bootstrap-suppressed",
    "shutdown-suppressed",
)

# Each runs as its own anchored CTest that must exist (--no-tests=error).
REFUSAL_AND_RETIREMENT_TESTS = (
    "test-download-refusal-answers",
    "test-consensus-retry-backoff",
    "test-bridge-retirement",
    "test-bridge-retirement-nonzero",
    "test-block-accepter",
    "test-rldp2-refusal-lifetime",
)

# The registrations, with the mode argument and the token each case prints, so
# a registration that loses or swaps its argument cannot pass as the other
# case.
REFUSAL_AND_RETIREMENT_REGISTRATIONS = (
    (
        r"tos_test\(test-download-refusal-answers\)",
        "download refusal and deadline CTest",
    ),
    (
        r"tos_test\(test-bridge-retirement zerostate-destroy\)\s*\n"
        r'set_tests_properties\(test-bridge-retirement PROPERTIES PASS_REGULAR_EXPRESSION "BRIDGE_RETIREMENT_ZEROSTATE_OK"\)',
        "zero-state group destruction CTest, its mode argument or its pass token",
    ),
    (
        r"add_test\(NAME test-bridge-retirement-nonzero COMMAND test-bridge-retirement nonzero-retirement\)\s*\n"
        r"set_tests_properties\(test-bridge-retirement-nonzero PROPERTIES "
        r'PASS_REGULAR_EXPRESSION "BRIDGE_RETIREMENT_NONZERO_OK"\)',
        "non-zero-state group retirement CTest, its mode argument or its pass token",
    ),
    (
        r"add_executable\(test-block-accepter test/validator/consensus/test-block-accepter\.cpp\)",
        "block accepter test executable",
    ),
    (
        r"tos_test\(test-block-accepter\)\s*\n"
        r'set_tests_properties\(test-block-accepter PROPERTIES PASS_REGULAR_EXPRESSION "BLOCK_ACCEPTER_OK"\)',
        "block accepter CTest or its pass token",
    ),
)

RESTART_ORIGIN_TESTS = (
    "test-consensus-simplex2-pq-empty-chain-restart",
    "test-consensus-simplex2-pq-restart-transient-anchor",
    "test-consensus-simplex2-pq-restart-transient-anchor-zerostate-control",
    "test-consensus-simplex2-pq-restart-transient-origin",
    "test-consensus-simplex2-pq-restart-permanent-origin",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"BRANCH_CHAIN_PYTHON_CI_FAILURE: {message}")


def validate_checkout_trust(text: str) -> None:
    steps = list(
        re.finditer(r"(?ms)^      - name: (?P<name>[^\n]+)\n(?P<body>.*?)(?=^      - |\Z)", text)
    )
    require(
        [step.group("name") for step in steps[:2]]
        == ["Check out repository", "Trust the checkout for container steps"],
        "container checkout trust must run immediately after checkout",
    )
    body = [
        line
        for line in steps[1].group("body").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    require(
        body
        == [
            "        shell: bash",
            "        run: |",
            "          set -euo pipefail",
            '          git config --global --add safe.directory "$GITHUB_WORKSPACE"',
            "          git rev-parse HEAD",
        ],
        "container checkout trust must use the runtime HOME, trust only the workspace and verify HEAD",
    )


def validate_unconditional_steps(text: str) -> None:
    # Always-on evidence upload cannot skip a test. All jobs and runtime gates
    # retain the unconditional coverage rule, including any other upload step.
    for archive_name in (
        "Retain Quantum candidate configuration and boot evidence",
        "Retain public explorer RPC response receipts",
        "Retain public self-pay proofs",
        "Retain native init-block publisher evidence",
        "Retain native wallet-index verification evidence",
    ):
        archive = re.search(
            rf"(?ms)^      - name: {re.escape(archive_name)}\n"
            r"(?P<body>.*?)(?=^      - |\Z)",
            text,
        )
        if archive is not None:
            body = archive.group("body")
            require(
                re.search(
                    r"(?m)^        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02(?: # v4)?$",
                    body,
                )
                is not None,
                "evidence archive is not the pinned upload action",
            )
            require(
                body.count("        if: always()\n") == 1 and "run:" not in body,
                "evidence archive must run always and cannot execute tests",
            )
            text = text.replace(
                archive.group(0), archive.group(0).replace("        if: always()\n", ""), 1
            )
    for name, command in (
        ("Collect disposable node failure logs", "python3 scripts/collect-disposable-node-logs.py"),
        ("Retain disposable node failure logs", None),
    ):
        step = re.search(
            rf"(?ms)^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - |^  #|\Z)",
            text,
        )
        require(step is not None, "disposable node failure diagnostics are absent")
        body = step.group("body")
        require(body.count("        if: failure()\n") == 1, "node logs must be retained on failure")
        if command is not None:
            require(
                body == f"        if: failure()\n        run: {command}\n\n",
                "node log collector may only run its diagnostic command",
            )
        else:
            require(
                "run:" not in body
                and "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4"
                in body
                and "path: build/disposable-node-logs/" in body,
                "node logs must use the pinned diagnostic archive",
            )
        text = text.replace(step.group(0), step.group(0).replace("        if: failure()\n", ""), 1)
    require("if:" not in text, "workflow makes a job or step conditional")


TRIGGERS = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n"


def validate_triggers(text: str) -> None:
    # Every pull request, with no base, path or type filter, and every push to
    # main. Pushes to other branches would duplicate the pull request run.
    head = text.split("\npermissions:", 1)[0]
    match = re.search(r"(?ms)^on:\n.*", head)
    require(match is not None, "workflow has no trigger map")
    require(
        match.group(0).rstrip("\n") + "\n" == TRIGGERS,
        "triggers are not exactly: every pull request, pushes to main, and dispatch",
    )


def validate_node_store_proof(text: str) -> None:
    job = re.search(r"(?ms)^  python-and-pq-chain:\n(?P<body>.*?)(?=^  [\w-]+:\s*$|\Z)", text)
    require(job is not None, "native StateDb proof job is absent")
    container = re.search(
        r"(?ms)^    container:\n(?P<body>.*?)(?=^    [\w-]+:|\Z)", job.group("body")
    )
    require(container is not None, "native StateDb proof container is absent")
    options = re.findall(r"(?m)^      options: ([^#\n]+)(?:#.*)?$", container.group("body"))
    require(
        len(options) == 1
        and re.search(r"(?:^|\s)--cap-add SYS_PTRACE(?:\s|$)", options[0]) is not None
        and re.search(r"(?:^|\s)--cap-drop(?:=|\s+)(?:SYS_PTRACE|ALL)(?:\s|$)", options[0]) is None,
        "native StateDb proof container must grant SYS_PTRACE for cross-user writer inspection",
    )
    required = (
        'export NODE_STORE_NATIVE_DIR="$GITHUB_WORKSPACE/build/third-party/rocksdb"',
        'export NODE_STORE_FIXTURE="$GITHUB_WORKSPACE/build/test-node-store-fixture"',
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-store --features native --test native_fixture -- --nocapture | tee build/node-store-native-tests.log",
        "grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored' build/node-store-native-tests.log",
        "cargo build --manifest-path tosctl/src/Cargo.toml --locked -p node-store --features native --example reconstruct_fixture",
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --lib service::tests::refuse_writers_checks_child_descriptor_access_modes -- --ignored --exact --nocapture | tee build/node-sync-writer-control.log",
        "grep -Fx 'CHILD_DESCRIPTOR_WRITER_CONTROL_OK' build/node-sync-writer-control.log",
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --tests",
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p commands --features node-data-sync-native --lib commands::nodectl::node_cmd::status_tests::standalone_status_keeps_rpc_only_contract_without_control_or_references -- --exact --nocapture | tee build/node-status-compatibility.log",
        "grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored' build/node-status-compatibility.log",
        "cargo build --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --examples --bin node-data-sync-worker",
        "cargo build --manifest-path tosctl/src/Cargo.toml --locked -p tosctl --features node-data-sync-native",
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --lib operations::tests::native_stage_preserves_own_context_and_never_overlays_recovery_material -- --ignored --exact --nocapture | tee build/node-sync-native-preservation.log",
        "grep -Fx 'NATIVE_STAGE_PRESERVATION_OK' build/node-sync-native-preservation.log",
        "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --lib -- --ignored --exact --nocapture operations::tests::root_capture_resists_a_service_account_swap operations::tests::foreign_mount_on_state_refuses_and_leaves_the_mounted_tree | tee build/node-sync-capture-controls.log",
        "grep -Fx 'ROOT_SERVICE_ACCOUNT_SWAP_OK' build/node-sync-capture-controls.log",
        "grep -Fx 'FOREIGN_MOUNT_REFUSAL_OK' build/node-sync-capture-controls.log",
        "run: uv run python test/integration/node_store_native_reopen.py --root build/node-store-native-reopen --build build --reconstruct build/operator-rust-target/debug/examples/reconstruct_fixture --validate-generation build/operator-rust-target/debug/examples/capture_and_validate",
    )
    for command in required:
        require(
            re.search(rf"(?m)^ +{re.escape(command)}$", text) is not None,
            f"native StateDb proof command is absent: {command}",
        )


def validate_init_block_lifecycle(text: str) -> None:
    required = (
        "uv run python test/integration/node_sync_init_block.py --root build/node-sync-init-block --build build --capture build/operator-rust-target/debug/examples/capture_and_validate --wallet-index-fixtures | tee build/node-sync-init-block.log",
        "grep -Fx 'NATIVE_SERIALIZER_NONLOCAL_REFUSAL_OK' build/node-sync-init-block.log",
        "grep -Fx 'NATIVE_INIT_BLOCK_JOIN_OK' build/node-sync-init-block.log",
        'export NODE_SYNC_NATIVE_INIT_ROOT="$GITHUB_WORKSPACE/build/node-sync-init-block"',
        "grep -Fx 'PRODUCTION_INIT_BLOCK_PUBLISH_BOOTSTRAP_OK' build/node-sync-native-lifecycle.log",
        "python3 scripts/check-init-block-pre-anchor-control.py --build-dir build --target-dir build/operator-rust-target --init-root build/node-sync-init-block --output-dir build/init-block-pre-anchor-control | tee build/init-block-pre-anchor-control.log",
        "grep -Fx 'INIT_BLOCK_PRE_ANCHOR_CONTROL_OK' build/init-block-pre-anchor-control.log",
    )
    for command in required:
        require(
            re.search(rf"(?m)^ +{re.escape(command)}$", text) is not None,
            f"native init-block lifecycle command is absent: {command}",
        )


WALLET_INDEX_SCENARIOS = {
    "reference",
    "path-a",
    "path-b",
    "tampered",
    "omitted",
    "truncated",
    "injected",
    "wrong-checkpoint",
    "wrong-anchor",
    "stale",
    "forged-ownership",
    "destroyed-omitted",
    "recreated-omitted",
}


def validate_wallet_index_scenarios(source: str) -> None:
    tree = ast.parse(source)
    registrations = []
    defaults = []
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "SCENARIOS"
        ):
            require(
                isinstance(node.value, ast.Dict), "native wallet-index scenarios are not a registry"
            )
            registrations.extend(
                key.value
                for key in node.value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            )
            expansions = [
                ast.dump(value)
                for key, value in zip(node.value.keys, node.value.values)
                if key is None
            ]
            expected = ast.dump(
                ast.parse(
                    "{control.name: scenario_red(control) for control in RED_CONTROLS}", mode="eval"
                ).body
            )
            require(
                expansions == [expected],
                "native wallet-index registry must include every red control",
            )
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "RED_CONTROLS" for target in node.targets
        ):
            require(isinstance(node.value, ast.List), "native red controls are not a list")
            for control in node.value.elts:
                require(
                    isinstance(control, ast.Call)
                    and isinstance(control.func, ast.Name)
                    and control.func.id == "RedControl"
                    and control.args
                    and isinstance(control.args[0], ast.Constant),
                    "native red control is unnamed",
                )
                registrations.append(control.args[0].value)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "--scenarios"
        ):
            defaults.extend(keyword.value for keyword in node.keywords if keyword.arg == "default")
    require(
        len(registrations) == len(WALLET_INDEX_SCENARIOS)
        and set(registrations) == WALLET_INDEX_SCENARIOS,
        f"native wallet-index scenarios differ: {sorted(set(registrations) ^ WALLET_INDEX_SCENARIOS)}",
    )
    require(
        len(defaults) == 1
        and ast.dump(defaults[0]) == ast.dump(ast.parse("list(SCENARIOS)", mode="eval").body),
        "native wallet-index default must run the entire scenario registry",
    )


def validate_wallet_index_acceptance(text: str) -> None:
    required = {
        "Remove and restore wallet-index ownership and retention guards": (
            "python3 scripts/test-wallet-index-review-controls.py --build-dir build --jobs 4 --output-dir build/wallet-index-review-controls | tee build/wallet-index-review-controls.log",
            "grep -Fx 'WALLET_INDEX_REVIEW_CONTROLS_OK' build/wallet-index-review-controls.log",
        ),
        "Verify every native wallet-index import and build scenario": (
            'uv run python test/integration/wallet_index_verify_native.py --init-root build/node-sync-init-block --build build --root build/wallet-index-verify-native --source-commit "$(git rev-parse HEAD)" | tee build/wallet-index-verify-native.log',
            "grep -Fx 'NATIVE_WALLET_INDEX_VERIFY_OK' build/wallet-index-verify-native.log",
        ),
    }
    for name, commands in required.items():
        step = re.search(
            rf"(?ms)^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - |\Z)", text
        )
        require(step is not None, f"native wallet-index acceptance step is absent: {name}")
        body = step.group("body")
        require(
            "        shell: bash\n" in body and "          set -euo pipefail\n" in body,
            "native wallet-index acceptance must propagate pipeline failures",
        )
        for command in commands:
            require(
                re.search(rf"(?m)^ +{re.escape(command)}$", body) is not None,
                f"native wallet-index acceptance command is absent: {command}",
            )
    require(
        text.index("      - name: Verify every native wallet-index import and build scenario")
        > text.index(
            "      - name: Refuse init-block publication on the pre-anchor-proof validation path"
        ),
        "native wallet-index acceptance must reuse the image after its existing consumers",
    )
    archive = re.search(
        r"(?ms)^      - name: Retain native wallet-index verification evidence\n(?P<body>.*?)(?=^      - |\Z)",
        text,
    )
    require(archive is not None, "native wallet-index evidence archive is absent")
    body = archive.group("body")
    require(
        "          retention-days: 14\n" in body,
        "native wallet-index evidence must be retained for 14 days",
    )
    paths = re.search(r"(?m)^          path: \|\n(?P<paths>(?:            .+\n)+)", body)
    require(paths is not None, "native wallet-index evidence paths are absent")
    require(
        paths.group("paths").split()
        == [
            "build/node-sync-init-block/wallet-index-fixtures.json",
            "build/node-sync-init-block/wallet-traffic/*.boc",
            "build/wallet-index-verify-native/receipt.json",
            "build/wallet-index-verify-native/*/receipt.json",
            "build/wallet-index-verify-native.log",
            "build/wallet-index-review-controls/receipt.json",
            "build/wallet-index-review-controls/*.log",
            "build/wallet-index-review-controls.log",
        ],
        "native wallet-index evidence must contain only bounded fixture transactions, receipts and logs",
    )


def validate_node_data_sync_callers(root: Path) -> None:
    callers = {
        "node_dump_cmd.rs": ("create",),
        "node_sync_cmd.rs": ("restore", "recover", "complete"),
        "backup_cmd.rs": ("backup",),
    }
    directory = root / "tosctl/src/node-control/commands/src/commands/nodectl"
    for filename, operations in callers.items():
        source = (directory / filename).read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
        require("node_store::" not in source, f"{filename} bypasses the shared typed-store policy")
        for operation in operations:
            call = f"node_data_sync::operations::{operation}("
            require(
                source.count(call) == 1, f"{filename} must use exactly one shared {operation} entry"
            )

    dump_source = (
        (directory / "node_dump_cmd.rs").read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
    )
    require(
        "PublisherSecret::load(&args.signing_key)" in dump_source,
        "publisher provenance bypasses shared policy",
    )
    require(
        "ReferencePolicy::from_endpoints(&args.references)" in re.sub(r"\s+", "", dump_source),
        "publication lacks named references",
    )
    require(
        dump_source.count("catalog.publish(") == 1,
        "publication must use the shared corroborated catalog entry",
    )
    core = root / "tosctl/src/node-control/node-data-sync/src"
    operations = (core / "operations.rs").read_text(encoding="utf-8")
    require(
        "publisher.validate(&context.database, store, operation_path)?;" in operations,
        "capture lacks publisher confinement",
    )
    create = operations.split("pub fn create(", 1)[1].split("pub fn restore(", 1)[0]
    confinement = "publisher.validate(&context.database, store, operation_path)?;"
    require(create.count(confinement) == 2, "publisher confinement must run before and after stop")
    require(
        create.index(confinement)
        < create.index("service.stop_command()")
        < create.rindex(confinement)
        < create.index("capture::cold_image_checked("),
        "publisher confinement must precede capture exposure",
    )
    restore = operations.split("pub fn restore(", 1)[1].split("struct StoppedTarget", 1)[0]
    require(
        restore.index("authorize_references(") < restore.index("expose_staged("),
        "restore must corroborate before the forward-only exposure boundary",
    )
    authorization = operations.split("fn authorize_references(", 1)[1].split(
        "fn expose_staged(", 1
    )[0]
    require(
        authorization.index("references.corroborate(") < authorization.index("journal.authorize("),
        "shared authorization must corroborate before persisting approval",
    )
    exposure = operations.split("fn expose_staged(", 1)[1].split("fn start_installed(", 1)[0]
    require(
        exposure.index("journal.forward_only(") < exposure.index("journal.exchange("),
        "exchange must follow the durable forward-only boundary",
    )
    generation = (core / "generation.rs").read_text(encoding="utf-8")
    generation_positions = [
        generation.find(call)
        for call in ("references.corroborate(", "SignedManifest::sign(", "catalog.prepare(")
    ]
    require(
        min(generation_positions) >= 0
        and generation_positions == sorted(set(generation_positions)),
        "creation must corroborate before signing and preparation",
    )


def validate_node_data_sync_modes(root: Path) -> None:
    core = root / "tosctl/src/node-control/node-data-sync/src"
    source = re.sub(r"\s+", "", (core / "operations.rs").read_text())
    require(
        '.join("FORWARD_ONLY")' not in source,
        "restore boundary is the restore.json phase, not a standalone FORWARD_ONLY file",
    )
    import tomllib

    manifest = tomllib.loads((core.parent / "Cargo.toml").read_text())
    features = manifest["features"]
    pending = list(features.get("default", []))
    seen = set()
    while pending:
        feature = pending.pop()
        require(feature != "native-lifecycle-tests", "lifecycle hooks must not be default features")
        if feature not in seen:
            seen.add(feature)
            pending.extend(features.get(feature, []))
    build = (core.parent / "build.rs").read_text()
    require(
        "CARGO_FEATURE_NATIVE_LIFECYCLE_TESTS" in build
        and '== Ok("release")' in build
        and "native-lifecycle-tests is forbidden in the release build profile" in build,
        "release profile must reject lifecycle test feature",
    )
    workflow = (root / ".github/workflows/branch-chain-python.yml").read_text()
    for token in (
        "--features native-lifecycle-tests --lib native_lifecycle:: -- --test-threads=1 --nocapture",
        "rustc --edition=2024 tosctl/src/node-control/node-data-sync/build.rs -o build/node-sync-profile-check",
        "if env CARGO_FEATURE_NATIVE_LIFECYCLE_TESTS=1 PROFILE=release build/node-sync-profile-check",
        "grep -Fx 'PRODUCTION_COMPLETE_RETRY_OK'",
        "grep -Fx 'PRODUCTION_RESTORE_STOP_CUT_OK'",
        "grep -Fx 'PRODUCTION_RESTORE_PROCESS_EXIT_OK'",
        "grep -Fx 'PRODUCTION_LIFECYCLE_MODES_OK'",
        "grep -Fx 'PRODUCTION_RESTORE_INDEX_BOUNDARIES_OK'",
        "grep -Fx 'RESTORE_DISK_BOUNDARIES_OK'",
        "grep -Fx 'STAGED_DISK_RECOVERY_OK'",
        "grep -Fx 'PRODUCTION_CREATE_WITHOUT_STATIC_OK'",
        "grep -Fx 'PRODUCTION_CREATE_WITHOUT_ZERO_STATE_OK'",
        "grep -Fx 'PRODUCTION_VALIDATION_REQUIRED_ANCESTOR_OK'",
        "grep -Fx 'PRODUCTION_CREATE_RESTART_OK'",
        "grep -Fx 'PRODUCTION_BOOTSTRAP_INSTALL_OK'",
        "grep -Fx 'PRODUCTION_BOOTSTRAP_REFUSALS_OK'",
        "grep -Fx 'PRODUCTION_BOOTSTRAP_RECOVERY_OK'",
        "grep -Fx 'PRODUCTION_BOOTSTRAP_ANCHOR_REFUSAL_OK'",
    ):
        require(token in workflow, "native lifecycle CI command or required result missing")
    validate_init_block_lifecycle(workflow)
    library = (core / "lib.rs").read_text()
    require(
        '#[cfg(all(test, feature = "native-lifecycle-tests"))]\nmod test_hooks;' in library,
        "lifecycle hook module must be compiled only for unit tests",
    )
    for name in ("operations.rs", "service.rs", "cas.rs", "references.rs"):
        text = (core / name).read_text()
        calls = text.count("crate::test_hooks::")
        guarded = re.findall(
            r'#\[cfg\(all\(test,\s*feature = "native-lifecycle-tests"\)\)\]\s*'
            r"(?:if let Some\(result\) = )?crate::test_hooks::",
            text,
        )
        require(len(guarded) == calls, f"non-test lifecycle hook in {name}")
    create = source.split("pubfncreate(", 1)[1].split("pubfnrestore(", 1)[0]
    restore = source.split("pubfnrestore(", 1)[1].split("structStoppedTarget", 1)[0]
    recover = source.split("pubfnrecover(", 1)[1].split("pubfncomplete(", 1)[0]
    start = source.split("fnstart_installed(", 1)[1].split("pubenumRecoveryOutcome", 1)[0]

    def between(body: str, left: str, right: str, check: str, label: str) -> None:
        require(left in body and right in body, f"storage-mode boundary missing: {label}")
        start = body.index(left) + len(left)
        end = body.find(right, start)
        require(end >= start, f"storage-mode boundary reordered: {label}")
        require(check in body[start:end], f"storage-mode binding omitted: {label}")

    expected = "require_restore_target(Some(signed.manifest.permanent_cells))?;"
    # Before the exchange every lane checks its target through one function: an existing
    # node for restore, a new inactive node for bootstrap, both in the selected mode.
    target = "require_unexchanged_target(request,Some(signed.manifest.permanent_cells))?;"
    unexchanged = source.split("fnrequire_unexchanged_target(", 1)[1].split("fnselected(", 1)[0]
    for check, label in (
        ("Lane::Restore=>{service.require_restore_target(expected)?;", "restore lane target"),
        ("Lane::Bootstrap=>{service.require_selected_mode(expected)?;", "bootstrap lane mode"),
        ("service.require_inactive()", "bootstrap lane inactive service"),
        ("crate::paths::new_node_root(&request.context.database)?;", "bootstrap new-node root"),
        ("require_no_signing_material(&request.context)", "bootstrap signing material"),
    ):
        require(check in unexchanged, f"storage-mode binding omitted: {label}")
    between(create, "letservice=", "letpublic=", "service.permanent_cells()?", "create entry")
    between(
        create,
        "service.stop_command().and_then(|()|service.freeze())",
        "capture::cold_image_checked(",
        "service.require_mode(permanent)?;",
        "create stopped",
    )
    restart = source.split("fnrestart_source(", 1)[1].split("fnleft_stopped(", 1)[0]
    between(
        restart,
        "letrecheck=",
        ".start_in_mode(frozen,permanent)",
        "service.require_mode(permanent).context(",
        "source restart",
    )
    require(
        "letrestarted=restart_source(context,&service,frozen,permanent,&attached);" in create,
        "storage-mode binding omitted: source restart",
    )
    selected = source.split("fnselected(", 1)[1].split("pubfnpreflight(", 1)[0]
    between(
        selected,
        "restore_storage(request,None)?;",
        "letkey=trusted(",
        "require_unexchanged_target(request,None)?;",
        "restore supported target before preparation",
    )
    require(
        "signed.manifest.permanent_cells==request.context.service().permanent_cells()?" in selected,
        "storage-mode binding omitted: preflight",
    )
    quiesce = source.split("fnquiesce(", 1)[1].split("structTargetRecords", 1)[0]
    require(
        "Lane::Restore=>service.stop()," in quiesce
        and "Lane::Bootstrap=>service.freeze()" in quiesce,
        "storage-mode binding omitted: lane quiescence",
    )
    between(
        restore,
        "catalog.hold_download(",
        "letfrozen=quiesce(request)?;",
        "prepare_stop(request,&signed,&operation,&operation_id)?;",
        "durable descriptor before stop",
    )
    stage = source.split("fnstage_with_space(", 1)[1].split("fnstart_installed(", 1)[0]
    between(
        stage,
        "letrevision=",
        "Root::create(&operation.path.join(&revision))?;",
        "read_stop(",
        "bound descriptor before stage creation",
    )
    between(
        restore,
        "catalog.hold_download(",
        "letfrozen=quiesce(request)?;",
        target,
        "restore transfer",
    )
    between(
        restore,
        "letfrozen=quiesce(request)?;",
        "letmutjournal=stage(",
        target,
        "restore stopped",
    )
    between(restore, "authorize_references(", "expose_staged(", target, "restore exposure")
    check_installed = recover.split("letcheck_installed=", 1)[1].split("};", 1)[0]
    for check, label in (
        (
            "require_unexchanged_target(&request,Some(signed.manifest.permanent_cells))",
            "recover unexchanged target",
        ),
        (expected.removesuffix("?;"), "recover installed replacement"),
    ):
        require(check in check_installed, f"storage-mode binding omitted: {label}")
    between(
        recover,
        "letsigned=",
        "letfrozen=ifunexchanged{",
        "signed.manifest.permanent_cells==request.context.service().permanent_cells()?",
        "recover entry",
    )
    between(
        recover,
        "signed.manifest.permanent_cells==request.context.service().permanent_cells()?",
        "letfrozen=ifunexchanged{",
        "check_installed()?;",
        "recover supported target before stop",
    )
    between(
        recover,
        "letfrozen=ifunexchanged{",
        "matchjournal.recovery()?",
        "check_installed()?;",
        "recover stopped",
    )
    between(
        recover,
        "authorize_references(",
        "expose_staged(",
        "check_installed()?;",
        "recover exposure",
    )
    between(start, "letsigned=", "context.service().freeze()?;", expected, "replacement freeze")
    require(
        "context.service().start_restore(frozen,signed.manifest.permanent_cells)?;" in start,
        "storage-mode binding omitted: replacement start",
    )
    authorization = source.split("fnauthorize_references(", 1)[1].split("fnexpose_staged(", 1)[0]
    between(
        authorization,
        ".corroborate(",
        "journal.authorize(",
        'exposure_check("restore-authorize")?;',
        "post-corroboration disk check",
    )
    exposure = source.split("fnexpose_staged(", 1)[1].split("fnstart_installed(", 1)[0]
    for boundary, action in (
        ("restore-forward-only", "journal.forward_only("),
        ("restore-exchange", "journal.exchange("),
    ):
        require(
            exposure.index(f'exposure_check("{boundary}")?;') < exposure.index(action),
            f"disk exposure boundary missing: {boundary}",
        )
    service = re.sub(r"\s+", "", (core / "service.rs").read_text())
    require(
        "check_mode(configured,Some(running),expected)?;" in service,
        "running/configured mode comparison omitted",
    )
    require("check_mode(configured,None,expected)?;" in service, "expected mode comparison omitted")
    require("self.describe(expected)?;" in service, "service start bypasses checked description")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workflow = root / ".github/workflows/branch-chain-python.yml"
    text = workflow.read_text(encoding="utf-8")
    validate_checkout_trust(text)
    validate_node_store_proof(text)
    validate_node_data_sync_callers(root)
    validate_node_data_sync_modes(root)
    validate_wallet_index_acceptance(text)
    validate_wallet_index_scenarios(
        (root / "test/integration/wallet_index_verify_native.py").read_text()
    )
    validate_triggers(text)
    # This workflow's purpose is to run on every pull request and push to main.
    # Refuse runtime conditions: a job- or step-level `if:` is
    # how the existing real-chain job became a green-looking skipped check.
    validate_unconditional_steps(text)
    require("uv sync --no-dev" in text, "workflow does not install repository Python dependencies")
    require(
        "test/tostester/generate_tl.py" in text,
        "workflow does not generate the ignored Python TL API",
    )
    require(re.search(r"(?m)^\s*run: uv run pytest\s*$", text) is not None, "full pytest is absent")
    require(
        re.search(
            r"(?m)^\s*run: uv run pytest -q test/pq-native/test_e04_negative_windows\.py\s*$",
            text,
        )
        is not None,
        "E04 exact cancellation and expiry behavior gate is absent",
    )
    require(
        "uv run python test/integration/test_basic.py" in text,
        "four-validator PQ chain regression is absent",
    )
    require(
        "uv run python test/integration/test_json_rpc_without_wallet_index.py" in text,
        "validator JSON-RPC without the wallet index gate is absent",
    )
    require(
        "ctest --test-dir build --output-on-failure -R '^test-pq-lite-forward-proof$'" in text,
        "PQ key-block proof context behavior gate is absent",
    )
    verifier_ctest = (
        "ctest --test-dir build --output-on-failure --no-tests=error "
        "-R '^test-proof-verify(-cli-verified|-cli-refused|-live-commit)?$'"
    )
    require(
        re.search(rf"(?m)^\s*run: {re.escape(verifier_ctest)}\s*$", text) is not None,
        "anchored proof verifier behavior gate is absent",
    )
    require(
        "ctest --test-dir build --output-on-failure --no-tests=error "
        "-R '^getter-context-(context|vm|libraries|liteserver)$'" in text,
        "getter-context independent parity gate is absent",
    )
    require(
        "ctest --test-dir build --output-on-failure --no-tests=error "
        "-R '^control-getter-(executor|shutdown|limits|actor|vm|context|delete|budget)$'" in text,
        "bounded control-getter behavior and budget gate is absent",
    )
    require(
        "ctest --test-dir build --output-on-failure --no-tests=error "
        "-R '^control-getter-(query-(service|boundary|admission|completion)|transport)$'" in text,
        "authenticated control-getter query and transport gate is absent",
    )
    c09_pytest = (
        "uv run pytest -q -p no:cacheprovider test/pq-native/test_x02_config34_verifier.py "
        "test/pq-native/test_x02_stage_a_capture.py"
    )
    require(
        re.search(rf"(?m)^\s*run: {re.escape(c09_pytest)}\s*$", text) is not None
        and "TOS_PROOF_VERIFY: build/lite-client/proof-verify/tos-proof-verify" in text,
        "C09 Config34 anchored-verifier behavior gate is absent",
    )
    cmake_text = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    require(
        "add_test(NAME branch-chain-python-ci-source-conditions" in cmake_text
        and "scripts/test_branch_chain_conditions.py)" in cmake_text
        and 'set_tests_properties(branch-chain-python-ci-source-conditions PROPERTIES LABELS "source-guard")'
        in cmake_text,
        "branch condition refusal regression is absent from the source-guard suite",
    )
    require(
        "foreach(context_case context vm libraries liteserver)" in cmake_text
        and "FIXTURES_REQUIRED getter-context-state" in cmake_text,
        "getter-context CTest registrations or fixture dependency are absent",
    )
    require(
        "foreach(core_case executor shutdown limits actor vm context delete)" in cmake_text
        and "add_test(NAME control-getter-budget" in cmake_text,
        "bounded control-getter CTest registrations are absent",
    )
    for registration in (
        r"tos_test\(test-proof-verify\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data\)",
        r"add_test\(NAME test-proof-verify-cli-verified\s",
        r"add_test\(NAME test-proof-verify-cli-refused\s",
        r"add_test\(NAME test-proof-verify-live-commit\s",
    ):
        require(
            re.search(registration, cmake_text) is not None,
            f"anchored proof verifier CTest registration is absent: {registration}",
        )
    manager_ctest = "ctest --test-dir build --output-on-failure -R '^test-pending-finality-cache$'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(manager_ctest)}\s*$", text) is not None,
        "pending PQ finality manager actor behavior gate is absent",
    )
    relay_ctest = (
        "ctest --test-dir build --output-on-failure -R '^test-custom-overlay-relay-dedup$'"
    )
    require(
        re.search(rf"(?m)^\s*run: {re.escape(relay_ctest)}\s*$", text) is not None,
        "custom overlay relay deduplication gate is absent",
    )
    rotation_ctest = (
        "ctest --test-dir build --output-on-failure -R '^test-pq-consensus-key-rotation$'"
    )
    require(
        re.search(rf"(?m)^\s*run: {re.escape(rotation_ctest)}\s*$", text) is not None,
        "multi-key PQ consensus custody and key schedule gate is absent",
    )
    seam_ctest = (
        "ctest --test-dir build --output-on-failure --no-tests=error -R '^pq-signer-no-test-clock$'"
    )
    require(
        re.search(rf"(?m)^\s*run: {re.escape(seam_ctest)}\s*$", text) is not None,
        "production PQ signer test-clock seam gate is absent",
    )
    require(
        "uv run python test/integration/test_pq_consensus_key_rotation.py" in text,
        "real-engine PQ consensus key rotation gate is absent",
    )
    real_state_ctest = "ctest --test-dir build --output-on-failure -R '^test-c04-real-state-proof$'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(real_state_ctest)}\s*$", text) is not None,
        "real PQ predecessor and BlockProof component gate is absent",
    )
    for test_name, boundary in (
        ("test-n5-manager-db-fixture", "FinalCert journal cold read"),
        ("test-n5-accept-block", "PQ AcceptBlock cold read"),
        ("test-n5-joined-finalcert", "same-FinalCert actor and cold persistence path"),
        ("test-n5-cut1-finalcert-recovery", "FinalCert write-after bootstrap recovery"),
        ("test-n5-cut2-signatures-recovery", "#13 signature write-after bootstrap recovery"),
        ("test-n5-cut3-proof-recovery", "BlockProof write-after bootstrap recovery"),
        (
            "test-n5-cut4-finalized-replay",
            "finalized marker cold replay without duplicate acceptance",
        ),
        ("test-n5-cut5-full-root-rebuild", "DB/archive-only full-root rebuild"),
        ("test-n5-cut6-check-proof", "cold persisted PQ CheckProof acceptance and tamper refusal"),
        ("test-n5-cold-continuation", "cold continuation through a second FinalCert"),
    ):
        command = f"ctest --test-dir build --output-on-failure -R '^{test_name}$'"
        require(
            re.search(rf"(?m)^\s*run: {re.escape(command)}\s*$", text) is not None,
            f"N5 {boundary} behavior gate is absent: {test_name}",
        )
    cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-accept-block COMMAND test-c04-real-state-proof "
            r"--n5-accept\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 AcceptBlock CTest is absent or no longer invokes the production-fixture mode",
    )
    require(
        re.search(
            r"tos_test\(test-n5-manager-db-fixture\s+"
            r"\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 FinalCert journal CTest is absent",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-joined-finalcert COMMAND test-c04-real-state-proof "
            r"--n5-joined\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 same-FinalCert actor CTest is absent or no longer invokes its joined mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut1-finalcert-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut1\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 write-after recovery CTest is absent or no longer invokes its cut1 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut2-signatures-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut2\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 #13 write-after recovery CTest is absent or no longer invokes its cut2 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut3-proof-recovery COMMAND test-c04-real-state-proof "
            r"--n5-cut3\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 BlockProof write-after recovery CTest is absent or no longer invokes its cut3 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut4-finalized-replay COMMAND test-c04-real-state-proof "
            r"--n5-cut4\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 finalized marker replay CTest is absent or no longer invokes its cut4 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut5-full-root-rebuild COMMAND test-c04-real-state-proof "
            r"--n5-cut5\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 DB/archive-only full-root rebuild CTest is absent or no longer invokes its cut5 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cut6-check-proof COMMAND test-c04-real-state-proof "
            r"--n5-cut6\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 CheckProof CTest is absent or no longer invokes its cut6 mode",
    )
    require(
        re.search(
            r"(?s)add_test\(NAME test-n5-cold-continuation COMMAND test-c04-real-state-proof "
            r"--n5-continue\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}/test/pq-native/data/c04-pq-genesis\.boc\)",
            cmake,
        )
        is not None,
        "N5 cold continuation CTest is absent or no longer invokes its seq2 mode",
    )
    c05_ctest = "ctest --test-dir build --output-on-failure -R '^c05-notarize-'"
    require(
        re.search(rf"(?m)^\s*run: {re.escape(c05_ctest)}\s*$", text) is not None,
        "Simplex parent-state retry voting behavior gate is absent",
    )
    consensus_tests = (root / "test/validator/consensus/CMakeLists.txt").read_text(encoding="utf-8")
    for test_name, fault_count in (
        ("c05-notarize-simultaneous-recovery", 3),
        ("c05-notarize-simultaneous-overbudget", 24),
    ):
        require(
            re.search(rf"(?m)^\s*NAME {re.escape(test_name)}\s*$", consensus_tests) is not None
            and re.search(
                rf"(?m)^set_tests_properties\({re.escape(test_name)} PROPERTIES\s*\n"
                rf'\s*ENVIRONMENT "TOS_TEST_C05_SIMULTANEOUS_FAULTS={fault_count}"\)\s*$',
                consensus_tests,
            )
            is not None,
            f"C05 four-node behavior CTest is absent or has wrong fault budget: {test_name}",
        )
    for command in (
        "ctest --test-dir build --output-on-failure --no-tests=error -R '^a142-backlog-'",
        "ctest --test-dir build --output-on-failure --no-tests=error "
        "-R '^test-consensus-simplex2-pq-finality-backlog-stall$'",
        "ctest --test-dir build --output-on-failure --no-tests=error -R '^a142-counted-finalizations$'",
        "ctest --test-dir build --output-on-failure --no-tests=error -R '^a142-unfinalized-count-'",
    ):
        require(
            re.search(rf"(?m)^\s*{re.escape(command)}\s*$", text) is not None,
            f"Simplex skip-timeout-across-backlog behavior gate is absent: {command}",
        )
    backlog_modes = re.search(
        r"foreach\(mode (?P<modes>[^)]*)\)\s*\n\s*add_test\(NAME a142-backlog-\$\{mode\} "
        r"COMMAND test-skip-after-finality-backlog \$\{mode\}\)",
        consensus_tests,
    )
    require(backlog_modes is not None, "skip-timeout-across-backlog CTest registration is absent")
    missing_modes = sorted(set(BACKLOG_SKIP_MODES) - set(backlog_modes.group("modes").split()))
    require(
        not missing_modes,
        f"skip-timeout-across-backlog CTest modes are not registered: {missing_modes}",
    )
    require(
        re.search(
            r"(?m)^\s*NAME test-consensus-simplex2-pq-finality-backlog-stall\s*$", consensus_tests
        )
        is not None
        and re.search(
            r'TOS_SIMPLEX_INJECT_FINALIZATION_HOLD_MS=10000;TOS_SIMPLEX_PENDING_FINALIZATIONS_MAX=1"',
            consensus_tests,
        )
        is not None,
        "the four-node finalization hold CTest is absent or lost its hold or backlog limit",
    )
    for test_name in RESTART_ORIGIN_TESTS:
        command = f"ctest --test-dir build --output-on-failure -R '^{test_name}$'"
        require(
            re.search(rf"(?m)^\s*{re.escape(command)}\s*$", text) is not None,
            f"Simplex restart-origin behavior gate is absent: {test_name}",
        )
    for test_name in REFUSAL_AND_RETIREMENT_TESTS:
        command = f"ctest --test-dir build --output-on-failure --no-tests=error -R '^{test_name}$'"
        require(
            re.search(rf"(?m)^\s*{re.escape(command)}\s*$", text) is not None,
            f"refusal, deadline, retirement or acceptance behavior gate is absent: {test_name}",
        )
    for registration, what in REFUSAL_AND_RETIREMENT_REGISTRATIONS:
        require(re.search(registration, cmake) is not None, f"{what} is absent from CMakeLists.txt")
    rust_job = re.search(
        r"(?ms)^  rust-workspace-tests-compile:\s*\n(?P<body>.*?)(?=^  [\w-]+:\s*$|\Z)",
        text,
    )
    require(rust_job is not None, "all-crate Rust test compilation job is absent")
    require(
        re.search(
            r"(?m)^\s*run: cargo check --manifest-path tosctl/src/Cargo.toml --workspace --tests --locked\s*$",
            rust_job.group("body"),
        )
        is not None,
        "all-crate Rust test compilation is absent or scoped to an allowlist",
    )
    require(
        re.search(
            # Either the E04 group alone or the whole commands library, which includes it.
            r"(?m)^\s*run: cargo test --manifest-path tosctl/src/Cargo.toml -p commands --lib "
            r"(?:exact_deploy_wallet_transaction_tests )?--locked --no-default-features\s*$",
            rust_job.group("body"),
        )
        is not None,
        "E04 exact wallet confirmation behavior gate is absent",
    )
    zero_stats = text.find("ccache --zero-stats")
    native_build = text.find("cmake --build build --parallel 4 --target")
    show_stats = text.find("ccache --show-stats")
    require(
        -1 < zero_stats < native_build < show_stats,
        "native cache statistics do not bracket the fixture build",
    )
    cache_key = "${{ runner.os }}-${{ runner.arch }}-branch-pq-chain-${{ github.sha }}"
    restore_prefix = "${{ runner.os }}-${{ runner.arch }}-branch-pq-chain-"
    require(f"key: {cache_key}" in text, "native cache key is not commit-specific")
    require(
        f"restore-keys: {restore_prefix}" in text,
        "native cache cannot restore the newest prior branch entry",
    )
    require("continue-on-error" not in text, "workflow permits a guarded step to fail")

    target_command = re.search(
        r"cmake --build build --parallel 4 --target\s+\\?\s*(?P<targets>(?:\s*[\w-]+\s*\\?\s*)+)",
        text,
    )
    require(target_command is not None, "minimal native target command is missing")
    observed_targets = set(target_command.group("targets").replace("\\", "").split())
    require(
        REQUIRED_NATIVE_TARGETS <= observed_targets,
        f"native fixture targets are missing: {sorted(REQUIRED_NATIVE_TARGETS - observed_targets)}",
    )
    print(
        "BRANCH_CHAIN_PYTHON_CI_OK: every pull request and push to main runs full pytest, "
        "boots the four-validator PQ chain, checks PQ key-block proof context, "
        "the pending-finality manager actor and real PQ predecessor/BlockProof component, "
        "the anchored proof verifier, its CLI and the C09 Config34 path, "
        "N5 FinalCert-journal, AcceptBlock, same-FinalCert, five recovery CTests, cold CheckProof and seq2 continuation, "
        "the C05 parent-state retry CTest selector "
        "and its two named four-node fault controls, "
        "the skip-timeout-across-backlog actor modes and four-node finalization hold, "
        "five named restart-origin controls, the six refusal, deadline, retirement and acceptance CTests, "
        "and the E04 Python negative-window tests; "
        "the Rust job compiles every test target and runs the E04 exact wallet confirmation group"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
