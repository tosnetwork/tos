#!/usr/bin/env python3
"""Run the real checker on canonical version-16 configuration and funded probes.

Only --controls mutates sources. Run that mode after every other build has
stopped; each production source is restored and rebuilt in finally.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument(
        "--control", action="append", help="run only this named mutation (with --controls)"
    )
    args = parser.parse_args()
    if args.control and not args.controls:
        parser.error("--control requires --controls")
    root = Path(__file__).resolve().parents[1]
    build = args.build_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").unlink(missing_ok=True)
    fixtures = output / "generated"
    fixtures.mkdir(exist_ok=True)
    for name in (
        "zerostate.boc",
        "basestate0.boc",
        "checker-gas-probe.fif",
        "checker-gas-probe.boc",
    ):
        (fixtures / name).unlink(missing_ok=True)
    binary = build / "test-ext-message-generated-checker"
    runs = {}
    env = dict(
        os.environ, SOURCE_DATE_EPOCH="1789434000", TOS_ADMISSION_GENERATED_DIR=str(fixtures)
    )

    def run(name, command, cwd=root):
        with (output / (name + ".log")).open("wb") as log:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        runs[name] = {"command": [str(arg) for arg in command], "returncode": result.returncode}
        return result.returncode

    def require_success(name, command, cwd=root):
        if run(name, command, cwd):
            raise RuntimeError(name + " failed; inspect " + str(output / (name + ".log")))

    # Public deterministic test records. The canonical template hashes these
    # distinct validator descriptors; this checker test performs no consensus
    # signing and makes no validator-key-generation acceptance claim.
    manifest = b"".join(
        bytes([i]) * 32 + bytes([i | 0x10]) * 32 + bytes([i | 0x20]) * 1312 for i in range(1, 5)
    )
    (fixtures / "validator-pq.pub").write_bytes(manifest)
    (fixtures / "main-wallet.pk").write_bytes(b"\x53" * 32)
    wrapper = fixtures / "candidate.fif"
    wrapper.write_text(
        "0x" + "42" * 32 + " constant quantum-network-tag\n"
        "true constant quantum-admission-candidate\n"
        f'"{root / "crypto/smartcont/gen-zerostate.fif"}" include\n'
    )
    require_success(
        "generate",
        [
            str(build / "crypto/create-state"),
            "-I",
            str(root / "crypto/fift/lib"),
            "-I",
            str(root / "crypto/smartcont"),
            "-I",
            str(build / "crypto/smartcont"),
            "-s",
            str(wrapper),
        ],
        fixtures,
    )
    source = root / "test/wallet-quantum/checker-gas-probe.fc"
    assembly = fixtures / "checker-gas-probe.fif"
    require_success(
        "compile-probe",
        [
            str(build / "crypto/func"),
            "-SPA",
            "-o",
            str(assembly),
            str(root / "crypto/smartcont/stdlib.fc"),
            str(source),
        ],
    )
    assemble = fixtures / "assemble.fif"
    assemble.write_text(
        f'"Asm.fif" include\n"{assembly}" include\n'
        f'2 boc+>B "{fixtures / "checker-gas-probe.boc"}" B>file\n'
    )
    require_success(
        "assemble-probe",
        [str(build / "crypto/fift"), "-I", str(root / "crypto/fift/lib"), "-s", str(assemble)],
    )
    source = root / "test/wallet-quantum/admission-action-probe.fc"
    assembly = fixtures / "admission-action-probe.fif"
    require_success(
        "compile-action-probe",
        [
            str(build / "crypto/func"),
            "-SPA",
            "-o",
            str(assembly),
            str(root / "crypto/smartcont/stdlib.fc"),
            str(source),
        ],
    )
    assemble = fixtures / "assemble-action.fif"
    assemble.write_text(
        f'"Asm.fif" include\n"{assembly}" include\n'
        f'2 boc+>B "{fixtures / "admission-action-probe.boc"}" B>file\n'
    )
    require_success(
        "assemble-action-probe",
        [str(build / "crypto/fift"), "-I", str(root / "crypto/fift/lib"), "-s", str(assemble)],
    )
    require_success("baseline", [str(binary)])
    baseline = (output / "baseline.log").read_text(errors="replace")
    required_tests = [
        chain + suffix
        for chain in ("Basechain", "Masterchain")
        for suffix in ("StopsAtAccept", "StopsAtSetGasLimit", "RejectsInsufficientSetGasLimit")
    ]
    required_tests.extend(
        [
            "LocalPriorityAdmittedWhileRegularLaneIsSaturated",
            "OldCompletionsDoNotConsumeReplacementCheckerSlots",
            "AdmissionAcceptsComputeButExecutionRejectsInvalidAction",
        ]
    )
    if "9 test(s) passed" not in baseline or any(name not in baseline for name in required_tests):
        raise RuntimeError("baseline did not execute all required checker cases")
    measurements = [
        {
            "workchain": int(workchain),
            "operation": "ACCEPT" if operation == "0" else "SETGASLIMIT",
            "gas_used": int(gas),
            "config_root": config_root.lower(),
        }
        for workchain, operation, gas, config_root in re.findall(
            r"Generated checker wc=(-?\d+) operation=(\d+) gas=(\d+) config=([0-9a-fA-F]{64})",
            baseline,
        )
    ]
    if len(measurements) != 4:
        raise RuntimeError("baseline did not report all four actual acceptance measurements")
    expected_operations = {
        (workchain, operation) for workchain in (-1, 0) for operation in ("ACCEPT", "SETGASLIMIT")
    }
    if {(item["workchain"], item["operation"]) for item in measurements} != expected_operations:
        raise RuntimeError("baseline did not cover both acceptance operations in both workchains")
    if len({item["config_root"] for item in measurements}) != 1:
        raise RuntimeError("baseline checker cases used different generated configurations")

    def rebuild(name):
        require_success(
            name,
            [
                "cmake",
                "--build",
                str(build),
                "--target",
                "test-ext-message-generated-checker",
                "test-ext-message-pool",
                "test-ext-message-expiry",
            ],
        )

    if args.controls:
        controls = [
            (
                "reverse-priority-wakeup",
                "validator/impl/ext-message-pool.cpp",
                b"auto &[priority, waiters] = *admission_waiters_.rbegin();",
                b"auto &[priority, waiters] = *admission_waiters_.begin();",
                ["WaitersWakeByPriorityThenFifo"],
                "awakened.back()",
            ),
            (
                "reverse-fifo-wakeup",
                "validator/impl/ext-message-pool.cpp",
                b"auto waiter = std::move(waiters.front());\n    waiters.pop_front();",
                b"auto waiter = std::move(waiters.back());\n    waiters.pop_back();",
                ["WaitersWakeByPriorityThenFifo"],
                "awakened.back()",
            ),
            (
                "disable-normalized-refusal-removal",
                "validator/impl/ext-message-pool.cpp",
                b"void ExtMessagePool::complete_external_messages(std::vector<ExtMessage::Hash> to_delete) {",
                b"void ExtMessagePool::complete_external_messages(std::vector<ExtMessage::Hash> to_delete) { return;",
                ["CollatorRefusalRemovesEveryNormalizedVariantExactlyOnce"],
                "metrics::ExtMessageRemovalReason::filtered",
            ),
            (
                "disable-priority-eviction",
                "validator/impl/ext-message-pool.cpp",
                b"admission_waiters_.empty() || admission_waiters_.begin()->first >= priority",
                b"true",
                ["PriorityEvictsLowerPriorityWaiterAtTheQueueCap"],
                "low.await_ready()",
            ),
            (
                "disable-ordered-expiry",
                "validator/impl/expiry-ordered-list.hpp",
                b"oldest_ != nullptr && oldest_->delete_at.is_in_past(now)",
                b"false",
                ["PopsExpiredHeadInOrderExactlyOnce"],
                "count is not equal to 2u",
            ),
            (
                "repeat-rejected-execution",
                "validator/impl/ext-message-checker.cpp",
                b"failure = Failure::vm_rejected;",
                b"failure = Failure::vm_rejected;\n"
                b"  auto repeated = ExtMessageQ::run_message_on_account(wc, &account, state.utime, "
                b"state.lt + 1, message->root_cell(), *exec_config);\n"
                b"  if (repeated.is_ok()) { co_return result; }",
                ["RejectedContractExecutesVmExactlyOnce"],
                "counter.starts",
            ),
            (
                "ignore-checker-generation",
                "validator/impl/ext-message-pool.cpp",
                b"if (current_generation == checkers_generation_) {",
                b"if (true) {",
                ["OldCompletionsDoNotConsumeReplacementCheckerSlots"],
                "priority.await_ready()",
            ),
            (
                "disable-local-priority",
                "validator/manager.cpp",
                b"opts_->get_ext_message_pool_options()->local_ls_message_priority,",
                b"0,",
                ["LocalPriorityAdmittedWhileRegularLaneIsSaturated"],
                "priority.await_ready()",
            ),
            (
                "restore-admission-action-phase",
                "validator/impl/external-message.cpp",
                b"if (!trans->compute_phase->accepted) {",
                b"if (trans->compute_phase->accepted && "
                b"(!trans->prepare_action_phase(exec_config.action_phase_cfg) || "
                b"!trans->action_phase->success)) { "
                b'return td::Status::Error("action refused by mutation"); }\n'
                b"  if (!trans->compute_phase->accepted) {",
                ["AdmissionAcceptsComputeButExecutionRejectsInvalidAction"],
                "admitted.is_ok()",
            ),
            (
                "disable-stop",
                "validator/impl/external-message.cpp",
                b"exec_config->compute_phase_cfg.stop_on_accept_message = true;",
                b"exec_config->compute_phase_cfg.stop_on_accept_message = false;",
                [
                    "BasechainStopsAtAccept",
                    "BasechainStopsAtSetGasLimit",
                    "MasterchainStopsAtAccept",
                    "MasterchainStopsAtSetGasLimit",
                ],
                "External message is accepted, stopping TVM",
            ),
            (
                "wrong-workchain-prices",
                "validator/impl/ext-message-checker.cpp",
                b"ExtMessageQ::ExecutionConfig::create(*config_snapshot.config, wc, state.utime, false)",
                b"ExtMessageQ::ExecutionConfig::create(*config_snapshot.config, masterchainId, state.utime, false)",
                ["BasechainStopsAtAccept"],
                "counter.messages.find(credit)",
            ),
            (
                "skip-charge",
                "validator/impl/ext-message-pool.cpp",
                b"if (!work_admission_->try_consume()) {",
                b"if (false) {",
                ["BasechainStopsAtSetGasLimit", "MasterchainStopsAtSetGasLimit"],
                "rejected.error().message().str().find(expected)",
            ),
            (
                "ignore-setgaslimit",
                "crypto/vm/tosops.cpp",
                b"return exec_set_gas_generic(st, gas);",
                b"(void)gas;\n  return exec_set_gas_generic(st, GasLimits::infty);",
                [
                    "BasechainRejectsInsufficientSetGasLimit",
                    "MasterchainRejectsInsufficientSetGasLimit",
                ],
                "result.is_ok() == accepted",
            ),
        ]
        for field, condition in (
            ("num_regular_checkers", "> 128"),
            ("num_priority_checkers", "> 128"),
            ("max_ext_msg_per_addr", "== 0"),
            ("max_ext_msg_per_addr_time_window", "== 0.0"),
        ):
            controls.append(
                (
                    "disable-limit-" + field,
                    "validator/validator-options.cpp",
                    ("if (f." + field + "_ " + condition + ") {").encode(),
                    b"if (false) {",
                    ["OptionsPreserveReleaseDefaultsAndRefuseInvalidLimits"],
                    "ExtMessagePoolOptions::unpack(config).is_error()",
                )
            )
        if args.control:
            selected = set(args.control)
            known = {control[0] for control in controls}
            if selected - known:
                raise RuntimeError("unknown controls: " + ", ".join(sorted(selected - known)))
            controls = [control for control in controls if control[0] in selected]
        for label, relative, anchor, replacement, test_names, assertion in controls:
            guarded = root / relative
            original = guarded.read_bytes()
            if original.count(anchor) != 1:
                raise RuntimeError(label + ": expected exactly one mutation anchor")
            try:
                guarded.write_bytes(original.replace(anchor, replacement))
                rebuild(label + "-build")
                for test_name in test_names:
                    name = label + "-" + test_name
                    test_binary = (
                        build / "test-ext-message-pool"
                        if test_name
                        in {
                            "OptionsPreserveReleaseDefaultsAndRefuseInvalidLimits",
                            "PriorityEvictsLowerPriorityWaiterAtTheQueueCap",
                            "RejectedContractExecutesVmExactlyOnce",
                            "WaitersWakeByPriorityThenFifo",
                        }
                        else build / "test-ext-message-expiry"
                        if test_name
                        in {
                            "PopsExpiredHeadInOrderExactlyOnce",
                            "CollatorRefusalRemovesEveryNormalizedVariantExactlyOnce",
                        }
                        else binary
                    )
                    if run(name, [str(test_binary), "--filter", test_name]) == 0:
                        raise RuntimeError(name + " unexpectedly passed")
                    failure = (output / (name + ".log")).read_text(errors="replace")
                    if (
                        test_name not in failure
                        or "Expectation failed" not in failure
                        or assertion not in failure
                    ):
                        raise RuntimeError(name + " failed outside the intended semantic assertion")
                    if label == "disable-stop":
                        gas = re.search(
                            r"Generated checker wc=-?\d+ operation=\d+ gas=(\d+)", failure
                        )
                        if gas is None or int(gas.group(1)) <= 20000:
                            raise RuntimeError(name + " did not run the post-acceptance loop")
                    if label == "ignore-setgaslimit" and (
                        "External message is accepted, stopping TVM" not in failure
                        or "accepted=true, success=true" not in failure
                    ):
                        raise RuntimeError(name + " did not accept the bypassed gas limit")
            finally:
                guarded.write_bytes(original)
                rebuild(label + "-restore-build")
                require_success(label + "-restored", [str(binary)])
                require_success(label + "-pool-restored", [str(build / "test-ext-message-pool")])
                require_success(
                    label + "-expiry-restored", [str(build / "test-ext-message-expiry")]
                )

    sources = [
        "crypto/smartcont/gen-zerostate.fif",
        "test/wallet-quantum/checker-gas-probe.fc",
        "test/wallet-quantum/admission-action-probe.fc",
        "test/test-ext-message-generated-checker.cpp",
        "scripts/check-ext-message-generated.py",
        "validator/impl/ext-message-checker.cpp",
        "validator/impl/external-message.cpp",
        "validator/impl/ext-message-pool.cpp",
        "crypto/vm/tosops.cpp",
    ]
    artifacts = {}
    evidence_files = [output / (name + ".log") for name in runs]
    evidence_files.extend(
        fixtures / name
        for name in (
            "zerostate.boc",
            "basestate0.boc",
            "checker-gas-probe.boc",
            "admission-action-probe.boc",
        )
    )
    for path in sorted(evidence_files):
        raw = path.read_bytes()
        artifacts[str(path.relative_to(output))] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    report = {
        "passed": True,
        "controls": args.controls,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "measurements": measurements,
        "runs": runs,
        "sources": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources
        },
        "artifacts": artifacts,
        "scope": "Real pool/checker on unchanged canonical candidate ConfigParams; synthetic funded accounts and shard descriptor",
        "limits": [
            "No HTTP/ADNL listener or live state database",
            "No production CPU/rate/burst calibration",
            "No wallet authorization or recipient-delivery claim",
            "Public fixture validator records are not signing keys",
        ],
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": True,
                "tests": len(required_tests),
                "controls": args.controls,
                "output": str(output),
                "scope": report["scope"],
            }
        )
    )


if __name__ == "__main__":
    main()
