#!/usr/bin/env python3
"""Run the real checker on canonical version-18 configuration and funded probes.

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
    args = parser.parse_args()
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
        "0x" + "42" * 32 + " constant v5r2-network-tag\n"
        "true constant v5r2-admission-candidate\n"
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
    source = root / "test/wallet-v5r2/checker-gas-probe.fc"
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
    require_success("baseline", [str(binary)])
    baseline = (output / "baseline.log").read_text(errors="replace")
    required_tests = [
        chain + suffix
        for chain in ("Basechain", "Masterchain")
        for suffix in ("StopsAtAccept", "StopsAtSetGasLimit", "RejectsInsufficientSetGasLimit")
    ]
    if "6 test(s) passed" not in baseline or any(name not in baseline for name in required_tests):
        raise RuntimeError("baseline did not execute the six required checker cases")
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
                "-j2",
            ],
        )

    if args.controls:
        controls = [
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
                    if run(name, [str(binary), "--filter", test_name]) == 0:
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

    sources = [
        "crypto/smartcont/gen-zerostate.fif",
        "test/wallet-v5r2/checker-gas-probe.fc",
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
        fixtures / name for name in ("zerostate.boc", "basestate0.boc", "checker-gas-probe.boc")
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
