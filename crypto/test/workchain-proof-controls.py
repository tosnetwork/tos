#!/usr/bin/env python3
"""Run one compiled mutation at a time with byte-exact restoration evidence."""
import argparse
import hashlib
import difflib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace(path, before, after):
    original = path.read_text()
    if original.count(before) != 1:
        raise ValueError(f"nonunique mutation anchor: {path}: {before}")
    expected = original.replace(before, after, 1)
    patch = "".join(difflib.unified_diff(original.splitlines(True), expected.splitlines(True),
                                        fromfile="a/" + path.name, tofile="b/" + path.name))
    subprocess.run(["git", "apply", "--no-index", "--whitespace=nowarn", "-"],
                   cwd=path.parent, input=patch, text=True, check=True)
    if path.read_text() != expected:
        raise ValueError("mutation changed bytes outside the declared replacement")
    return expected.encode()


def restore(path, mutant, original):
    if path.read_bytes() != mutant:
        raise ValueError("unexpected concurrent source change; refusing restoration")
    patch = "".join(difflib.unified_diff(mutant.decode().splitlines(True), original.decode().splitlines(True),
                                        fromfile="a/" + path.name, tofile="b/" + path.name))
    subprocess.run(["git", "apply", "--no-index", "--whitespace=nowarn", "-"],
                   cwd=path.parent, input=patch, text=True, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", required=True)
    args = parser.parse_args()
    root, build, out = args.source.resolve(), args.build.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    work = "crypto/block/workchain-proof-work.h"
    engine = "crypto/block/workchain-account-engine.h"
    dispatch = "crypto/block/workchain-execution-dispatch.h"
    profile = "crypto/block/workchain-resource-policy.h"
    cases = {
        "precharge": (work, "if (units.ok() > declared_ - consumed_)", "if (false)", "unit"),
        "deduction": (work, "consumed_ += units.ok();", "consumed_ += 0;", "unit"),
        "sticky": (work, "if (failure_.is_error()) return failure_.clone();", "if (false) return failure_.clone();", "unit"),
        "invalid-classification": (work, "case WorkchainProofVerdict::InvalidProof:\n        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid)",
                                   "case WorkchainProofVerdict::InvalidProof:\n        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable)", "unit"),
        "runner-sticky": (engine, "TRY_STATUS(proofs.status());", "(void)proofs.status();", "runner"),
        "runner-profile": (engine, "if (source.policy().requires_proof_operation_meter())", "if (false)", "runner"),
        "declaration-cap": (engine, "WorkchainProofVerifier(declared_proof_work_)", "WorkchainProofVerifier(policy().resources().work_output.max_proof_units)", "runner"),
        "configured-forward": (dispatch, "return engine_->execute_metered_accounts(input, accounts, *configuration_, proofs);",
                               "return engine_->execute_accounts(input, accounts, *configuration_); // injected unmetered dispatch", "runner"),
        "fee-profile": (profile, "resources_.admission_version == 3 || resources_.admission_version == 4",
                        "resources_.admission_version == 3", "profiles"),
        "context-guard": (work, "!request.context_bytes || request.context_bytes > limits.max_context_bytes",
                          "request.context_bytes > limits.max_context_bytes", "unit"),
        "context-charge": (work, "result.context_bytes = request.context_bytes;", "result.context_bytes = 0;", "unit"),
        "count-overflow": (work, "if (part > std::numeric_limits<std::uint64_t>::max() - result)", "if (false)", "unit"),
        "engine-default": (engine,
            'return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),\n                             "engine has no operation-metered execution implementation");',
            'return execute_accounts(input, accounts);', "contracts"),
        "registry-default": (dispatch,
            'return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),\n                             "registered engine has no operation-metered implementation");',
            'return execute_accounts(input, accounts, configuration);', "contracts"),
        "reserved-key": ("crypto/block/workchain-proof-backend.cpp", "case UNO_CRYPTO_KEY:",
                         "case UNO_CRYPTO_KEY: return WorkchainProofVerdict::InvalidProof;", "backend"),
        "low-formula": (work, "proof_count_sum({sigma_terms, ip_terms, poly_terms})", "proof_count_sum({sigma_terms, ip_terms})", "trace"),
    }
    name, before, after, kind = cases[args.case]
    path = root / name
    original = path.read_bytes()
    target = "test-workchain-proof-work" if kind == "unit" else "test-workchain-block"
    if kind in {"trace", "backend"}:
        target = "test-workchain-proof-backend"
    if kind == "contracts":
        target = "test-workchain-proof-contracts"
    build_command = ["cmake", "--build", str(build), "--target", target, "-j32"]

    def run(command, logfile):
        with (out / logfile).open("w") as log:
            return subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT).returncode

    def test(stage):
        if kind == "trace":
            return run(["python3", str(root / "crypto/test/workchain-proof-trace.py"), "--source", str(root),
                        "--build", str(build), "--output", str(out / (stage + "-trace"))], stage + ".log")
        command = [str(build / target)]
        if kind == "backend":
            command += [str(root / "uno/crypto/fixtures/balance-kernel-v2.txt")]
        if kind == "runner":
            command += ["--filter", "AccountRegistryReplayConnectivity", "--verbosity", "0"]
        if kind == "profiles":
            command += ["--filter", "BatchPolicyVersionIdentityAgreement", "--verbosity", "0"]
        return run(command, stage + ".log")

    if run(build_command, "baseline-build.log") != 0 or test("baseline") != 0:
        raise ValueError("baseline failed; no mutation evidence")
    record = {"path": name, "from": before, "to": after, "original_sha256": sha(original),
              "baseline_binary_sha256": sha((build / target).read_bytes())}
    (out / "restore-audit.json").write_text(json.dumps(record, indent=2) + "\n")
    try:
        mutant = replace(path, before, after)
        record["recorded_mutant_sha256"] = sha(path.read_bytes())
        record["reconstructed_mutant_sha256"] = sha(original.replace(before.encode(), after.encode(), 1))
        if run(build_command, "mutant-build.log") != 0:
            raise ValueError("mutation did not compile; not behavioral evidence")
        record["mutant_binary_sha256"] = sha((build / target).read_bytes())
        record["mutant_exit"] = test("mutant")
        (out / "restore-audit.json").write_text(json.dumps(record, indent=2) + "\n")
        if record["mutant_exit"] == 0:
            raise ValueError("mutation stayed green")
    finally:
        # Restore the exact one-site edit before any next experiment.
        if path.read_bytes() != original:
            restore(path, original.replace(before.encode(), after.encode(), 1), original)
        if path.read_bytes() != original:
            raise ValueError("byte restoration failed")
        record["restored_sha256"] = sha(path.read_bytes())
        (out / "restore-audit.json").write_text(json.dumps(record, indent=2) + "\n")
    if run(build_command, "restored-build.log") != 0 or test("restored") != 0:
        raise ValueError("restored regression failed")
    record["restored_binary_sha256"] = sha((build / target).read_bytes())
    (out / "restore-audit.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
