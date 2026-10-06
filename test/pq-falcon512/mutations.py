"""Compile each mutation, require a targeted failing assertion, restore and re-run."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--build", type=Path, required=True)
p.add_argument("--artifacts", type=Path, required=True)
p.add_argument("--library", type=Path, required=True)
p.add_argument("--old-signer", type=Path, required=True)
a = p.parse_args()
build = a.build.resolve()
out = a.artifacts.resolve()
out.mkdir(exist_ok=True, parents=True)
reports = []


def run(cmd):
    result = subprocess.run([str(x) for x in cmd], cwd=R, capture_output=True, text=True)
    return result


def compile_vm():
    result = run(["cmake", "--build", build, "--target", "test-pq-falcon512-parity", "-j", "2"])
    (out / "mutation-build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("mutation did not compile: " + (result.stdout + result.stderr)[-1500:])


def inspect_vm(name):
    result = run([build / "crypto/pq/test-pq-falcon512-parity", out / "scenarios.tsv"])
    if result.returncode:
        raise RuntimeError("driver failed instead of exercising an assertion")
    path = out / f"mutant-{name}.tsv"
    path.write_text(result.stdout)
    check = run(
        [
            sys.executable,
            R / "test/pq-falcon512/compare.py",
            out / "scenarios.tsv",
            path,
            out / "rust.tsv",
            "--out",
            out / "mutant.json",
        ]
    )
    return check


for name, file, old, new in [
    (
        "verification",
        "crypto/vm/pqops.cpp",
        "switch (tos::pq::verify_falcon512_padded(message, signature, key))",
        "switch (tos::pq::VerifyResult::valid)",
    ),
    (
        "version",
        "crypto/vm/pqops.h",
        "pq_falcon512_min_version = 19",
        "pq_falcon512_min_version = 18",
    ),
    ("base-gas", "crypto/vm/pqops.h", "pq_falcon512_base_gas = 20000", "pq_falcon512_base_gas = 0"),
    (
        "canonical-chunk",
        "crypto/vm/pqops.cpp",
        "(cs.size_refs() && size != max_chunk_bytes)",
        "(false)",
    ),
]:
    path = R / file
    original = path.read_text()
    if original.count(old) != 1:
        raise ValueError("mutation target missing or ambiguous: " + name)
    try:
        path.write_text(original.replace(old, new))
        compile_vm()
        check = inspect_vm(name)
        killed = check.returncode != 0 and (
            "execution divergence" in check.stderr or "ValueError" in check.stderr
        )
        reports.append(
            dict(
                guard=name,
                compiled=True,
                killed=killed,
                assertion=check.stderr.splitlines()[-1][:500] if killed else "",
            )
        )
        if not killed:
            raise RuntimeError("live mutant: " + name)
    finally:
        path.write_text(original)
        compile_vm()
    # A restored green result is required between mutants.
    if inspect_vm("restored-" + name).returncode:
        raise RuntimeError("restored baseline failed")

for name, file, old, new in [
    (
        "root-func",
        "crypto/smartcont/falcon512-auth-module.fc",
        ".store_uint(root_hash, 256)",
        ".store_uint(0, 256)",
    ),
    (
        "root-tol",
        "crypto/smartcont/falcon512-auth-module.tol",
        ".storeUint(rootHash, 256)",
        ".storeUint(0, 256)",
    ),
    (
        "profile-func",
        "crypto/smartcont/falcon512-auth-module.fc",
        "  throw_unless(auth::bad_operation, ds~load_uint(16) == 1);",
        "  ds~load_uint(16);",
    ),
    (
        "profile-tol",
        "crypto/smartcont/falcon512-auth-module.tol",
        "    assert (ds.loadUint(16) == 1) throw 1811;",
        "    ds.loadUint(16);",
    ),
    (
        "request-network-func",
        "crypto/smartcont/falcon512-auth-module.fc",
        "  throw_unless(auth::wrong_network, cs~load_int(32) == network);",
        "  cs~load_int(32);",
    ),
    (
        "request-network-tol",
        "crypto/smartcont/falcon512-auth-module.tol",
        "    assert (cs.loadInt(32) == network) throw 1801;",
        "    cs.loadInt(32);",
    ),
    (
        "chain-network-func",
        "crypto/smartcont/falcon512-auth-module.fc",
        "  throw_unless(auth::wrong_network, network == auth_global_id());",
        "  ;; mutation: skip actual-chain binding",
    ),
    (
        "chain-network-tol",
        "crypto/smartcont/falcon512-auth-module.tol",
        "    assert (network == authGlobalId()) throw 1801;",
        "    // mutation: skip actual-chain binding",
    ),
]:
    path = R / file
    original = path.read_text()
    if original.count(old) != 1:
        raise ValueError("missing module mutation target")
    language = "func" if name.endswith("func") else "tol"
    args = [
        sys.executable,
        R / "test/falcon-auth/e2e.py",
        "--build",
        build,
        "--signer",
        a.library.resolve(),
        "--old-signer",
        a.old_signer.resolve(),
        "--out",
        out / name,
        "--module",
        language,
        "--case",
        "test_every_request_field_and_payload_are_authenticated"
        if "network" in name
        else "test_root_domain_and_profile_are_bound",
    ]
    try:
        path.write_text(original.replace(old, new))
        result = run(args)
        compiled = (out / name / "contracts.json").exists()
        killed = (
            compiled
            and result.returncode != 0
            and "E2E_ASSERTION_FAILURE" in result.stdout
            and "AssertionError:" in result.stderr
        )
        reports.append(
            dict(
                guard=name,
                compiled=compiled,
                killed=killed,
                assertion=next(
                    (l for l in result.stderr.splitlines() if "AssertionError:" in l), ""
                ),
            )
        )
        if not killed:
            raise RuntimeError(
                "module mutation did not reach its target assertion: "
                + name
                + " "
                + result.stderr[-700:]
            )
    finally:
        path.write_text(original)
    restored = run(args)
    if restored.returncode:
        raise RuntimeError("restored module failed: " + name)
(out / "mutations.json").write_text(json.dumps(reports, indent=2) + "\n")
print("PASS:", len(reports), "compiled mutations killed; restored baselines green")
