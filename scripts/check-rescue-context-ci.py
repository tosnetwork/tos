#!/usr/bin/env python3
"""Keep the split rescue jobs complete, isolated and fail-closed."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = [
    "signer-core",
    "fee-promotion",
    "fee-lifecycle",
    "fee-successor",
    "signer-custody",
    "vm-ingress",
    "release-wallet",
    "mutations",
]
RUNNERS = ["ubuntu-24.04", "ubuntu-24.04-arm"]
RUNNER_MATRIX = "runner: ${{ fromJSON(github.event_name == 'workflow_dispatch' && '[\"ubuntu-24.04\",\"ubuntu-24.04-arm\"]' || '[\"ubuntu-24.04\"]') }}"
CONTRACT = ROOT / "test/wallet-quantum/rescue-ci-contract.json"
WORKFLOW = ROOT / ".github/workflows/rescue-context.yml"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def pairs():
    return {
        (suite, runner)
        for suite in SUITES
        for runner in RUNNERS
        if (suite, runner) != ("mutations", "ubuntu-24.04-arm")
    }


def blocks(text):
    """Read our deliberately fixed step layout; reject unsupported metadata."""
    return re.split(r"(?m)(?=^      - (?:name:|uses:))", text)[1:]


def selected(row, suite, runner):
    return suite in row["suites"] and (not row["x86_only"] or runner == RUNNERS[0])


def condition(row):
    suites = json.dumps(row["suites"], separators=(",", ":"))
    return f"contains(fromJSON('{suites}'), matrix.suite)" + (
        " && matrix.runner == 'ubuntu-24.04'" if row["x86_only"] else ""
    )


def validate(text, contract, source_guard):
    require(
        text.count("\n  suites:\n") == text.count("\n  parity:\n") == 1,
        "expected one suite matrix and one parity gate",
    )
    require("  workflow_dispatch:\n" in text, "ARM must remain manually available")
    prefix, rest = text.split("\n  suites:\n", 1)
    suites_text, parity = rest.split("\n  parity:\n", 1)
    require("continue-on-error:" not in text, "suite failures must propagate")
    require(re.search(r"(?m)^    if:", suites_text) is None, "suite job must not be conditional")
    require("      fail-fast: false\n" in suites_text, "all suites must complete independently")
    require(
        "      max-parallel: 16\n" in suites_text, "all 15 workers need bounded parallel capacity"
    )
    matrix = suites_text.split("      matrix:\n", 1)[1].split("    runs-on:", 1)[0]
    require(
        matrix
        == """        suite: [signer-core, fee-promotion, fee-lifecycle, fee-successor, signer-custody, vm-ingress, release-wallet, mutations]
        """
        + RUNNER_MATRIX
        + """
        exclude:
          # These controls were x86-only in the serial workflow.
          - suite: mutations
            runner: ubuntu-24.04-arm
""",
        "suite or architecture coverage changed",
    )
    require(
        "    runs-on: ${{ matrix.runner }}\n" in suites_text,
        "native architecture must match the matrix",
    )
    for path in [
        ".github/workflows/rescue-context.yml",
        ".github/workflows/source-guards.yml",
        ".github/actions/native-cache/**",
        "scripts/check-rescue-context-ci.py",
        "scripts/test_rescue_context_ci.py",
        "test/wallet-quantum/rescue-ci-contract.json",
    ]:
        require(f"      - '{path}'\n" in prefix, f"missing trigger path {path}")
    step_map = {}
    for b in blocks(suites_text):
        if b.startswith("      - name: "):
            name = b.splitlines()[0].split("name: ", 1)[1]
            require(name not in step_map, f"duplicate step {name}")
            step_map[name] = b
    require(
        len(contract["steps"]) == 52,
        "serial coverage contract must retain all 52 build/control steps",
    )
    for row in contract["steps"]:
        name = row["name"]
        require(name in step_map, f"missing serial step {name}")
        b = step_map[name]
        run = b[b.index("        run:") :].rstrip() + "\n"
        require(digest(run) == row["run_sha256"], f"serial commands changed: {name}")
        before = b[: b.index("        run:")]
        expected = "      - name: " + name + "\n"
        if name != "Build native Release tools and both Rust drivers":
            expected += "        if: " + condition(row) + "\n"
        require(before == expected, f"unexpected condition or metadata: {name}")
        # Every formerly dual-architecture step still runs on both. Repeated
        # prerequisites are permitted; removing an original audience is not.
        expected_runners = {RUNNERS[0]} if row["x86_only"] else set(RUNNERS)
        actual = {r for s, r in pairs() if selected(row, s, r)}
        require(actual == expected_runners, f"architecture lost: {name}")
    original_names = [row["name"] for row in contract["steps"]]
    require(len(set(original_names)) == 52, "duplicate original coverage entry")
    for helper in [
        "Build shared public fixture signer",
        "Build the fee lifecycle CLI",
        "Require source restoration",
        "Record successful suite",
        "Retain success receipt",
    ]:
        require(helper in step_map, f"missing prerequisite or evidence step: {helper}")
    require(
        [name for name in step_map if name in original_names] == original_names,
        "serial prerequisite order changed",
    )
    for suite, runner in pairs():
        done = set()
        for row in contract["steps"]:
            if selected(row, suite, runner):
                require(
                    set(row["requires"]) <= done,
                    f"missing prerequisite for {row['name']} in {suite}/{runner}",
                )
                done.add(row["name"])
    fixture = step_map["Build shared public fixture signer"]
    require(
        fixture.strip().endswith(
            "run: cargo build --manifest-path tosctl/src/Cargo.toml --locked -p wallet-pq-signer --example public_fixture"
        )
        and "if:" not in fixture,
        "every suite needs the public fixture signer",
    )
    cli = step_map["Build the fee lifecycle CLI"]
    require(
        '        if: contains(fromJSON(\'["fee-lifecycle","fee-successor","fee-promotion"]\'), matrix.suite)\n'
        in cli
        and cli.strip().endswith(
            "run: cargo build --manifest-path tosctl/src/Cargo.toml --locked -p tosctl --features pq-wallet"
        ),
        "fee lifecycle CLI prerequisite missing",
    )
    require(
        list(step_map).index("Build shared public fixture signer")
        < list(step_map).index(original_names[1]),
        "public fixture signer must exist before its consumers",
    )
    require(
        list(step_map).index("Build the fee lifecycle CLI")
        < list(step_map).index("Full R2 fee transaction parity at diagnostic credit"),
        "CLI must exist before fee lifecycle consumers",
    )
    require(f"uses: {UPLOAD}" in suites_text, "public evidence must still be retained")
    for pattern in [
        "PUBLIC-TEST-ONLY-lms-tree",
        "PUBLIC-TEST-ONLY-successor-tree",
        "PUBLIC-TEST-ONLY-tree",
    ]:
        require(f"!artifacts/context/**/{pattern}" in suites_text, "test tree must not be uploaded")
    require(
        "uses: ./.github/actions/native-cache" in suites_text, "use the existing object-only cache"
    )
    require(
        "profile: rescue-context\n" in suites_text and "max-size: 1G\n" in suites_text,
        "native object cache must have its own bounded profile",
    )
    require(
        "actions/download-artifact@" not in suites_text,
        "suites must regenerate mutable fixtures locally",
    )
    require(
        "rust-cache@" not in suites_text and "path: build-cargo" not in suites_text,
        "do not cache mutable test state or Rust mutation build trees",
    )
    require(
        "        ref: ${{ github.event.pull_request.head.sha || github.sha }}" in suites_text,
        "all suites must test the same source",
    )
    require(
        step_map["Require source restoration"].strip().endswith("run: git diff --exit-code"),
        "all suites must restore source after controls",
    )
    require(
        "if:" not in step_map["Require source restoration"], "source restoration cannot be skipped"
    )
    require(
        "--write-receipt artifacts/context/suite-success.json"
        in step_map["Record successful suite"],
        "success receipt missing",
    )
    require(
        "if:" not in step_map["Record successful suite"],
        "receipt must run only after successful checks",
    )
    receipt = step_map["Retain success receipt"]
    require(
        "name: rescue-receipt-${{ matrix.runner }}-${{ matrix.suite }}-attempt-${{ github.run_attempt }}"
        in receipt,
        "receipt artifacts must not collide on partial reruns",
    )
    require(
        "name: rescue-context-${{ matrix.runner }}-${{ matrix.suite }}-attempt-${{ github.run_attempt }}"
        in suites_text,
        "public artifacts must not collide on partial reruns",
    )
    require(
        f"uses: {UPLOAD}" in receipt
        and "if-no-files-found: error" in receipt
        and "if:" not in receipt,
        "missing receipt must fail the suite",
    )
    require(re.search(r"(?m)^        if:", parity) is None, "parity steps must not be skipped")
    require(
        RUNNER_MATRIX + "\n" in parity,
        "both original parity check names must remain",
    )
    require(
        "needs: suites\n" in parity and "    if: always()\n" in parity,
        "parity gate must run even when a suite fails or is cancelled",
    )
    require(
        "name: parity (${{ matrix.runner }}, 180)\n" in parity, "retain the existing gate names"
    )
    require(
        'run: test "$SUITES_RESULT" = success\n' in parity
        and "SUITES_RESULT: ${{ needs.suites.result }}" in parity,
        "matrix failures cannot turn green",
    )
    require(
        f"uses: {DOWNLOAD}" in parity and "pattern: rescue-receipt-*" in parity,
        "gate must retrieve all success receipts",
    )
    require(
        "--verify-receipts receipts" in parity, "gate must check receipt completeness and source"
    )
    require(
        "python3 scripts/check-rescue-context-ci.py\n" in source_guard
        and "python3 scripts/test_rescue_context_ci.py\n" in source_guard,
        "coverage guard and its negative tests must run in required source-guards",
    )
    # Detect unsupported extra per-step skip rules, including hidden receipts.
    named = {row["name"] for row in contract["steps"]}
    for name, b in step_map.items():
        if name in named:
            continue
        if "        if:" in b:
            require(
                name
                in {
                    "Build the fee lifecycle CLI",
                    "Compile cache statistics",
                    "Record exact source and public evidence hashes",
                },
                f"unexpected skip rule: {name}",
            )
    return {
        pair: [row["name"] for row in contract["steps"] if selected(row, *pair)] for pair in pairs()
    }


def coverage_for_event(coverage, event):
    require(event in {"pull_request", "workflow_dispatch"}, "unsupported workflow event")
    return {
        pair: names
        for pair, names in coverage.items()
        if event == "workflow_dispatch" or pair[1] == RUNNERS[0]
    }


def receipt(suite, runner, coverage):
    event = os.environ["GITHUB_EVENT_NAME"]
    coverage = coverage_for_event(coverage, event)
    require((suite, runner) in coverage, "suite not scheduled for this workflow event")
    return {
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "event": event,
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "suite": suite,
        "runner": runner,
        "contract_sha256": digest(CONTRACT.read_text()),
        "checks": coverage[(suite, runner)],
    }


def verify_receipts(directory, source, run_id, attempt, coverage, event):
    coverage = coverage_for_event(coverage, event)
    # Re-running failed jobs retains earlier successful workers. Bind all receipts
    # to this source/run, permit earlier successful attempts, and select the newest
    # receipt per worker. The separate matrix-result gate still rejects a failed
    # current attempt even if an older success receipt exists.
    require(re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "invalid current attempt")
    seen = set()
    newest = {}
    for p in directory.rglob("suite-success.json"):
        r = json.loads(p.read_text())
        pair = (r["suite"], r["runner"])
        require(pair in coverage, "unexpected suite receipt")
        require(r["event"] == event, "receipt belongs to another workflow event")
        require(
            r["source"] == source and r["run_id"] == run_id,
            "receipt belongs to another source or run",
        )
        require(
            isinstance(r["run_attempt"], str)
            and re.fullmatch(r"[1-9][0-9]*", r["run_attempt"]) is not None,
            "invalid receipt attempt",
        )
        number = int(r["run_attempt"])
        require(number <= int(attempt), "receipt comes from a future attempt")
        require((pair, number) not in seen, "duplicate suite receipt for one attempt")
        require(
            r["contract_sha256"] == digest(CONTRACT.read_text()),
            "receipt coverage contract differs",
        )
        require(r["checks"] == coverage[pair], "receipt omits or changes required checks")
        seen.add((pair, number))
        newest[pair] = max(number, newest.get(pair, 0))
    require(
        set(newest) == set(coverage), f"missing success receipts: {set(coverage) - set(newest)}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-receipt", type=Path)
    parser.add_argument("--suite", choices=SUITES)
    parser.add_argument("--runner", choices=RUNNERS)
    parser.add_argument("--verify-receipts", type=Path)
    args = parser.parse_args()
    coverage = validate(
        WORKFLOW.read_text(),
        json.loads(CONTRACT.read_text()),
        (ROOT / ".github/workflows/source-guards.yml").read_text(),
    )
    if args.write_receipt:
        args.write_receipt.parent.mkdir(parents=True, exist_ok=True)
        args.write_receipt.write_text(
            json.dumps(receipt(args.suite, args.runner, coverage), indent=2) + "\n"
        )
    if args.verify_receipts:
        verify_receipts(
            args.verify_receipts,
            os.environ["SOURCE_SHA"],
            os.environ["GITHUB_RUN_ID"],
            os.environ["GITHUB_RUN_ATTEMPT"],
            coverage,
            os.environ["GITHUB_EVENT_NAME"],
        )
    print(
        f"RESCUE_CI_COVERAGE_OK: {len(coverage)} isolated suites; all 52 original build/control steps retained"
    )


if __name__ == "__main__":
    main()
