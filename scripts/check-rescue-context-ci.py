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
    "signer-fee",
    "signer-mnemonic",
    "signer-vault",
    "fee-promotion",
    "fee-lifecycle",
    "fee-successor",
    "signer-custody",
    "vm-ingress",
    "release-wallet",
    "mutations",
]
RUNNERS = ["ubuntu-24.04", "ubuntu-24.04-arm"]
RUNNER_MATRIX = "runner: [ubuntu-24.04, ubuntu-24.04-arm]"
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


def expanded_steps(contract):
    return [part for row in contract["steps"] for part in row.get("parts", [row])]


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
        "      max-parallel: 20\n" in suites_text, "all 19 workers need bounded parallel capacity"
    )
    matrix = suites_text.split("      matrix:\n", 1)[1].split("    runs-on:", 1)[0]
    require(
        matrix
        == """        suite: [signer-fee, signer-mnemonic, signer-vault, fee-promotion, fee-lifecycle, fee-successor, signer-custody, vm-ingress, release-wallet, mutations]
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
    for original in contract["steps"]:
        if "parts" not in original:
            continue
        commands = []
        for part in original["parts"]:
            name = part["name"]
            require(name in step_map, f"missing serial step {name}")
            block = step_map[name]
            run = block[block.index("        run:") :].rstrip() + "\n"
            require(run.startswith("        run: |\n"), "split body must be a literal script")
            commands.append(run.removeprefix("        run: |\n"))
            require(part["x86_only"] == original["x86_only"], "split architecture policy changed")
        require(
            digest("        run: |\n" + "".join(commands)) == original["run_sha256"],
            "split commands do not reconstruct original: " + original["name"],
        )
    steps = expanded_steps(contract)
    for row in steps:
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
    original_names = [row["name"] for row in steps]
    require(len(set(original_names)) == len(steps), "duplicate original coverage entry")
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
        for row in steps:
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
    named = {row["name"] for row in steps}
    for name, b in step_map.items():
        if name in named:
            continue
        if "        if:" in b:
            require(
                name
                in {
                    "Build the fee lifecycle CLI",
                    "Verify generated transaction root controls and bundle",
                    "Retain generated transaction roots",
                    "Verify original wallet variant roots",
                    "Retain original wallet variant roots",
                    "Compile cache statistics",
                    "Record exact source and public evidence hashes",
                },
                f"unexpected skip rule: {name}",
            )
    validate_generated_roots(prefix, suites_text, parity, step_map)
    validate_wallet_roots(suites_text, parity, step_map)
    coverage = {pair: [row["name"] for row in steps if selected(row, *pair)] for pair in pairs()}
    for pair in coverage:
        if pair[0] == "release-wallet":
            coverage[pair].extend(
                ["Verify original wallet variant roots", "Retain original wallet variant roots"]
            )
    return coverage


def validate_wallet_roots(suites, parity, steps):
    name = "Verify original wallet variant roots"
    require(name in steps, "missing original wallet root producer")
    require("Retain original wallet variant roots" in steps, "missing wallet root upload")
    before, run = steps[name].split("        run:", 1)
    require(
        before
        == "      - name: "
        + name
        + "\n        if: contains(fromJSON('[\"release-wallet\"]'), matrix.suite)\n",
        "wallet roots require both release-wallet architectures",
    )
    require(
        digest("        run:" + run.rstrip() + "\n")
        == "7d5af09f7663eb4d6456820777f37ee39ad72269726607b844041b7548a1e35c",
        "wallet producer/control/bundle commands changed",
    )
    order = list(steps)
    require(
        order.index("Require source restoration")
        < order.index(name)
        < order.index("Retain original wallet variant roots")
        < order.index("Record successful suite"),
        "wallet root checks/upload must precede suite success",
    )
    require(
        steps.get("Retain original wallet variant roots", "")
        == """      - name: Retain original wallet variant roots
        if: contains(fromJSON('["release-wallet"]'), matrix.suite)
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: wallet-variant-roots-${{ matrix.runner }}-attempt-${{ github.run_attempt }}
          path: artifacts/wallet-variant-roots
          if-no-files-found: error
          retention-days: 14
""",
        "wallet bundle upload policy changed",
    )
    require(
        "run: python test/executor-parity/wallet_variant_bundle.py --check-download\n" in parity,
        "wallet download preflight missing",
    )
    download = """      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          pattern: wallet-variant-roots-*
          path: wallet-roots
"""
    require(download in parity, "wallet bundle download missing")
    final = """      - name: Compare original wallet roots from both architectures
        env:
          SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        run: python test/executor-parity/wallet_variant_bundle.py --compare wallet-roots --receipts receipts
"""
    require(final in parity, "wallet final comparison/source missing")
    require(
        parity.index("wallet_variant_bundle.py --check-download")
        < parity.index(download)
        < parity.index(final),
        "wallet download must be bounded before extraction/comparison",
    )


def validate_generated_roots(prefix, suites, parity, steps):
    for path in ("test/executor-parity/**", "test/falcon-auth/linked_roots.py", "test/rel02/**"):
        require(f"      - '{path}'\n" in prefix, f"missing generated root trigger {path}")
    require("  actions: read\n" in prefix, "artifact metadata needs read-only actions permission")
    name = "Verify generated transaction root controls and bundle"
    require(name in steps, "missing generated root controls")
    block = steps[name]
    before, run = block.split("        run:", 1)
    require(
        before
        == "      - name: "
        + name
        + "\n        if: contains(fromJSON('[\"release-wallet\"]'), matrix.suite)\n",
        "generated controls need both release-wallet architectures",
    )
    require(
        digest("        run:" + run.rstrip() + "\n")
        == "ea53ec07c9c9310a8e3dc662f87fd742bc32a3fdfaced66b7f2ac4ed06282fc0",
        "generated producer/control/bundle commands changed",
    )
    order = list(steps)
    require(
        order.index("Require source restoration")
        < order.index(name)
        < order.index("Record successful suite"),
        "generated controls must precede suite success",
    )
    upload = steps.get("Retain generated transaction roots", "")
    require(
        upload
        == """      - name: Retain generated transaction roots
        if: contains(fromJSON('["release-wallet"]'), matrix.suite)
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: rescue-roots-${{ matrix.runner }}-attempt-${{ github.run_attempt }}
          path: artifacts/generated-roots
          if-no-files-found: error
          retention-days: 14
""",
        "generated root upload identity/audience changed",
    )
    require(
        order.index(name)
        < order.index("Retain generated transaction roots")
        < order.index("Record successful suite"),
        "generated root upload must follow controls",
    )
    preflight = """      - name: Bound generated root artifact download
        env:
          GH_TOKEN: ${{ github.token }}
        run: python test/executor-parity/generated_bundle.py --check-download
"""
    download = """      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
        with:
          pattern: rescue-roots-*
          path: roots
"""
    compare = """      - name: Compare generated transaction roots from both architectures
        env:
          SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        run: python test/executor-parity/generated_bundle.py --compare roots --receipts receipts
"""
    require(
        parity.count(preflight) == parity.count(download) == parity.count(compare) == 1,
        "generated final preflight/download/source comparison missing",
    )
    require(
        parity.index(preflight) < parity.index(download) < parity.index(compare),
        "generated download selection must be bounded first",
    )
    require(
        "        ref: ${{ github.event.pull_request.head.sha || github.sha }}" in parity,
        "generated final checkout must match expected source",
    )


def coverage_for_event(coverage, event):
    require(event in {"pull_request", "workflow_dispatch"}, "unsupported workflow event")
    return coverage


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
    return newest


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
