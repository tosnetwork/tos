#!/usr/bin/env python3
"""Run ownership and retention regressions with each repaired rule removed.

The named native tests must run and pass before mutation, fail with the old
behavior, and pass after restoration. Only the configured checkout is edited.
Every source is restored byte for byte, including on interruption; receipts
record its hashes and each test's exit status. Command logs retain at most
512 KiB each, and a timeout or a test that never starts is not a red result.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "validator-engine/wallet-index-writer.cpp"
REPLAY = ROOT / "services/index-replay-loop.h"
VERIFY = ROOT / "services/index-verify.cpp"
TARGET = "test-wallet-index-source"
LOG_BYTES = 512 * 1024

# A mutant restores the original behavior without requiring an earlier Git
# object in a shallow CI checkout. Each anchor must occur exactly once.
MUTATIONS = (
    (
        "malformed-getter-result-escapes",
        (
            (
                WRITER,
                "    // A malformed getter result is a negative verdict, not work to retry.\n"
                "    return err.get_errno() == static_cast<int>(vm::Excno::virt_err) ? TokenVerification::Indeterminate\n"
                "                                                                    : TokenVerification::Rejected;",
                "    throw;",
            ),
        ),
        (
            "WalletIndexVerify_malformed_wallet_getters_do_not_block_full_ownership",
            "WalletIndexVerify_malformed_resolver_getters_do_not_block_full_ownership",
            "WalletIndexVerify_the_ownership_drain_rejects_malformed_getters",
        ),
    ),
    (
        "absent-account-data-is-parked",
        (
            (
                WRITER,
                "    if (state_init.data.is_null()) {",
                "    if (state_init.data.is_null() || state_init.data->size_refs() < 1) {",
            ),
            (
                WRITER,
                "  return state_init.data.not_null() ? AccountAtHead::WithCode : AccountAtHead::Undecodable;",
                "  return state_init.data.not_null() && state_init.data->size_refs() > 0\n"
                "             ? AccountAtHead::WithCode : AccountAtHead::Undecodable;",
            ),
        ),
        (
            "WalletIndexVerify_absent_account_data_does_not_block_full_ownership",
            "WalletIndexVerify_the_ownership_drain_runs_accounts_with_absent_data",
        ),
    ),
    (
        "trusted-restore-retention-stays-stalled",
        ((REPLAY, "    if (window.stalled) {", "    if (window.stalled && false) {"),),
        (
            "WalletIndexSource_a_trusted_restore_resumes_retention_after_the_source_bootstrap_gap",
            "WalletIndexSource_only_a_full_index_can_rebase_retention_across_a_source_gap",
        ),
    ),
    (
        "retained-ancestor-looks-up-block-one",
        ((VERIFY, "get_old_mc_block_id(seqno, first)", "get_old_mc_block_id(1, first)"),),
        (
            "WalletIndexVerify_a_retained_ancestor_comes_from_the_requested_entry_in_the_bound_head_state",
        ),
    ),
    (
        "first-block-anchor-refuses-its-own-head",
        ((VERIFY, "block_id_from_head_state(head, block_root, state, 1, true)",
          "block_id_from_head_state(head, block_root, state, 1, false)"),),
        ("WalletIndexVerify_block_1_comes_from_the_state_the_heads_block_names",),
    ),
)

EXPECTED_RED = {
    "WalletIndexVerify_malformed_wallet_getters_do_not_block_full_ownership":
        r"(?:terminate called after throwing an instance of ['\"]vm::VmError['\"]|uncaught exception of type vm::VmError)",
    "WalletIndexVerify_malformed_resolver_getters_do_not_block_full_ownership":
        r"(?:terminate called after throwing an instance of ['\"]vm::VmError['\"]|uncaught exception of type vm::VmError)",
    "WalletIndexVerify_the_ownership_drain_rejects_malformed_getters": re.escape(
        "Expectation failed: db.token_backlog_stats().move_as_ok().parked is not equal to 0u"
    ),
    "WalletIndexVerify_absent_account_data_does_not_block_full_ownership": re.escape(
        "Expectation failed: outcome.step == VerifyStep::Done && index.state() == VerificationState::Full"
    ),
    "WalletIndexVerify_the_ownership_drain_runs_accounts_with_absent_data": re.escape(
        "Expectation failed: db.token_backlog_stats().move_as_ok().parked is not equal to 0u"
    ),
    "WalletIndexSource_a_trusted_restore_resumes_retention_after_the_source_bootstrap_gap": re.escape(
        "Expectation failed: db->get_window_base().move_as_ok() is not equal to 23u"
    ),
    "WalletIndexSource_only_a_full_index_can_rebase_retention_across_a_source_gap": re.escape(
        "Expectation failed: db->get_window_base().move_as_ok() is not equal to state == VerificationState::Full ? 23u : 10u"
    ),
    "WalletIndexVerify_a_retained_ancestor_comes_from_the_requested_entry_in_the_bound_head_state":
        "the head's masterchain state does not record masterchain block 17",
    "WalletIndexVerify_block_1_comes_from_the_state_the_heads_block_names":
        "the requested masterchain block is not an ancestor of the head",
}


def native_test_marker(test: str) -> bytes:
    return f"Running test Test_{test}...".encode()


def require_test_result(test: str, status: int, executed: bool, output: str, expect_red: bool) -> str | None:
    if not executed:
        raise RuntimeError(f"{test} never started; exit {status}")
    if not expect_red:
        if status != 0:
            raise RuntimeError(f"{test} must pass; exit {status}")
        return None
    # With backtraces enabled the native signal handler prints SIGABRT and
    # exits 1. Without that handler, waitpid reports the abort signal itself.
    aborted = status == -signal.SIGABRT or (status == 1 and re.search(r"\bSignal: 6(?:\s|$)", output))
    pattern = EXPECTED_RED.get(test)
    match = re.search(pattern, output) if pattern is not None else None
    if not aborted or match is None:
        raise RuntimeError(f"{test} did not abort at its expected semantic failure; exit {status}, pattern {pattern!r}")
    return match.group(0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_source(build: Path, checkout: Path) -> None:
    entries = [
        line.split("=", 1)[1]
        for line in (build / "CMakeCache.txt").read_text().splitlines()
        if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")
    ]
    if len(entries) != 1 or Path(entries[0]).resolve() != checkout.resolve():
        raise RuntimeError("the build must use the invoked checkout as its one configured source")


def mutation_text(originals: dict[Path, bytes], edits) -> dict[Path, bytes]:
    changed = {}
    for path, anchor, replacement in edits:
        text = changed.get(path, originals[path]).decode()
        if text.count(anchor) != 1:
            raise RuntimeError(f"mutation anchor must occur once in {path.name}: {anchor!r}")
        changed[path] = text.replace(anchor, replacement, 1).encode()
    return changed


class SourceEdits:
    def __init__(self, paths):
        self.originals = {path: path.read_bytes() for path in paths}
        self.expected = dict(self.originals)

    @staticmethod
    def write(path: Path, data: bytes) -> None:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), path.stat().st_mode & 0o777)
                stream.write(data)
            temporary.replace(path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def replace(self, changed: dict[Path, bytes]) -> None:
        for path in changed:
            if path.read_bytes() != self.expected[path]:
                raise RuntimeError(f"source changed outside the control runner: {path}")
        for path, data in changed.items():
            # The replacement is atomic: interruption leaves either the
            # original bytes or the exact expected mutation to restore.
            self.expected[path] = data
            self.write(path, data)

    def restore(self) -> None:
        failures = []
        for path, original in self.originals.items():
            try:
                current = path.read_bytes()
            except OSError as error:
                failures.append(f"cannot read {path}: {error}")
                continue
            if current != self.expected[path] and current != original:
                failures.append(f"refusing to overwrite a concurrent source edit: {path}")
                continue
            try:
                if current != original:
                    self.write(path, original)
                if path.read_bytes() != original:
                    failures.append(f"control source restoration mismatch: {path}")
                    continue
            except OSError as error:
                failures.append(f"cannot restore {path}: {error}")
                continue
            self.expected[path] = original
        if failures:
            raise RuntimeError("; ".join(failures))


def run_logged(command: list[str], log: Path, timeout: float, marker: bytes = b"") -> tuple[int, bool]:
    """Drain output with a bounded tail and kill the command group on timeout."""
    tail = bytearray()
    marker_tail = b""
    observed = not marker
    completed = False
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    assert process.stdout is not None
    try:
        with selectors.DefaultSelector() as events:
            events.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"command timed out; this is not a sensitivity result: {command}")
                if not events.select(min(remaining, 0.25)):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                if marker and not observed:
                    combined = marker_tail + chunk
                    observed = marker in combined
                    marker_tail = combined[-len(marker):]
                tail.extend(chunk)
                if len(tail) > LOG_BYTES:
                    del tail[:-LOG_BYTES]
        status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        completed = True
        return status, observed
    finally:
        if not completed:
            # The leader may already have exited while its child still
            # owns stdout. The whole command group must end on failure.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        log.write_bytes(tail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        raise ValueError("jobs must be positive")
    build = args.build_dir.resolve(strict=True)
    checked_source(build, ROOT)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    lock = (build / ".wallet-index-review-controls.lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    sources = SourceEdits((WRITER, REPLAY, VERIFY, ROOT / "services/index-verify.h"))
    tests = sorted({test for _, _, names in MUTATIONS for test in names})
    prepared = [(name, mutation_text(sources.originals, edits), names) for name, edits, names in MUTATIONS]
    command = ["cmake", "--build", str(build), "--target", TARGET, "-j", str(args.jobs)]
    source_commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    receipt = {
        "source_commit": source_commit,
        "source_sha256": {str(path.relative_to(ROOT)): sha256(data) for path, data in sources.originals.items()},
        "test_source_sha256": {
            name: sha256((ROOT / name).read_bytes())
            for name in ("test/test-wallet-index-source.cpp", "test/test-wallet-index-verify.cpp")
        },
        "log_limit_bytes": LOG_BYTES,
        "mutant_sha256": {
            name: {str(path.relative_to(ROOT)): sha256(data) for path, data in changed.items()}
            for name, changed, _ in prepared
        },
        "results": [],
        "sources_restored": False,
        "result": "FAILED",
    }

    def save() -> None:
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def compile_source(label: str) -> None:
        status, _ = run_logged(command, output / f"{label}-build.log", 600)
        if status != 0:
            raise RuntimeError(f"{label}: native build failed ({status}); this is not a sensitivity result")

    def test_source(label: str, names, expect_red: bool) -> None:
        for index, test in enumerate(names):
            log = output / f"{label}-{index}.log"
            status, executed = run_logged(
                [str(build / TARGET), "--filter", test],
                log,
                120,
                native_test_marker(test),
            )
            result = {"mutation": label, "test": test, "exit_status": status, "executed": executed, "accepted": False}
            if expect_red:
                result["expected_failure"] = EXPECTED_RED[test]
            receipt["results"].append(result)
            save()
            result["failure_match"] = require_test_result(test, status, executed, log.read_text(errors="replace"), expect_red)
            result["accepted"] = True
            save()

    try:
        compile_source("baseline")
        test_source("baseline", tests, False)
        for name, changed, names in prepared:
            sources.replace(changed)
            compile_source(name)
            test_source(name, names, True)
            sources.restore()
    finally:
        try:
            sources.restore()
            receipt["restored_sha256"] = {
                str(path.relative_to(ROOT)): sha256(path.read_bytes()) for path in sources.originals
            }
            receipt["sources_restored"] = receipt["source_sha256"] == receipt["restored_sha256"]
            receipt["tests_unchanged"] = all(
                sha256((ROOT / name).read_bytes()) == digest
                for name, digest in receipt["test_source_sha256"].items()
            )
            if not receipt["tests_unchanged"]:
                raise RuntimeError("test source changed during the control run")
            compile_source("restored")
            test_source("restored", tests, False)
        finally:
            save()
    receipt["result"] = "WALLET_INDEX_REVIEW_CONTROLS_OK"
    save()
    print(json.dumps(receipt, indent=2), flush=True)
    print("WALLET_INDEX_REVIEW_CONTROLS_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
