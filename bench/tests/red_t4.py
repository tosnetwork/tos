#!/usr/bin/env python3
"""Red controls for test_t4: each guarded behaviour is broken in a copy, and its test must fail.

Run: uv run python bench/tests/red_t4.py [--only NAME]

Every mutant runs in its own copy of the bench tree under a temporary
directory, with its own empty PYTHONPYCACHEPREFIX, so neither the worktree
nor a stale compiled module can turn a mutant green. The unmutated copy runs
first and must pass every test the mutants use.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COPIED = ["bench/t4", "bench/shard", "bench/pqbench", "bench/run_t4_ramp.py", "bench/tests"]

L = "bench/t4/ledger.py"
R = "bench/t4/ramp.py"
LO = "LedgerOutcomes"
SUB = "Submissions"
PASS = "PassRule"
E2E = "RemoteRun.test_ramp_binds_every_transfer_over_json_rpc_and_never_leaks_a_key"
CAP = "RemoteRun.test_over_the_cap_is_refused_before_any_request"

# (name, file, old, new, test)
MUTANTS: list[tuple[str, str, str, str, str]] = [
    (
        "skipped: bind out messages by position",
        L,
        'i = slots.get((message.destination or "", message.value or 0))',
        "i = list(tx.out_msgs).index(message)",
        f"{LO}.test_a_skipped_action_is_not_counted_as_completed",
    ),
    (
        "skipped: ignore the action's failure",
        L,
        "        if failure is not None:\n",
        "        if False:\n",
        f"{LO}.test_a_skipped_action_is_not_counted_as_completed",
    ),
    (
        "ambiguous: resolve from the chain",
        L,
        "if self.submission == AMBIGUOUS:",
        "if self.submission == AMBIGUOUS and self.tx_hash is None:",
        f"{LO}.test_an_ambiguous_submission_stays_unknown",
    ),
    (
        "ambiguous: resolve from the chain (end to end)",
        L,
        "if self.submission == AMBIGUOUS:",
        "if self.submission == AMBIGUOUS and self.tx_hash is None:",
        E2E,
    ),
    (
        "ambiguous: release the wallet on no answer",
        R,
        'self.ledger.ambiguous(ext, f"no answer: {type(error).__name__}")',
        'self.ledger.ambiguous(ext, f"no answer: {type(error).__name__}")\n'
        "            self.release(ext, False)",
        f"{SUB}.test_an_ambiguous_submission_stays_unknown_and_is_never_resent",
    ),
    (
        "never resent: drop the message-hash guard",
        L,
        "        if msg_hash in self._by_hash:\n",
        "        if False:\n",
        f"{LO}.test_the_same_message_is_never_submitted_twice",
    ),
    (
        "refused: an external rejection is ambiguous",
        R,
        'return True, f"external rejected: {message}"',
        'return False, f"external rejected: {message}"',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "refused: a seqno conflict is ambiguous",
        R,
        'return True, "seqno conflict: the wallet\'s nonce moved"',
        'return False, "seqno conflict: the wallet\'s nonce moved"',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "refused: a rate-gate refusal is ambiguous",
        R,
        'self.ledger.refuse(ext, f"rate gate: {error.reason}")',
        'self.ledger.ambiguous(ext, f"rate gate: {error.reason}")',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "refused: the rate gate's reason is lost",
        "bench/shard/rpc.py",
        'reason = "HTTP 429" if status == 429 else str(RATE_LIMITED_CODE)',
        'reason = ""',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "finality: one block above finality counts",
        L,
        "if finalized is None or mc > finalized:",
        "if finalized is None or mc > finalized + 1:",
        f"{LO}.test_a_completed_transfer_above_the_finalized_seqno_is_not_completed",
    ),
    (
        "binding: an unknown delivery takes any pending message",
        L,
        "hit = self._by_emitted.get(message.hash)",
        "hit = self._by_emitted.get(message.hash) or next(iter(self._by_emitted.values()), None)",
        f"{LO}.test_a_recipient_transaction_for_another_message_does_not_complete",
    ),
    (
        "binding: the recipient account is not checked",
        L,
        "if tx.account != ext.destinations[i] or message.bounced:",
        "if message.bounced:",
        f"{LO}.test_a_recipient_transaction_for_another_message_does_not_complete",
    ),
    (
        "pass rule: completed only bounded by offered",
        L,
        "abs(completed - offered) <= rule.tolerance * offered",
        "completed <= offered",
        f"{PASS}.test_throughput_must_match_offered_within_one_percent",
    ),
    (
        "pass rule: backlog growth ignored",
        L,
        "backlog_ok = backlog_end - backlog_start <= rule.backlog_slack",
        "backlog_ok = True",
        f"{PASS}.test_a_growing_backlog_fails",
    ),
    (
        "pass rule: p50 checked instead of p95",
        L,
        "latency_ok = p95 is not None and p95 <= rule.p95_limit",
        "latency_ok = p50 is not None and p50 <= rule.p95_limit",
        f"{PASS}.test_p95_over_thirty_seconds_fails",
    ),
    (
        "pass rule: drain completions counted",
        L,
        "if state == COMPLETED and start <= (ext.recipient_utime[i] or 0) < end:",
        "if state == COMPLETED and start <= (ext.recipient_utime[i] or 0):",
        f"{PASS}.test_drain_completions_do_not_count",
    ),
    (
        "bound: refusal not enforced",
        R,
        '    if why is not None:\n        print(f"refused: {why}", file=sys.stderr)\n        return REFUSED\n',
        "    if False:\n        return REFUSED\n",
        CAP,
    ),
    (
        "bound: layout repeats not counted",
        R,
        "    runs = 1 + plan.repeats\n",
        "    runs = 1\n",
        "Bound.test_bound_counts_every_step_and_repeat",
    ),
    (
        "key: load seeds written to the results",
        R,
        'record["load_wallets"] = [w.address for w in wallets]',
        'record["load_wallets"] = [w.seed.reveal().hex() for w in wallets]',
        E2E,
    ),
    (
        "key: a failing signer's stderr is reported",
        R,
        'raise RuntimeError(f"bench signer failed with exit status {result.returncode}")',
        'raise RuntimeError(f"bench signer failed: {result.stderr}")',
        "Signing.test_a_failing_signer_does_not_echo_its_input",
    ),
    (
        "end to end: the follower walks no shard block",
        R,
        "walk_blocks(self.rpc, [self.last, cur], max_blocks=4096)",
        "walk_blocks(self.rpc, [cur, cur], max_blocks=4096)",
        E2E,
    ),
]


def tree(dest: Path) -> None:
    for rel in COPIED:
        src = ROOT / rel
        if src.is_dir():
            shutil.copytree(src, dest / rel, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
    (dest / "test/tostester").mkdir(parents=True)
    (dest / "test/tostester/src").symlink_to(ROOT / "test/tostester/src")


def run_tests(dest: Path, tests: list[str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as cache:
        env = os.environ | {"PYTHONPYCACHEPREFIX": cache, "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, str(dest / "bench/tests/test_t4.py"), *tests],
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd=dest,
        )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--only", help="run only mutants whose name contains this text")
    p.add_argument("--why", action="store_true", help="show each mutant's failing assertion")
    a = p.parse_args()
    mutants = [m for m in MUTANTS if a.only is None or a.only in m[0]]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "control"
        tree(base)
        control = run_tests(base, sorted({m[4] for m in mutants}))
        if control.returncode != 0:
            print("CONTROL FAILED: the unmutated tests do not pass\n" + control.stderr[-3000:])
            return 2
        print(f"control: {len({m[4] for m in mutants})} tests pass unmutated")
        for k, (name, rel, old, new, test) in enumerate(mutants):
            dest = Path(tmp) / f"mutant{k}"
            tree(dest)
            path = dest / rel
            text = path.read_text()
            if text.count(old) != 1:
                print(f"BROKEN  {name}: the guarded text occurs {text.count(old)} times")
                failures += 1
                continue
            path.write_text(text.replace(old, new))
            result = run_tests(dest, [test])
            red = result.returncode != 0
            print(f"{'RED   ' if red else 'GREEN!'}  {name}  [{test}]")
            failures += 0 if red else 1
            if a.why:
                lines = [x for x in result.stderr.splitlines() if "Error" in x or "assert" in x]
                print("        " + " | ".join(lines[-3:])[:400])
    print(f"{len(mutants) - failures} of {len(mutants)} mutants caught")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
