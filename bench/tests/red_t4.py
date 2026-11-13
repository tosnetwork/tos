#!/usr/bin/env python3
"""Red controls for test_t4 and test_remote: each guarded behaviour is broken in a copy,
and its test must fail.

Run: uv run python bench/tests/red_t4.py [--only NAME]

A mutant's test names a test of test_t4.py, or of another test file as
``test_remote.py::Class.test``.

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
RM = "bench/shard/remote.py"
J = "bench/shard/journal.py"
TR = "test_remote.py::"
LO = "LedgerOutcomes"
SUB = "Submissions"
PASS = "PassRule"
E2E = "RemoteRun.test_ramp_binds_every_transfer_over_json_rpc_and_never_leaks_a_key"
CAP = "RemoteRun.test_over_the_cap_is_refused_before_any_request"
FEE_CAP = "RemoteRun.test_a_fee_bound_over_max_cost_is_refused_before_any_send"
OVERCHARGE = "RemoteRun.test_a_fee_over_its_bound_stops_the_ramp"
FUNDING = "RemoteRun.test_a_funding_fee_over_its_bound_stops_before_the_ramp"
HAND = "FeeBound.test_a_100_action_external_matches_a_hand_computation"
ORDER = "JournalBeforeSend.test_every_attempt_is_on_disk_and_fsynced_before_its_send"
DISTINCT = "JournalBeforeSend.test_three_rate_gate_refusals_on_two_wallets_never_repeat_an_external"
KILL = "RemoteRun.test_a_kill_after_a_send_leaves_a_journal_reconcile_classifies"
TORN = "JournalReader.test_a_torn_last_line_is_dropped_and_reported"
INC = "IncompleteReads"
R_E2E = TR + "RemoteRun.test_remote_run_uses_json_rpc_only_and_never_leaks_the_key"
R_KILL = TR + "RemoteRun.test_a_kill_after_the_send_is_reconciled_before_any_new_signature"
R_LOCK = TR + "RemoteRun.test_a_second_invocation_on_a_locked_wallet_is_refused"
R_BUMP = TR + "RemoteRun.test_a_concurrent_nonce_bump_does_not_settle_the_request"
R_HANG = TR + "RemoteRun.test_a_hung_signer_before_any_send_is_killed_and_refused"
R_HANG2 = TR + "RemoteRun.test_a_hung_signer_after_a_send_is_killed_and_stops"
T2 = "bench/shard/t2collect.py"
RPC = "bench/shard/rpc.py"
RECON = "ReconcileHistory"
STEP = "StepVerdicts"

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
        'self.ledger.ambiguous(ext, reason or "ambiguous")',
        'self.ledger.ambiguous(ext, reason or "ambiguous")\n            self.release(ext, False)',
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
        J,
        'return True, f"external rejected: {message}"',
        'return False, f"external rejected: {message}"',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "refused: a seqno conflict is ambiguous",
        J,
        'return True, "seqno conflict: the wallet\'s nonce moved"',
        'return False, "seqno conflict: the wallet\'s nonce moved"',
        f"{SUB}.test_a_refused_external_marks_every_action_refused_with_its_reason",
    ),
    (
        "refused: a rate-gate refusal is ambiguous",
        J,
        'return "refused", f"rate gate: {error.reason}"',
        'return "ambiguous", f"rate gate: {error.reason}"',
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
        "    if why is not None:\n        return refuse(why)\n\n    try:\n        key",
        "    if False:\n        return refuse(why)\n\n    try:\n        key",
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
        '"load_wallets": [w.address for w in wallets],\n    }',
        '"load_wallets": [w.seed.reveal().hex() for w in wallets],\n    }',
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
        "walk_blocks(self.rpc, [prev, cur], max_blocks=4096)",
        "walk_blocks(self.rpc, [cur, cur], max_blocks=4096)",
        E2E,
    ),
    (
        "fee bound: forward fees dropped",
        RM,
        "        import_fee + gas_fee + forward_fees,\n",
        "        import_fee + gas_fee,\n",
        HAND,
    ),
    (
        "fee bound: forward fees rounded down",
        RM,
        "return self.lump_price + _ceil_shr16(self.bit_price * bits + self.cell_price * cells)",
        "return self.lump_price + ((self.bit_price * bits + self.cell_price * cells) >> 16)",
        HAND,
    ),
    (
        "fee bound: gas dropped (end to end)",
        RM,
        "    gas_fee = config.gas.max_fee()\n",
        "    gas_fee = 0\n",
        E2E,
    ),
    (
        "fee bound: a received value buys gas_limit",
        RM,
        "        return self.fee(self.bought_for(value))\n",
        "        return self.max_fee()\n",
        "FeeBound.test_the_computation_a_received_value_can_buy",
    ),
    (
        "fee bound: one size priced for every external",
        R,
        "        sizes[plan.batch] += runs * full\n        if rest:\n            sizes[rest] += runs\n",
        "        sizes[plan.batch] += runs * full\n",
        "FeeBound.test_the_whole_ramp_bound_sums_every_external_of_every_step_and_repeat",
    ),
    (
        "fee bound: recipients not counted",
        R,
        "        return self.transfer_total + self.receipts + self.recipients + storage\n",
        "        return self.transfer_total + self.receipts + storage\n",
        "FeeBound.test_the_whole_ramp_bound_sums_every_external_of_every_step_and_repeat",
    ),
    (
        "cost: the bench fee bound left out",
        R,
        "        funding + bench_fees,\n",
        "        funding,\n",
        FEE_CAP,
    ),
    (
        "cost: the second refusal skipped",
        R,
        "    if why is not None:\n        return refuse(why)\n    if balance_before",
        "    if False:\n        return refuse(why)\n    if balance_before",
        FEE_CAP,
    ),
    (
        "cost: load fees over the funding accepted",
        R,
        "    if bound.load_fees > bound.funding:\n",
        "    if False:\n",
        "Bound.test_over_a_cap_is_refused",
    ),
    (
        "horizon: deadlines not capped",
        R,
        "max(min(now + self.a.lifetime, self.horizon), w.last_deadline + 1)",
        "max(now + self.a.lifetime, w.last_deadline + 1)",
        f"{SUB}.test_request_deadlines_are_capped_at_the_fee_horizon",
    ),
    (
        "cross-check: a load fee over its bound ignored",
        R,
        "        if ext.tx_fee <= limit:\n",
        "        if True:\n",
        OVERCHARGE,
    ),
    (
        "cross-check: the wallet's storage not allowed for",
        R,
        "        limit = ext.fee_bound + self.storage_bounds[ext.wallet]\n",
        "        limit = ext.fee_bound\n",
        f"{SUB}.test_a_fee_over_its_bound_stops_the_ramp",
    ),
    (
        "cross-check: a funding fee over its bound ignored",
        R,
        "        if fee > limit:\n",
        "        if False:\n",
        FUNDING,
    ),
    (
        "exit: a ledger anomaly passes",
        R,
        "    if anomalies or duplicates:\n        return FAILED\n",
        "    if False:\n        return FAILED\n",
        "ExitStatus.test_the_mapping",
    ),
    (
        "exit: a stopped ramp passes (end to end)",
        R,
        "    if stop_reason is not None:\n        return STOPPED\n",
        "    if False:\n        return STOPPED\n",
        OVERCHARGE,
    ),
    # ── the journal (both users) ──
    (
        "journal: transfer attempts never written",
        R,
        "        try:\n            self.journal.append(*records)\n",
        "        try:\n            pass\n",
        ORDER,
    ),
    (
        "journal: written but not fsynced",
        J,
        "            view = view[written:]\n        os.fsync(self.fd)\n",
        "            view = view[written:]\n",
        ORDER,
    ),
    (
        "journal: a torn tail is an error",
        J,
        "    tail = lines.pop()  # what follows",
        "    tail = b''; lines = lines[:-1] if not lines[-1] else lines  # what follows",
        TORN,
    ),
    (
        "journal: the remote attempt written after its send",
        RM,
        "        journal.append(record)\n        try:\n            await self.remote.send(external)\n",
        "        try:\n            await self.remote.send(external)\n            journal.append(record)\n",
        R_E2E,
    ),
    (
        "reconcile: an attempt without an answer is skipped",
        J,
        "        verdict = await find_attempt(rpc, attempt, now, grace)\n        sent = read.sent(key)\n",
        "        sent = read.sent(key)\n        if sent is None:\n            continue\n"
        "        verdict = await find_attempt(rpc, attempt, now, grace)\n",
        KILL,
    ),
    (
        "reconcile: a new T4 run signs without accounting for earlier attempts",
        J,
        "                    if read.settled(key):\n                        continue\n",
        "                    if True:\n                        continue\n",
        KILL,
    ),
    (
        "reconcile: a new remote run signs without accounting for earlier attempts",
        J,
        "                    if read.settled(key):\n                        continue\n",
        "                    if True:\n                        continue\n",
        R_KILL,
    ),
    (
        "remote: a deployed hop tree is funded again",
        RM,
        '    if root.get("state") == "active":\n',
        "    if False:\n",
        R_KILL,
    ),
    (
        "lock: the wallet lock is not taken",
        J,
        "            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n",
        "            pass\n",
        R_LOCK,
    ),
    (
        "lock: the T4 ramp signs under a held lock",
        J,
        "            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n",
        "            pass\n",
        "RemoteRun.test_a_second_invocation_on_a_locked_wallet_is_refused",
    ),
    (
        "confirmation: any external of the wallet settles the request",
        J,
        '        and t.tx.in_msg.hash == attempt["external"]\n',
        "",
        R_BUMP,
    ),
    (
        "confirmation: a skipped start message settles the start",
        J,
        "        if match is None:\n",
        "        if False:\n",
        TR + "RemoteRun.test_a_consumed_nonce_without_a_start_message_is_inconclusive",
    ),
    (
        "signer: no deadline before the first send",
        RM,
        "            out, err = process.communicate(text, timeout=timeout)\n",
        "            out, err = process.communicate(text, timeout=None)\n",
        R_HANG,
    ),
    (
        "signer: a hung start signer is not a stop",
        RM,
        '        return stop("STOPPED", f"start: {error}", INCONCLUSIVE)\n',
        '        return stop("REFUSED", f"start: {error}", REFUSED)\n',
        R_HANG2,
    ),
    (
        "signer: the hung signer is left running",
        RM,
        "                os.killpg(process.pid, signal.SIGKILL)\n",
        "                pass\n",
        "Signing.test_a_hung_batch_signer_is_killed_at_its_deadline",
    ),
    # ── distinct attempts ──
    (
        "distinct: a refused request is rebuilt with the same deadline",
        R,
        "max(min(now + self.a.lifetime, self.horizon), w.last_deadline + 1)",
        "max(min(now + self.a.lifetime, self.horizon), w.last_deadline)",
        DISTINCT,
    ),
    # ── incomplete reads ──
    (
        "follower: an incomplete transaction list counts as read",
        R,
        "                if block.complete:\n",
        "                if True:\n",
        f"{INC}.test_a_transaction_list_that_fails_once_is_read_again",
    ),
    (
        "follower: an unread header is ignored",
        R,
        "            missing = unread_blocks(blocks, prev, cur)\n",
        "            missing = []\n",
        f"{INC}.test_a_header_that_fails_once_is_read_again",
    ),
    (
        "follower: no second read",
        R,
        "READ_ATTEMPTS = 3\n",
        "READ_ATTEMPTS = 1\n",
        f"{INC}.test_a_transaction_list_that_fails_once_is_read_again",
    ),
    (
        "follower: an unreadable block does not stop the ramp",
        R,
        "        elif self.follower is not None and self.follower.failed is not None:\n",
        "        elif False:\n",
        f"{INC}.test_a_block_that_stays_unreadable_stops_the_ramp_inconclusive",
    ),
    (
        "follower: an unreadable block does not stop the ramp (end to end)",
        R,
        "        elif self.follower is not None and self.follower.failed is not None:\n",
        "        elif False:\n",
        "RemoteRun.test_shard_reads_that_never_complete_stop_the_ramp_inconclusive",
    ),
    # ── load wallets follow the whole bench identity ──
    (
        "identity: load seeds ignore the bench wallet's address",
        R,
        'LOAD_TAG + bench_seed.reveal() + identity + index.to_bytes(4, "big")',
        'LOAD_TAG + bench_seed.reveal() + index.to_bytes(4, "big")',
        "Signing.test_two_bench_wallets_with_one_seed_never_share_a_load_wallet",
    ),
    # ── a failed receipt is never a completion ──
    (
        "receipt: a failed recipient transaction completes",
        L,
        "        ext.receipt_failure[i] = tx.phase_failure\n",
        "        ext.receipt_failure[i] = None\n",
        f"{LO}.test_a_failed_recipient_transaction_is_delivered_failed_never_completed",
    ),
    (
        "receipt: the delivered_failed outcome ignored",
        L,
        "        if receipt is not None:\n            return DELIVERED_FAILED, receipt\n",
        "",
        f"{LO}.test_a_failed_recipient_transaction_is_delivered_failed_never_completed",
    ),
    (
        "receipt: an aborted transaction executed (end to end)",
        T2,
        '    if aborted is True:\n        return "transaction aborted"\n',
        "    if aborted is True:\n        return None\n",
        E2E,
    ),
    (
        "receipt: an aborted transaction executed",
        T2,
        '    if aborted is True:\n        return "transaction aborted"\n',
        "    if aborted is True:\n        return None\n",
        f"{LO}.test_the_servers_rendering_decides_whether_a_receipt_executed",
    ),
    (
        "receipt: an unshown abort flag counts as false",
        T2,
        "    if aborted is not False:\n",
        "    if False:\n",
        f"{LO}.test_the_servers_rendering_decides_whether_a_receipt_executed",
    ),
    (
        "receipt: a failed compute phase executed",
        T2,
        '        if compute.get("success") is True:\n            return None\n',
        "        return None\n",
        f"{LO}.test_the_servers_rendering_decides_whether_a_receipt_executed",
    ),
    (
        "receipt: any compute skip executed",
        T2,
        "        if type(reason) is int and reason == COMPUTE_SKIP_NO_STATE:\n",
        "        if True:\n",
        f"{LO}.test_the_servers_rendering_decides_whether_a_receipt_executed",
    ),
    # ── reconcile: only a provably complete history proves not_executed ──
    (
        "history: a non-object entry is skipped",
        J,
        "        entries = [_entry(x) for x in page]\n",
        "        entries = [_entry(x) for x in page if isinstance(x, dict)]\n",
        f"{RECON}.test_a_non_object_entry_is_undetermined",
    ),
    (
        "history: an empty continuation page proves completeness",
        J,
        "            if expect is None:\n                return out, True\n",
        "            if True:\n                return out, True\n",
        f"{RECON}.test_a_truncated_history_is_undetermined",
    ),
    (
        "history: a skipped predecessor goes unnoticed",
        J,
        "            if expect is not None and (found.tx.lt, found.tx.hash) != expect:\n",
        "            if False:\n",
        f"{RECON}.test_a_page_that_skips_a_transaction_is_undetermined",
    ),
    # ── a step's layout needs every block it spans ──
    (
        "layout: missing endpoints ignored",
        L,
        "    stable = verdict.status == t2check.PASS and not changes and not missing\n",
        "    stable = verdict.status == t2check.PASS and not changes\n",
        f"{STEP}.test_a_layout_needs_both_endpoints_and_every_block_between",
    ),
    (
        "layout: an unreached step end counts",
        R,
        '        layout["stable"] = layout["stable"] and reached\n',
        "",
        f"{STEP}.test_a_step_the_follower_never_reached_the_end_of_does_not_count",
    ),
    # ── stop conditions before every batch and every send ──
    (
        "stop: not checked before a batch is built",
        R,
        "            self.check_stop()\n            if self.stop_reason is not None:\n                break\n",
        "",
        f"{STEP}.test_a_stop_file_present_before_a_batch_means_nothing_is_built_signed_or_sent",
    ),
    (
        "stop: not checked after signing",
        R,
        "        self.check_stop()\n        if self.stop_reason is not None:\n            for ext, *_ in ready:\n",
        "        if False:\n            for ext, *_ in ready:\n",
        f"{STEP}.test_a_stop_file_that_appears_while_signing_holds_back_every_send",
    ),
    (
        "stop: a stop file at the start is not a refusal",
        R,
        "    if a.stop_file is not None and a.stop_file.exists():\n",
        "    if False:\n",
        "RemoteRun.test_a_stop_file_present_at_the_start_sends_nothing",
    ),
    (
        "live deadline: count from the follower's frontier",
        R,
        "            now = live\n",
        "            now = self.chain_now()\n",
        "LiveDeadlines.test_a_deadline_counts_from_the_live_head_not_the_lagging_frontier",
    ),
    (
        "live deadline: fall back to the frontier without a reading",
        R,
        "            return None\n        now = max(self.live[1], floor)",
        "            return floor\n        now = max(self.live[1], floor)",
        "LiveDeadlines.test_without_a_live_reading_no_request_is_built",
    ),
    (
        "live deadline: a stale reading serves forever",
        R,
        "        if self.live is None or time.monotonic() - self.live[0] > LIVE_MAX_AGE:",
        "        if self.live is None:",
        "LiveDeadlines.test_a_reading_older_than_its_maximum_age_is_not_used",
    ),
    (
        "follower: read the windows one at a time",
        R,
        "        windows = await asyncio.gather(\n"
        "            *(self.read_window(p, c) for p, c in zip(opening, fresh, strict=True)),\n"
        "            return_exceptions=True,\n"
        "        )",
        "        windows = [await self.read_window(p, c) for p, c in zip(opening, fresh, strict=True)]",
        "FollowerReadRate.test_the_windows_of_one_round_are_read_together_and_applied_in_order",
    ),
    (
        "follower: apply the windows after a failed one",
        R,
        '                log.error("follower stopped: %s", self.failed)\n                return advanced\n',
        '                log.error("follower stopped: %s", self.failed)\n                continue\n',
        "FollowerReadRate.test_a_window_that_fails_stops_the_frontier_before_it_and_applies_the_ones_before",
    ),
    (
        "reader pool: no failover",
        RPC,
        "                failure = error\n",
        "                raise\n",
        "ReaderPoolTests.test_an_endpoint_that_errs_is_skipped_for_the_next",
    ),
    (
        "reader pool: no rotation",
        RPC,
        "        self._cursor = (self._cursor + 1) % n\n",
        "",
        "ReaderPoolTests.test_reads_are_spread_over_every_endpoint",
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
    """Run the named tests, each file's in one process with a fresh, empty bytecode cache."""
    by_file: dict[str, list[str]] = {}
    for test in tests:
        name, _, rest = test.rpartition("::")
        by_file.setdefault(name or "test_t4.py", []).append(rest)
    result = subprocess.CompletedProcess[str]([], 0, "", "")
    for name, names in sorted(by_file.items()):
        with tempfile.TemporaryDirectory() as cache:
            env = os.environ | {"PYTHONPYCACHEPREFIX": cache, "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, str(dest / "bench/tests" / name), *names],
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
                cwd=dest,
            )
        if result.returncode != 0:
            return result
    return result


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
