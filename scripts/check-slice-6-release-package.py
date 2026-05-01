#!/usr/bin/env python3
"""Slice 6 release-package guardrails.

Stage 3 starts this checker with the rules that are cheap to enforce before
the full release package exists. Later Slice 6 stages extend it.
"""

from __future__ import annotations

from pathlib import Path
import json
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    full = ROOT / path
    if not full.exists():
        fail(f"missing required Slice 6 file: {path}")
    return full.read_text(encoding="utf-8")


def check_required_surface() -> None:
    delivery = read("crypto/smartcont/tol-stdlib/delivery.tol")
    schedule = read("crypto/smartcont/tol-stdlib/schedule.tol")
    time = read("crypto/smartcont/tol-stdlib/time.tol")
    supervision = read("crypto/smartcont/tol-stdlib/supervision.tol")

    for needle in [
        "BACK_PRESSURE_ACTIVATION_GATE = false",
        "Slice6DeadLetterSink",
        "slice6BackPressureAdvice",
    ]:
        if needle not in delivery:
            fail(f"delivery stdlib missing {needle}")

    for needle in [
        "Slice6ScheduledActionV1",
        "slice6ScheduledHandle",
        "SLICE6_SCHEDULE_CANCEL_NOT_AUTHORIZED",
        "forceExpireIfEscrowDepleted",
    ]:
        if needle not in schedule:
            fail(f"schedule stdlib missing {needle}")

    for needle in [
        "Slice6TimerBudget",
        "sendAfterBlocks",
        "sendAtMcSeqno",
        "cancelScheduled",
        "trustedCurrentMcSeqno",
    ]:
        if needle not in time:
            fail(f"time stdlib missing {needle}")

    for needle in [
        "Slice6MonitorRegistration",
        "Slice6MonitorDownNotification",
        "slice6BuildMonitorDownNotification",
        "slice6IsMonitorDownOpcode",
        "observerFailureAffectsObserved",
        "Slice6ChildSpec",
        "Slice6SupervisorState",
        "Slice6RecoveryBudget",
        "recordRestart",
        "slice6StrategyIncludesChild",
        "slice6RecordPartialRecovery",
        "emitEscalation",
    ]:
        if needle not in supervision:
            fail(f"supervision stdlib missing {needle}")

    schema = json.loads(read("doc/slice-6-timer-manifest-schema.json"))
    timer_props = schema["properties"]["slice6"]["properties"]["timers"]["items"]["properties"]
    for required in [
        "max_scheduled_entries",
        "max_body_bits",
        "max_body_refs",
        "max_future_horizon_blocks",
        "max_cell_depth",
    ]:
        if required not in timer_props:
            fail(f"timer manifest schema missing {required}")


def iter_slice6_tol_sources() -> list[Path]:
    paths = [
        ROOT / "crypto/smartcont/tol-stdlib/delivery.tol",
        ROOT / "crypto/smartcont/tol-stdlib/schedule.tol",
        ROOT / "crypto/smartcont/tol-stdlib/time.tol",
        ROOT / "crypto/smartcont/tol-stdlib/supervision.tol",
    ]
    paths.extend(sorted((ROOT / "tol-tester/tests").glob("slice6-*.tol")))
    examples = ROOT / "examples/slice6"
    if examples.exists():
        paths.extend(sorted(examples.rglob("*.tol")))
    return paths


def check_no_caller_controlled_now_scheduling() -> None:
    schedule_call = re.compile(r"\b(sendAfterBlocks|sendAtMcSeqno|slice6ScheduledAction|slice6ScheduledHandle)\b")
    for path in iter_slice6_tol_sources():
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "msg.now" in line and schedule_call.search(line):
                fail(f"{rel}:{lineno}: caller-controlled msg.now used in scheduling helper call")


def check_extra_flags_bit3_still_reserved() -> None:
    message_policy = read("doc/tos-message-policy.md")
    if "bit 3" not in message_policy or "reserved" not in message_policy:
        fail("message policy no longer documents extra_flags bit 3 as reserved")
    for path in iter_slice6_tol_sources():
        text = path.read_text(encoding="utf-8")
        if re.search(r"extraFlags\s*[:=]\s*8\b", text) or re.search(r"extra_flags\s*[:=]\s*8\b", text):
            fail(f"{path.relative_to(ROOT)} sets extra_flags bit 3")


def main() -> None:
    check_required_surface()
    check_no_caller_controlled_now_scheduling()
    check_extra_flags_bit3_still_reserved()
    print("Validated Slice 6 release-package guardrails: delivery, schedule, time, supervision, no msg.now scheduling")


if __name__ == "__main__":
    main()
