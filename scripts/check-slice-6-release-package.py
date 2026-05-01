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

REQUIRED_DOCS = [
    "doc/slice6-failure-trace-schema.json",
    "doc/slice-6-author-guide.md",
    "doc/slice-6-audit-checklist.md",
    "doc/slice-6-compatibility-matrix.md",
    "doc/slice-6-release-notes.md",
    "doc/slice-6-activation-plan.md",
]

REQUIRED_EXAMPLES = {
    "examples/slice6/scheduled-transfer.tol": ["slice6TimerBudget", "sendAfterBlocks"],
    "examples/slice6/monitored-contract.tol": ["slice6MonitorBudget", "slice6BuildMonitorDownNotification"],
    "examples/slice6/supervised-child.tol": ["slice6ChildSpec"],
    "examples/slice6/supervisor.tol": ["slice6RecoveryBudget", "recordChildRestart"],
    "examples/slice6/capability-example.tol": ["slice6CapabilityConstraints", "slice6CapabilityGrant"],
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    full = ROOT / path
    if not full.exists():
        fail(f"missing required Slice 6 file: {path}")
    return full.read_text(encoding="utf-8")


def check_required_surface() -> None:
    common = read("crypto/smartcont/tol-stdlib/common.tol")
    delivery = read("crypto/smartcont/tol-stdlib/delivery.tol")
    schedule = read("crypto/smartcont/tol-stdlib/schedule.tol")
    time = read("crypto/smartcont/tol-stdlib/time.tol")
    supervision = read("crypto/smartcont/tol-stdlib/supervision.tol")
    capability = read("crypto/smartcont/tol-stdlib/capability.tol")
    safe_payments = read("crypto/smartcont/tol-stdlib/safe-payments.tol")
    dogfood = read("crypto/smartcont/slice6-dogfood.tol")

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
        "SLICE6_SCHEDULE_SAFE_SEND_MODE_MASK",
        "slice6RequireSafeSendMode",
        "SLICE6_SCHEDULE_CANCEL_NOT_AUTHORIZED",
        "SLICE6_SCHEDULE_CANCEL_ALREADY_CANCELED",
        "forceExpireIfEscrowDepleted",
    ]:
        if needle not in schedule:
            fail(f"schedule stdlib missing {needle}")
    for needle in [
        "(sendMode & SLICE6_SCHEDULE_SAFE_SEND_MODE_MASK) != sendMode",
        "slice6RequireSafeSendMode(sendMode)",
    ]:
        if needle not in schedule:
            fail(f"schedule stdlib missing safe send-mode validation: {needle}")

    for needle in [
        "Slice6TimerBudget",
        "Slice6WallClockBudget",
        "sendAfterBlocks",
        "sendAtMcSeqno",
        "cancelScheduled",
        "trustedCurrentMcSeqno",
        "slice6WallClockBudget",
        "requireDurationWithinBudget",
    ]:
        if needle not in time:
            fail(f"time stdlib missing {needle}")

    for needle in ["previousMasterchainBlocks", "currentMcSeqno", "PREVMCBLOCKS"]:
        if needle not in common:
            fail(f"common stdlib missing trusted masterchain seqno surface {needle}")

    for needle in [
        "Slice6MonitorRegistration",
        "Slice6MonitorDownNotification",
        "slice6BuildMonitorDownNotification",
        "slice6IsMonitorDownOpcode",
        "observerFailureAffectsObserved",
        "Slice6ChildSpec",
        "Slice6SupervisorState",
        "Slice6RestartOutcome",
        "Slice6RecoveryBudget",
        "recordRestart",
        "recordChildRestart",
        "recordChildRestartOutcome",
        "slice6StrategyIncludesChild",
        "slice6RecordPartialRecovery",
        "emitEscalation",
    ]:
        if needle not in supervision:
            fail(f"supervision stdlib missing {needle}")

    for needle in [
        "Slice6CapabilityGrantV1",
        "Slice6CapabilityConstraintsV1",
        "Slice6CapabilityUseContext",
        "constraintsHash",
        "requireCapability",
        "requireCapabilityWithSignature",
        "consumeNonce",
        "maxConsumedNonces",
        "maxTrackedUses",
        "requireUseConsumable",
        "consumeUse",
        "SLICE6_CAPABILITY_MAX_ARGUMENT_BOUNDS",
        "argumentBoundCount",
        "revokeHandle",
        "setMinEpoch",
        "SLICE6_CAPABILITY_THROW_INVALID_EPOCH",
        "SLICE6_CAPABILITY_THROW_SIGNATURE_REQUIRED",
        "SLICE6_CAPABILITY_THROW_REPLAY_DOMAIN_MISMATCH",
        "SLICE6_CAPABILITY_THROW_DELEGATION_DEPTH_EXCEEDED",
        "SLICE6_CAPABILITY_THROW_ARGUMENT_BOUND",
        "replayDomain",
        "delegationDepth",
        "argumentBounds",
        "setArgumentBound",
        "signatureBoundValid",
        "slice6RejectPublicCapabilitySecret",
    ]:
        if needle not in capability:
            fail(f"capability stdlib missing {needle}")

    for needle in [
        "slice6SendCoins",
        "slice6SendCoinsWithBody",
        "slice6RefundExcess",
        "slice6RequireMinimumBalanceAfterPayout",
        "SEND_MODE_BOUNCE_ON_ACTION_FAIL",
    ]:
        if needle not in safe_payments:
            fail(f"safe-payments stdlib missing {needle}")

    for needle in [
        "Slice6DogfoodFailureRecord",
        "sendAfterBlocks",
        "slice6BuildMonitorDownNotification",
        "recordChildRestart",
        "addRecord",
        "SLICE6_ATTEMPT_SUPERVISOR_RECOVERY",
    ]:
        if needle not in dogfood:
            fail(f"Slice 6 dogfood service missing {needle}")

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

    capability_schema = json.loads(read("doc/slice-6-capability-manifest-schema.json"))
    capability_props = capability_schema["properties"]["capabilities"]["items"]["properties"]
    for required in ["binding", "single_use", "revocation", "constraints_display"]:
        if required not in capability_props:
            fail(f"capability manifest schema missing {required}")
    display_enum = set(capability_props["constraints_display"]["items"]["enum"])
    for required in ["replay_domain", "delegated_depth", "argument_bounds"]:
        if required not in display_enum:
            fail(f"capability manifest schema display vocabulary missing {required}")


def check_release_artifacts() -> None:
    for path in REQUIRED_DOCS:
        read(path)

    trace_schema = json.loads(read("doc/slice6-failure-trace-schema.json"))
    trace_required = set(trace_schema["required"])
    for required in ["version", "trace_id", "created_at_mc_seqno", "source", "resource_bounds"]:
        if required not in trace_required:
            fail(f"failure trace schema missing required field {required}")

    for path, needles in REQUIRED_EXAMPLES.items():
        text = read(path)
        for needle in needles:
            if needle not in text:
                fail(f"{path} missing expected example surface {needle}")
        if "createEmptyMap" in text:
            fail(f"{path} declares raw map storage instead of stdlib-bounded state")


def iter_slice6_tol_sources() -> list[Path]:
    paths = [
        ROOT / "crypto/smartcont/tol-stdlib/delivery.tol",
        ROOT / "crypto/smartcont/tol-stdlib/schedule.tol",
        ROOT / "crypto/smartcont/tol-stdlib/time.tol",
        ROOT / "crypto/smartcont/tol-stdlib/supervision.tol",
        ROOT / "crypto/smartcont/tol-stdlib/capability.tol",
        ROOT / "crypto/smartcont/tol-stdlib/safe-payments.tol",
        ROOT / "crypto/smartcont/slice6-dogfood.tol",
    ]
    paths.extend(sorted((ROOT / "tol-tester/tests").glob("slice6-*.tol")))
    examples = ROOT / "examples/slice6"
    if examples.exists():
        paths.extend(sorted(examples.rglob("*.tol")))
    external_trials = ROOT / "examples/external-trials"
    if external_trials.exists():
        paths.extend(sorted(external_trials.rglob("*.tol")))
    return paths


def strip_line_comment(line: str) -> str:
    return line.split("//", 1)[0]


def strip_tol_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(strip_line_comment(line) for line in text.splitlines())


def check_no_caller_controlled_now_scheduling() -> None:
    schedule_call = re.compile(r"\b(sendAfterBlocks|sendAtMcSeqno|slice6ScheduledAction|slice6ScheduledHandle)\b")
    mc_sensitive = re.compile(
        r"\b(sendAfterBlocks|sendAtMcSeqno|slice6ScheduledAction|slice6ScheduledHandle|"
        r"slice6CapabilityUseContext|slice6CapabilityConstraints|slice6CapabilityGrant|"
        r"requireHorizon|revokeHandle)\b|McSeqno|currentMcSeqno|trustedCurrentMcSeqno"
    )
    now_assignment = re.compile(r"\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\b[^=]*=\s*blockchain\.now\s*\(")
    for path in iter_slice6_tol_sources():
        rel = path.relative_to(ROOT)
        now_tainted: set[str] = set()
        active_sensitive_call: str | None = None
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = strip_line_comment(line)
            if re.match(r"\s*fun\b", code):
                now_tainted.clear()
                active_sensitive_call = None
            if "msg.now" in code and schedule_call.search(code):
                fail(f"{rel}:{lineno}: caller-controlled msg.now used in scheduling helper call")
            m = now_assignment.search(code)
            if m:
                now_tainted.add(m.group(1))
            if mc_sensitive.search(code):
                active_sensitive_call = code
            if active_sensitive_call and "blockchain.now" in code:
                fail(f"{rel}:{lineno}: blockchain.now() must not feed Slice 6 masterchain-seqno APIs; use blockchain.currentMcSeqno() or a protocol-provided seqno")
            if "blockchain.now" in code and mc_sensitive.search(code):
                fail(f"{rel}:{lineno}: blockchain.now() used directly in a masterchain-seqno context")
            if mc_sensitive.search(code):
                for name in now_tainted:
                    if re.search(rf"\b{re.escape(name)}\b", code):
                        fail(f"{rel}:{lineno}: value `{name}` derived from blockchain.now() flows into a masterchain-seqno context")
            if active_sensitive_call and ";" in code:
                active_sensitive_call = None


def check_safe_payment_defaults() -> None:
    risky_mode = re.compile(r"\bSEND_MODE_REGULAR\b")
    for path in iter_slice6_tol_sources():
        rel = path.relative_to(ROOT)
        if not (str(rel).startswith("examples/slice6/") or str(rel).startswith("examples/external-trials/")):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = strip_line_comment(line)
            if risky_mode.search(code):
                fail(f"{rel}:{lineno}: production Slice 6 examples must not use SEND_MODE_REGULAR for value dispatch; use @stdlib/safe-payments helpers or SEND_MODE_BOUNCE_ON_ACTION_FAIL")


def check_slice6_stdlib_no_regular_send_mode() -> None:
    risky_mode = re.compile(r"\bSEND_MODE_REGULAR\b")
    stdlib_paths = [
        ROOT / "crypto/smartcont/tol-stdlib/delivery.tol",
        ROOT / "crypto/smartcont/tol-stdlib/schedule.tol",
        ROOT / "crypto/smartcont/tol-stdlib/time.tol",
        ROOT / "crypto/smartcont/tol-stdlib/supervision.tol",
        ROOT / "crypto/smartcont/tol-stdlib/capability.tol",
        ROOT / "crypto/smartcont/tol-stdlib/safe-payments.tol",
    ]
    for path in stdlib_paths:
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = strip_line_comment(line)
            if risky_mode.search(code):
                fail(f"{rel}:{lineno}: Slice 6 stdlib must not default to SEND_MODE_REGULAR for value dispatch")


def check_calculate_size_has_quiet_ok_guard() -> None:
    guarded_paths = [
        ROOT / "crypto/smartcont/tol-stdlib/delivery.tol",
        ROOT / "crypto/smartcont/tol-stdlib/time.tol",
        ROOT / "crypto/smartcont/tol-stdlib/supervision.tol",
    ]
    for path in guarded_paths:
        rel = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines):
            if ".calculateSize(" not in strip_line_comment(line):
                continue
            window = "\n".join(strip_line_comment(item) for item in lines[idx : min(idx + 8, len(lines))])
            if "ok" not in window or ("!ok" not in window and "== false" not in window):
                fail(f"{rel}:{idx + 1}: calculateSize result must check the quiet ok flag before trusting bits/refs")


def check_runtime_activation_is_version_gated() -> None:
    transaction = read("crypto/block/transaction.cpp")
    required = [
        "kDeploySuccessActivationVersion = 14",
        "compute_phase_can_activate_account",
        "global_version >= kDeploySuccessActivationVersion ? success : accepted",
    ]
    for needle in required:
        if needle not in transaction:
            fail(f"transaction.cpp missing version-gated deploy activation surface: {needle}")
    use_msg_gate = "compute_phase_can_activate_account(cp.success, cp.accepted, cfg.global_version) && use_msg_state"
    state_root_gate = "compute_phase_can_activate_account(cp.success, cp.accepted, cfg.global_version) && cp.new_data.not_null()"
    if transaction.count(use_msg_gate) < 2:
        fail("transaction.cpp must version-gate both precompiled and TVM StateInit activation paths")
    if transaction.count(state_root_gate) < 2:
        fail("transaction.cpp must version-gate both EVM and Uno custom-executor activation paths")
    forbidden = [
        "if (cp.success && use_msg_state)",
        "if (cp.accepted && use_msg_state)",
        "if (cp.accepted & use_msg_state)",
        "if (cp.success && cp.new_data.not_null())",
        "if (cp.accepted && cp.new_data.not_null())",
    ]
    for needle in forbidden:
        if needle in transaction:
            fail(f"transaction.cpp contains an unversioned deploy activation gate: {needle}")


def check_extra_flags_bit3_still_reserved() -> None:
    message_policy = read("doc/tos-message-policy.md")
    if "bit 3" not in message_policy or "reserved" not in message_policy:
        fail("message policy no longer documents extra_flags bit 3 as reserved")
    for path in iter_slice6_tol_sources():
        text = path.read_text(encoding="utf-8")
        if re.search(r"extraFlags\s*[:=]\s*8\b", text) or re.search(r"extra_flags\s*[:=]\s*8\b", text):
            fail(f"{path.relative_to(ROOT)} sets extra_flags bit 3")


def check_no_reusable_public_bearer_capability() -> None:
    forbidden = re.compile(r"\b(bearerToken|bearerSecret|ReusableBearer|PublicBearer)\b")
    for path in iter_slice6_tol_sources():
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if forbidden.search(line):
                fail(f"{rel}:{lineno}: reusable public bearer capability token is forbidden")


def check_external_trial_unit_boundaries() -> None:
    vesting = ROOT / "examples" / "external-trials" / "vesting-vault" / "src" / "vesting-vault.tol"
    if vesting.exists():
        source = strip_tol_comments(vesting.read_text(encoding="utf-8"))
        for needle in ["Slice6WallClockBudget", "slice6WallClockBudget", "VAULT_MAX_VEST_HORIZON_SECONDS"]:
            if needle not in source:
                fail(f"{vesting.relative_to(ROOT)} must use explicit wall-clock duration budget {needle}")
        for needle in ["@implicit_protocol_default", "@disclaim_query_id"]:
            if needle not in source:
                fail(f"{vesting.relative_to(ROOT)} must document sparse-state/default query-id behaviour with {needle}")
        for forbidden in ["VAULT_MAX_TIMER", "timerBudget", "maxFutureHorizonBlocks"]:
            if forbidden in source:
                fail(f"{vesting.relative_to(ROOT)} mixes wall-clock vesting with scheduler timer budget field {forbidden}")


def main() -> None:
    check_required_surface()
    check_release_artifacts()
    check_no_caller_controlled_now_scheduling()
    check_safe_payment_defaults()
    check_slice6_stdlib_no_regular_send_mode()
    check_calculate_size_has_quiet_ok_guard()
    check_runtime_activation_is_version_gated()
    check_extra_flags_bit3_still_reserved()
    check_no_reusable_public_bearer_capability()
    check_external_trial_unit_boundaries()
    print("Validated Slice 6 release-package guardrails: delivery, schedule, time, supervision, capability, safe payments, no caller-controlled time scheduling")


if __name__ == "__main__":
    main()
