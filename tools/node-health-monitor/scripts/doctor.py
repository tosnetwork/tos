#!/usr/bin/env python3
"""Production doctor: one table of gates, each pass / fail / not_run.

Reads only the manager state endpoint (or a saved copy of it), the evidence
database read-only, and a gate-evidence file of receipts for gates that live
outside the running process (physical separation, performance rounds, soak,
rotation and rollback drills). It changes nothing, and it never prints
``pass`` without a concrete check: anything it cannot establish is
``not_run``. Exit status is 1 when any gate fails, 2 on a usage error.

Gate-evidence file schema (JSON)::

    {"schema_version": 1,
     "gates": {"<gate_id>": {"status": "pass" | "fail" | "not_run",
                             "evidence_path": "<file the receipt points at>",
                             "at": "<RFC 3339 UTC>",
                             "note": "<free text>"}}}

A ``pass`` receipt is honoured only when its evidence path exists (unless
``--no-check-evidence-paths``) and it is younger than ``--receipt-max-age-days``.
"""
import argparse
import datetime as dt
import json
import os
import sqlite3
import stat
import sys
import urllib.request
from pathlib import Path

PASS, FAIL, NOT_RUN = "pass", "fail", "not_run"
ACTIVE_STATES = {"open", "suspended_unknown", "recovering"}
RECEIPT_GATES = [
    ("physical_separation", "M and O run in separate failure domains (receipt)"),
    ("performance_round_a", "performance round A (receipt)"),
    ("performance_round_b", "performance round B (receipt)"),
    ("performance_round_c", "performance round C (receipt)"),
    ("performance_round_d", "performance round D (receipt)"),
    ("performance_round_e", "performance round E (receipt)"),
    ("performance_round_f", "performance round F (receipt)"),
    ("soak_72h", "72-hour soak (receipt)"),
    ("token_rotation", "token rotation drill (receipt)"),
    ("cert_rotation", "certificate rotation drill (receipt)"),
    ("rollback_drill", "rollback drill (receipt)"),
]
DAY_MS = 86_400_000


class Gate:
    def __init__(self, gate_id, status, detail):
        if status not in (PASS, FAIL, NOT_RUN):
            raise ValueError(status)
        self.id, self.status, self.detail = gate_id, status, detail

    def as_dict(self):
        return {"id": self.id, "status": self.status, "detail": self.detail}


def parse_time(value):
    """RFC 3339 with a Z or offset; naive values are refused."""
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def read_secret(path):
    meta = os.stat(path)
    if not stat.S_ISREG(meta.st_mode):
        raise SystemExit(f"{path}: token file must be a regular file")
    if meta.st_mode & 0o077:
        raise SystemExit(f"{path}: token file must not be group/world readable")
    return Path(path).read_text().strip()


def fetch_state(url, token, timeout):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(4 * 1024 * 1024)
    return json.loads(body)


def as_int(value):
    """Wire u64/i64 values arrive as decimal strings; anything else is None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def load_state(args):
    """Return (state, gate). The gate is FAIL when M could not be read."""
    try:
        if args.manager_state_file:
            state = json.loads(Path(args.manager_state_file).read_text())
            origin = args.manager_state_file
        elif args.manager_state_url:
            if not args.manager_read_token_file:
                raise SystemExit("--manager-state-url requires --manager-read-token-file")
            state = fetch_state(args.manager_state_url, read_secret(args.manager_read_token_file),
                                args.timeout)
            origin = args.manager_state_url
        else:
            return None, Gate("manager_state", NOT_RUN, "no --manager-state-url or --manager-state-file")
    except SystemExit:
        raise
    except Exception as error:  # network, permission, JSON: the gate itself fails
        return None, Gate("manager_state", FAIL, f"state unreadable: {error}")
    if not isinstance(state, dict) or state.get("schema_version") != 1 \
            or not isinstance(state.get("incidents"), list) \
            or not isinstance(state.get("evaluation_sequence"), str):
        return None, Gate("manager_state", FAIL, f"{origin}: not a schema_version 1 manager state")
    return state, Gate("manager_state", PASS,
                       f"evaluation_sequence {state['evaluation_sequence']} from {origin}")


def incident_index(state):
    index = {}
    for incident in state.get("incidents", []):
        key = incident.get("key", {})
        if not isinstance(key, dict):
            continue
        index[(key.get("node"), key.get("scope"), key.get("rule"))] = incident
    return index


def gate_rule_inputs(state):
    inventory = state.get("inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("targets"), list):
        return Gate("rule_inputs_usable", NOT_RUN, "state carries no inventory")
    index = incident_index(state)
    expected = 0
    missing, unknown = [], []
    for target in inventory["targets"]:
        node, scope = target.get("node"), target.get("scope")
        for rule in target.get("rules", []):
            expected += 1
            incident = index.get((node, scope, rule))
            label = f"{node}/{scope}/{rule}"
            if incident is None:
                missing.append(label)
            elif incident.get("input") != "good" and incident.get("input") != "bad":
                unknown.append(label)
    if expected == 0:
        return Gate("rule_inputs_usable", FAIL, "inventory binds no rules")
    if missing or unknown:
        detail = []
        if missing:
            detail.append("no evaluation: " + ", ".join(missing))
        if unknown:
            detail.append("unknown input: " + ", ".join(unknown))
        return Gate("rule_inputs_usable", FAIL, "; ".join(detail))
    return Gate("rule_inputs_usable", PASS, f"{expected} rule bindings evaluated with usable input")


def gate_quarantine(state, evidence_db):
    checks = []
    live = state.get("quarantined_sources") if state else None
    if isinstance(live, list):
        if live:
            names = ", ".join(f"{q.get('node')}/{q.get('scope')}/{q.get('source')}" for q in live)
            return Gate("no_quarantined_sources", FAIL, f"live quarantine: {names}")
        checks.append("live state clean")
    if evidence_db:
        try:
            db = sqlite3.connect(f"file:{Path(evidence_db).resolve()}?mode=ro", uri=True, timeout=0.5)
            try:
                db.execute("PRAGMA query_only=ON")
                counts = {}
                for table in ("quarantined", "witness_quarantined"):
                    try:
                        counts[table] = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    except sqlite3.OperationalError:
                        counts[table] = None
            finally:
                db.close()
        except sqlite3.Error as error:
            return Gate("no_quarantined_sources", FAIL, f"evidence db unreadable: {error}")
        bad = {k: v for k, v in counts.items() if v}
        if bad:
            return Gate("no_quarantined_sources", FAIL,
                        "durable quarantine rows: " + ", ".join(f"{k}={v}" for k, v in bad.items()))
        known = [k for k, v in counts.items() if v == 0]
        if known:
            checks.append("evidence db " + "+".join(known) + " empty")
    if not checks:
        return Gate("no_quarantined_sources", NOT_RUN, "no live quarantine list and no evidence db")
    return Gate("no_quarantined_sources", PASS, "; ".join(checks))


def gate_retention(state):
    retention = state.get("retention")
    if not isinstance(retention, dict):
        return Gate("evidence_retention", NOT_RUN, "state carries no retention status")
    if retention.get("configured") is not True:
        return Gate("evidence_retention", FAIL, "evidence retention is not configured; the store is unbounded")
    period = as_int(retention.get("period_ms"))
    age = as_int(retention.get("last_pass_age_ms"))
    if period is None or period <= 0:
        return Gate("evidence_retention", FAIL, "retention period missing")
    if age is None:
        return Gate("evidence_retention", FAIL, "no retention pass has completed")
    if age > 2 * period:
        return Gate("evidence_retention", FAIL, f"last pass {age} ms ago exceeds 2x period {period} ms")
    if retention.get("last_pass_error"):
        return Gate("evidence_retention", FAIL, f"last pass failed: {retention['last_pass_error']}")
    window = retention.get("evidence_retention_ms")
    return Gate("evidence_retention", PASS,
                f"window {window} ms, last pass {age} ms ago, deleted {retention.get('observations_deleted_total')} rows total")


def gate_notification(state, receipts, now):
    notification = state.get("notification")
    if not isinstance(notification, dict):
        return Gate("notification_receiver", NOT_RUN, "state carries no notification status")
    if notification.get("receiver_configured") is not True:
        return Gate("notification_receiver", FAIL, "no notification receiver configured")
    age = as_int(notification.get("last_delivery_age_ms"))
    if age is not None and age <= DAY_MS:
        return Gate("notification_receiver", PASS,
                    f"receiver {notification.get('receiver_alias')}; live receipt {age} ms ago")
    receipt = receipts.get("notification_delivery") if isinstance(receipts, dict) else None
    if isinstance(receipt, dict) and receipt.get("status") == PASS:
        at = parse_time(receipt.get("at"))
        if at is not None and (now - at).total_seconds() * 1000 <= DAY_MS:
            return Gate("notification_receiver", PASS,
                        f"receiver {notification.get('receiver_alias')}; delivery receipt {receipt.get('evidence_path')} at {receipt.get('at')}")
    return Gate("notification_receiver", FAIL,
                "receiver configured but no delivery receipt within 24 h (live or in the evidence file)")


def gate_ai_lane(state):
    inventory = state.get("inventory")
    bound = False
    if isinstance(inventory, dict):
        for target in inventory.get("targets", []) or []:
            if "ai_unavailable" in (target.get("rules") or []):
                bound = True
    index = incident_index(state)
    lanes = [(k, v) for k, v in index.items() if k[2] == "ai_unavailable"]
    if not bound and not lanes:
        return Gate("ai_lane", NOT_RUN, "ai_unavailable is not bound in the inventory")
    open_lanes = [k for k, v in lanes if (v.get("state") or {}).get("state") in ACTIVE_STATES]
    if open_lanes:
        return Gate("ai_lane", FAIL, "ai_unavailable active on " + ", ".join(f"{n}/{s}" for n, s, _ in open_lanes))
    if not lanes:
        return Gate("ai_lane", FAIL, "ai_unavailable bound but never evaluated")
    return Gate("ai_lane", PASS, f"{len(lanes)} ai_unavailable lane(s) not open")


def gate_receipt(gate_id, title, receipts, base_dir, now, check_paths, max_age_days):
    receipt = receipts.get(gate_id) if isinstance(receipts, dict) else None
    if receipt is None:
        return Gate(gate_id, NOT_RUN, f"{title}: no receipt")
    if not isinstance(receipt, dict) or receipt.get("status") not in (PASS, FAIL, NOT_RUN):
        return Gate(gate_id, FAIL, f"{title}: malformed receipt")
    note = receipt.get("note") or ""
    status = receipt["status"]
    if status == NOT_RUN:
        return Gate(gate_id, NOT_RUN, f"{title}: {note or 'receipt says not_run'}")
    if status == FAIL:
        return Gate(gate_id, FAIL, f"{title}: {note or 'receipt says fail'}")
    at = parse_time(receipt.get("at"))
    if at is None:
        return Gate(gate_id, FAIL, f"{title}: pass receipt without a valid RFC 3339 'at'")
    age_days = (now - at).total_seconds() / 86_400
    if age_days < 0:
        return Gate(gate_id, FAIL, f"{title}: receipt is dated in the future")
    if age_days > max_age_days:
        return Gate(gate_id, NOT_RUN, f"{title}: receipt is {age_days:.0f} days old (> {max_age_days})")
    path = receipt.get("evidence_path")
    if not isinstance(path, str) or not path:
        return Gate(gate_id, FAIL, f"{title}: pass receipt without an evidence path")
    if check_paths:
        resolved = Path(path) if os.path.isabs(path) else base_dir / path
        if not resolved.exists():
            return Gate(gate_id, FAIL, f"{title}: evidence path missing: {path}")
    return Gate(gate_id, PASS, f"{title}: {path} at {receipt.get('at')}" + (f" - {note}" if note else ""))


def load_receipts(path):
    if not path:
        return {}, None
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or value.get("schema_version") != 1 \
            or not isinstance(value.get("gates"), dict):
        raise SystemExit(f"{path}: expected {{schema_version: 1, gates: {{...}}}}")
    return value["gates"], Path(path).resolve().parent


def run(args):
    now = parse_time(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    if now is None:
        raise SystemExit("--now must be RFC 3339 with a timezone")
    receipts, base_dir = load_receipts(args.evidence_file)
    state, state_gate = load_state(args)
    gates = [state_gate]
    if state is None:
        for gate_id in ("rule_inputs_usable", "evidence_retention", "notification_receiver", "ai_lane"):
            gates.append(Gate(gate_id, NOT_RUN, "manager state unavailable"))
        gates.insert(2, gate_quarantine(None, args.evidence_db))
    else:
        gates.append(gate_rule_inputs(state))
        gates.append(gate_quarantine(state, args.evidence_db))
        gates.append(gate_retention(state))
        gates.append(gate_notification(state, receipts, now))
        gates.append(gate_ai_lane(state))
    for gate_id, title in RECEIPT_GATES:
        gates.append(gate_receipt(gate_id, title, receipts, base_dir or Path.cwd(), now,
                                  not args.no_check_evidence_paths, args.receipt_max_age_days))
    return gates


def render(gates):
    width = max(len(g.id) for g in gates)
    lines = [f"{'gate'.ljust(width)}  status   detail", f"{'-' * width}  -------  ------"]
    for gate in gates:
        lines.append(f"{gate.id.ljust(width)}  {gate.status.ljust(7)}  {gate.detail}")
    counts = {s: sum(1 for g in gates if g.status == s) for s in (PASS, FAIL, NOT_RUN)}
    lines.append("")
    lines.append(f"pass {counts[PASS]}  fail {counts[FAIL]}  not_run {counts[NOT_RUN]}  "
                 f"-> {'FAIL' if counts[FAIL] else 'no failing gate'}")
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manager-state-url")
    parser.add_argument("--manager-read-token-file")
    parser.add_argument("--manager-state-file", help="saved state JSON instead of the live endpoint")
    parser.add_argument("--evidence-db", help="manager evidence SQLite file, opened read-only")
    parser.add_argument("--evidence-file", help="gate-evidence JSON of receipts")
    parser.add_argument("--receipt-max-age-days", type=float, default=90.0)
    parser.add_argument("--no-check-evidence-paths", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--now", help="RFC 3339 clock override for deterministic runs")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        gates = run(args)
    except SystemExit as error:
        if isinstance(error.code, str):
            print(error.code, file=sys.stderr)
            return 2
        raise
    if args.json:
        print(json.dumps({"schema_version": 1, "gates": [g.as_dict() for g in gates],
                          "failing": sum(1 for g in gates if g.status == FAIL)}, indent=1))
    else:
        print(render(gates))
    return 1 if any(g.status == FAIL for g in gates) else 0


if __name__ == "__main__":
    sys.exit(main())
