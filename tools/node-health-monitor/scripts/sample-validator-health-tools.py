#!/usr/bin/env python3
"""One bounded read of a node's health through the six fixed tools (private MCP).

Issues a short grant on the private control socket, lists the tools (exactly
six), reads `tos_get_node_snapshot` with the process, consensus, chain and
storage components, prints the delivered components and verdict copy, then
revokes the grant. No model, no validator or edge access, no retries."""

import argparse
import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path

HELPERS = Path(__file__).with_name("sample-query-functional.py")
spec = importlib.util.spec_from_file_location("functional", HELPERS)
functional = importlib.util.module_from_spec(spec)
sys.modules["functional"] = functional
spec.loader.exec_module(functional)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--control-socket", required=True)
    parser.add_argument("--mcp-socket", required=True)
    parser.add_argument("--operator-token-file", required=True)
    parser.add_argument("--service-token-file", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--components", default="process,consensus,chain,storage")
    args = parser.parse_args()
    operator = Path(args.operator_token_file).read_text().strip()
    service = Path(args.service_token_file).read_text().strip()
    now = dt.datetime.now(dt.timezone.utc)
    start = (now - dt.timedelta(minutes=10)).isoformat(timespec="seconds").replace("+00:00", "Z")
    end = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    leases = []
    run, token = functional.issue(args.control_socket, operator, args.node, start, end, leases)
    outcome = {"run_id": run, "node": args.node}
    session = functional.McpSession(args.mcp_socket, service, run, token)
    try:
        session.initialize()
        tools = session.call("tools/list", {})
        names = sorted(t["name"] for t in tools.get("tools", []))
        outcome["tools"] = names
        # as_of must fall inside the granted [start, end) window.
        as_of = (
            (now - dt.timedelta(seconds=1))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        result = session.call(
            "tools/call",
            {
                "name": "tos_get_node_snapshot",
                "arguments": {
                    "run_id": run,
                    "node_id": args.node,
                    "as_of": as_of,
                    "max_age_seconds": 180,
                    "components": args.components.split(","),
                },
            },
        )
        envelope = json.loads(result["content"][0]["text"])
        outcome["status"] = envelope.get("status")
        outcome["error"] = envelope.get("error")
        outcome["coverage"] = envelope.get("coverage")
        outcome["missing_evidence"] = envelope.get("missing_evidence")
        outcome["evidence_ids"] = [e.get("evidence_id") for e in envelope.get("evidence", [])]
        outcome["components"] = []
        for component in (envelope.get("data") or {}).get("components", []):
            summary = {
                "kind": component.get("kind"),
                "sources": component.get("sources"),
                "quality": component.get("quality"),
            }
            # M's read-only verdict copy rides on the consensus component.
            if component.get("health") is not None:
                health = component["health"]
                summary["health"] = {
                    "evaluation_sequence": health.get("evaluation_sequence"),
                    "rules_evaluated": health.get("rules_evaluated"),
                    "active_incidents": health.get("active_incidents"),
                    "observed_at": health.get("observed_at"),
                    "evidence_id": health.get("evidence_id"),
                }
            value = component.get("value")
            if isinstance(value, dict):
                summary["keys"] = sorted(value.keys())[:16]
                for key in ("verdict", "health", "outside_view"):
                    if key in value:
                        summary[key] = value[key]
            outcome["components"].append(summary)
        outcome["budget"] = envelope.get("budget")
    finally:
        session.close()
        outcome["revoked"] = functional.revoke(args.control_socket, operator, run)
    print(json.dumps(outcome, ensure_ascii=False, indent=1))
    return (
        0 if outcome.get("tools") and len(outcome["tools"]) == 6 and outcome.get("revoked") else 1
    )


if __name__ == "__main__":
    sys.exit(main())
