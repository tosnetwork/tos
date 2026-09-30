#!/usr/bin/env python3
"""Run one bounded pinned-AURA process check against the local private broker.

This uses AURA's McpManager through the already compiled, source-bound host
check. It reports process-source availability, not whole-node health or model
judgment. The caller schedules invocations and retains the JSON status.
"""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


NODES = frozenset(("validator1", "validator2", "validator3", "validator4", "observer5", "observer6"))
PROCESS_LINE = re.compile(
    r'^AURA_C09_REAL_PROCESS (validator[1-4]|observer[56]) "partial" '
    r'pid=([1-9][0-9]*) parent=([0-9a-f]{64})$'
)
TEST_NAME = "pinned_aura_reads_six_real_m_process_sources_without_model"


def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            sha.update(block)
    return sha.hexdigest()


def unit_pid(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=MainPID", "--value", unit],
        capture_output=True, text=True, timeout=3, check=True,
    )
    value = result.stdout.strip()
    if not value.isdecimal() or int(value) <= 0:
        raise ValueError("unit_unavailable")
    return value


def evaluate(output):
    seen = set()
    for line in output.splitlines():
        match = PROCESS_LINE.fullmatch(line)
        if match:
            node = match.group(1)
            if node in seen:
                raise ValueError("duplicate_node")
            seen.add(node)
    if seen != NODES:
        raise ValueError("missing_node")
    if (output.count("C09_GRANT_REVOKED group=0") != 1
            or output.count("C09_GRANT_REVOKED group=1") != 1
            or output.count("AURA_C09_REAL_UNKNOWN consensus=error") != 1
            or output.count("AURA_C09_REAL_SCOPE cross_run=error") != 1
            or f"test {TEST_NAME} ... ok" not in output):
        raise ValueError("missing_control")
    return sorted(seen)


def run(args):
    test = Path(args.test_binary)
    adapter = Path(args.adapter_binary)
    manifest = Path(args.manifest)
    for path, expected in ((test, args.test_sha256), (adapter, args.adapter_sha256)):
        if digest(path) != expected:
            raise ValueError("binary_changed")
    manifest_sha = digest(manifest)
    env = {
        "NHM_C09_LIVE_M_EVIDENCE_DB": args.manager_db,
        "NHM_C09_DEPLOYMENT_MANIFEST": str(manifest),
        "NHM_C09_EXPECTED_MANIFEST_SHA256": manifest_sha,
        "NHM_C09_MANAGER_PID": unit_pid(args.manager_unit),
        "NHM_C09_BROKER_PID": unit_pid(args.broker_unit),
        "NHM_C09_BROKER_CONTROL_SOCKET": args.control_socket,
        "NHM_C09_BROKER_MCP_SOCKET": args.mcp_socket,
        "NHM_C09_BROKER_OPERATOR_TOKEN_FILE": args.operator_token_file,
        "NHM_C09_BROKER_SERVICE_TOKEN_FILE": args.service_token_file,
        "NHM_AURA_STDIO_BIN": str(adapter),
    }
    # The child needs its ordinary runtime environment, but no token value is
    # placed in argv, env, stdout, or the status row.
    import os
    child_env = os.environ.copy()
    child_env.update(env)
    result = subprocess.run(
        [str(test), "--exact", TEST_NAME, "--nocapture"],
        capture_output=True, timeout=45, env=child_env,
    )
    output = result.stdout + result.stderr
    if len(output) > 32768:
        raise ValueError("child_output_oversize")
    if result.returncode != 0:
        raise ValueError("aura_check_failed")
    return evaluate(output.decode("utf-8", errors="replace"))


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "test-binary", "test-sha256", "adapter-binary", "adapter-sha256",
        "manifest", "manager-db", "manager-unit", "broker-unit",
        "control-socket", "mcp-socket", "operator-token-file", "service-token-file",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    status = {"schema_version": 1, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source": "pinned_aura_mcp", "scope": "process_source_only"}
    try:
        status["nodes"] = run(args)
        status["result"] = "observed_partial"
        code = 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        status["result"] = "unavailable"
        status["error_kind"] = str(error) if isinstance(error, ValueError) else type(error).__name__
        code = 1
    print(json.dumps(status, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
