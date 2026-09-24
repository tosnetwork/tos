#!/usr/bin/env python3
"""Exercise the real manager's PQ group decision with zero and nonzero rotation.

This is a process-level refusal test, not a full serialized BlockProof / CheckProof
test. It uses the one-validator fixture from the manager-session identity probe
and preserves both node logs. The two zerostate BOCs can differ; the control
therefore checks block production and never infers rotation from an ID delta.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import subprocess
import time
from pathlib import Path

from nacl.signing import SigningKey
from tostester.install import Install
from tostester.key import Key
from tostester.network import Network, StartOptions

from test_manager_session_identity import (
    FIXED_PQ_SEED,
    FIXED_VALIDATOR_ID,
    FIXED_VALIDATOR_SEED,
)

GROUP_CREATED = re.compile(
    r"Created validator group \(-1,8000000000000000\)\.0:(?P<session>[A-Za-z0-9+/]{43}=)"
)
ROTATION_REFUSED = "refusing to create PQ Simplex validator group"
TRUSTED_SESSION_MISMATCH = "pq finality: carried session_id does not match trusted expected session_id"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=28900)
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser.parse_args()


def successful_masterchain_stats(path: Path) -> bool:
    if not path.exists():
        return False
    for line in path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue  # A live writer may be in the middle of its final line.
        if (
            event.get("@type") == "validatorStats.stats"
            and event.get("success") is True
            and event.get("block_id", {}).get("workchain") == -1
        ):
            return True
    return False


async def wait_for_decision(
    log_path: Path, session_log_path: Path, timeout: float, *, rotated: bool
) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    session_id: str | None = None
    while time.monotonic() < deadline:
        if log_path.exists():
            log = log_path.read_text(errors="replace")
            match = GROUP_CREATED.search(log)
            if match is not None:
                session_id = base64.b64decode(match.group("session"), validate=True).hex().upper()
                if not rotated and successful_masterchain_stats(session_log_path):
                    if TRUSTED_SESSION_MISMATCH in log:
                        return {"decision": "zero_rotation_proof_mismatch", "session_id": session_id}
                    return {"decision": "masterchain_stats_success", "session_id": session_id}
            if not rotated and ROTATION_REFUSED in log:
                return {"decision": "zero_rotation_refused"}
            if rotated and ROTATION_REFUSED in log:
                # The manager must not log a refusal and still create the
                # same active group later in this update cycle.
                await asyncio.sleep(2.0)
                if GROUP_CREATED.search(log_path.read_text(errors="replace")):
                    return {"decision": "refused_then_group_created"}
                return {"decision": "rotation_refused"}
            if rotated and TRUSTED_SESSION_MISMATCH in log:
                return {"decision": "trusted_session_mismatch", "session_id": session_id or ""}
        await asyncio.sleep(0.1)
    return {"decision": "timeout", "session_id": session_id or ""}


async def observe(
    install: Install, directory: Path, base_port: int, rotation_tag: int, timeout: float
) -> dict[str, str]:
    directory.mkdir()
    validator_key = Key(SigningKey(FIXED_VALIDATOR_SEED))
    async with Network(install, directory, base_port=base_port) as network:
        network.config.global_id = -239
        dht = network.create_dht_node()
        node = network.create_full_node(validator_key=validator_key)
        node.make_initial_pq_validator(FIXED_VALIDATOR_ID, FIXED_PQ_SEED)
        node.announce_to(dht)
        for key_file in directory.glob("node*/keyring/*"):
            key_file.chmod(0o600)
        await dht.run(StartOptions(threads=1, verbosity=3))
        await node.run(
            StartOptions(threads=2, verbosity=3, args=("--unsafe-catchain-rotate", f"0:0:{rotation_tag}"))
        )
        result = await wait_for_decision(node.log_path, node.session_log_path, timeout, rotated=rotation_tag != 0)
        result["log_path"] = str(node.log_path)
        result["session_log_path"] = str(node.session_log_path)
        return result


async def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    artifact_dir = args.artifact_dir.resolve()
    if artifact_dir.exists():
        raise ValueError(f"artifact directory already exists: {artifact_dir}")
    artifact_dir.mkdir(parents=True)
    install = Install(args.build_dir.resolve(), root)
    zero = await observe(install, artifact_dir / "zero", args.base_port, 0, args.timeout)
    nonzero = await observe(install, artifact_dir / "nonzero", args.base_port + 100, 1, args.timeout)
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    summary = {"source_commit": source_commit, "zero_rotation": zero, "nonzero_rotation": nonzero}
    (artifact_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if zero["decision"] != "masterchain_stats_success":
        raise RuntimeError(f"PQ_ZERO_ROTATION_CONTROL_FAILURE: {zero}")
    if nonzero["decision"] != "rotation_refused":
        raise RuntimeError(
            "PQ_UNSAFE_ROTATION_REFUSAL_FAILURE: nonzero local rotation produced a carrier that "
            f"trusted validation refused, or never reached a decision: {nonzero}; "
            f"zero-rotation control={zero}"
        )
    print(
        "PQ_UNSAFE_ROTATION_REFUSAL_OK: zero rotation recorded successful masterchain stats; "
        "nonzero rotation refused before PQ group creation"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except (RuntimeError, TimeoutError, ValueError) as error:
        print(error)
        raise SystemExit(1) from error
