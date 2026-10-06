#!/usr/bin/env python3
"""Read-only liveness/operating-budget check for persistent local PQ elections."""

import argparse
import json
import subprocess
import time
from pathlib import Path


def check(directory, now=None):
    now = time.time() if now is None else now
    errors, warnings = [], []
    try:
        status = json.loads((directory / "status.json").read_text())
        if not status.get("healthy"):
            errors.append("election driver reports a failure")
        if not 0 <= now - status["at"] <= 180:
            errors.append("election driver heartbeat is stale or in the future")
        since = status.get("activation_since")
        if since is not None:
            activation = json.loads((directory / f"activation-{since}.json").read_text())
            if activation["config34"]["utime_until"] <= now:
                errors.append(
                    "Config34 expired without a new observed activation; key-block/GC risk"
                )
        for index in (1, 2, 3, 4, 7):
            row = json.loads((directory / f"operations-{index}.json").read_text())
            if not row.get("ready"):
                errors.append(f"controller {index} is not ready")
            if now - row["checked_at"] > 1800:
                errors.append(f"controller {index} operating observation is stale")
            op = row["operating_state"]
            # The driver refreshes this observation before that candidate stakes.
            # Expiry is absolute; the recorded runway is an estimate, not a balance proof.
            if op["expires"] - now <= 30 * 86400 / 4 or row["runway_seconds"] <= 30 * 86400 / 4:
                warnings.append(f"controller {index} is at/below the 25% renewal threshold")
            if op["expires"] <= now:
                errors.append(f"controller {index} authorization has expired")
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(f"missing or invalid election evidence: {error}")
    return dict(
        healthy=not errors,
        errors=errors,
        warnings=warnings,
        note="persistent elections drive key blocks; do not leave a stopped driver unnoticed",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("/data"))
    args = parser.parse_args()
    result = check(args.data / "elections")
    state = subprocess.run(["systemctl", "is-active", "--quiet", "tos-pq-elections"], check=False)
    if state.returncode:
        result["healthy"] = False
        result["errors"].append("tos-pq-elections is not active")
    print(json.dumps(result))
    return 0 if result["healthy"] and not result["warnings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
