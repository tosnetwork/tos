"""Record the insertion-manifest hash this round produces, and nothing else.

The round amends the bytes already inserted into the frozen configuration
contract, so the insertion manifest changes and its recorded hash in the freeze
record stops matching. The record is rewritten here one entry at a time: every
other hash, the approval thresholds and the accumulated evidence survive
byte-for-byte. Rebuilding the record instead would discard the evidence it
exists to accumulate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "doc/validator-auth-p0-native-insertions.json"
RECORD = ROOT / "doc/validator-auth-p0-freeze.json"

CHANGE = (
    "Installed the registry configuration parameter before the compute checkpoint, "
    "declared as amended bytes of the existing configuration-contract insertions in "
    "original-file coordinates."
)
SCOPE = (
    "Additive only: crypto/smartcont/config-code.fc keeps every historical byte and "
    "declares no additional insertion. No wire or API artifact, activation gate, "
    "approval threshold, configuration root or later implementation boundary changes."
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default=os.environ.get("GITHUB_SHA"),
                        help="commit whose manifest the record must already bind")
    arguments = parser.parse_args()
    if not arguments.base_ref:
        raise SystemExit("no base commit to bind against")

    record = json.loads(RECORD.read_text())
    previous = record["artifact_sha256"][MANIFEST]

    # The record must already describe the manifest this round started from.
    # Without this the updater would silently absorb drift it did not cause.
    base = subprocess.check_output(["git", "show", f"{arguments.base_ref}:{MANIFEST}"], cwd=ROOT)
    if previous != hashlib.sha256(base).hexdigest():
        raise SystemExit("freeze record does not bind the manifest this round started from")

    current = hashlib.sha256((ROOT / MANIFEST).read_bytes()).hexdigest()
    if current == previous:
        raise SystemExit("this round did not change the insertion manifest")

    record["artifact_sha256"][MANIFEST] = current
    update = {"artifact": MANIFEST, "previous_sha256": previous, "sha256": current,
              "change": CHANGE, "scope": SCOPE}
    updates = record.setdefault("evidence_updates", [])
    if update not in updates:
        updates.append(update)
    RECORD.write_text(json.dumps(record, indent=2) + "\n")
    print(f"CONFIG_PERSISTENCE_FREEZE_RECORD_UPDATE {previous} {current}")


if __name__ == "__main__":
    main()
