#!/usr/bin/env python3
"""Run the X02 Config34 controls through the frozen launcher.

Loads the committed four-node binding (scripts/x02_four_node_inputs.json), verifies it
against the live host with the binding contract, and runs the coordinator's own
config34_proof_check with its default launcher: the pinned interpreter in the frozen
U24 rootfs under bwrap, calling the anchored verifier indexed in the frozen closure.

Controls, on retained real lite-server answers (test/pq-native/data/proof-verify-real):
  genuine: anchored at the network's zerostate -> X02_CONFIG34_SAME_BLOCK_PROOF_OK;
  foreign-anchor: the same bundle under another network's zerostate -> refused.

usage: x02_frozen_config34_controls.py --output NEW_DIR
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REAL = REPO / "test/pq-native/data/proof-verify-real"
GENESIS = REPO / "test/pq-native/data/c04-pq-genesis.boc"
sys.path.insert(0, str(REPO / "scripts"))


def load(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(REPO / "scripts" / f"{name}.py")
    exec(compile(Path(module.__file__).read_bytes(), module.__file__, "exec"), module.__dict__)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=False, exist_ok=False)

    closure = load("x02_four_node_binding")
    four_node = load("x02_four_node")
    proof = load("x02_config34_proof")
    binding = json.loads((REPO / "scripts/x02_four_node_inputs.json").read_bytes())
    closure.verify_binding(binding, host=True)
    source_sha = subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
    ).strip()
    verifier = Path(binding["build_root"]) / four_node.ANCHORED_VERIFIER

    # The retained answers, laid out as Stage A retains them.
    target = json.loads((REAL / "historical-request.json").read_text())["target"]
    target = {
        **target,
        "root_hash": target["root_hash"].lower(),
        "file_hash": target["file_hash"].lower(),
    }
    request = output / "param-request.json"
    request.write_text(json.dumps({"mode": "historical", "target": target, "config_params": [34]}))
    # The account material is not part of a Config34 bundle; prove the parameter from it alone.
    material = output / "param-material"
    material.mkdir()
    for name in ("chain-0000.tl", "config.tl"):
        shutil.copyfile(REAL / "historical" / name, material / name)
    fetched = subprocess.run(
        [
            str(verifier),
            "verify",
            "--anchor",
            str(REAL / "anchor.json"),
            "--request",
            str(request),
            "--material",
            str(material),
        ],
        capture_output=True,
        check=True,
    )
    param = base64.b64decode(json.loads(fetched.stdout)["config_params"][0]["boc"])
    sys.path.insert(0, str(REPO / "test/tostester/src"))
    from pytosiq_core.boc.cell import Cell

    decoded = proof.decode_validator_set(Cell.one_from_boc(param))
    election_id = decoded["utime_since"]
    rows = [
        {f: row[f] for f in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")}
        for row in decoded["validators"]
    ]
    artifacts = output / "artifacts"
    paths = proof.bundle_paths(election_id)
    (artifacts / paths["material"]).mkdir(parents=True)
    bundle = {"block_id": target, "material": {}}
    for name in ("chain-0000.tl", "config.tl"):
        raw = (REAL / "historical" / name).read_bytes()
        (artifacts / paths["material"] / name).write_bytes(raw)
        bundle["material"][name] = {
            "path": paths["material"] + name,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    (artifacts / paths["param"]).write_bytes(param)
    bundle["param"] = {"path": paths["param"], "sha256": hashlib.sha256(param).hexdigest()}
    genesis = subprocess.run(
        [str(verifier), "anchor", "--zerostate", str(GENESIS)], capture_output=True, check=True
    )
    anchors = {
        "genuine": json.loads((REAL / "anchor.json").read_text()),
        "foreign-anchor": json.loads(genesis.stdout),
    }
    for anchor in anchors.values():
        anchor["root_hash"], anchor["file_hash"] = (
            anchor["root_hash"].lower(),
            anchor["file_hash"].lower(),
        )

    results = {}
    for name, anchor in anchors.items():
        leaf = output / name
        leaf.mkdir()
        check = four_node.config34_proof_check(binding, {"source_sha": source_sha}, leaf, anchor)
        try:
            verdict = check({"election_id": election_id, "config34_proof": bundle}, output, rows)
            results[name] = {
                "accepted": True,
                "verdict": verdict["verdict"],
                "chain_links": verdict["chain_links"],
            }
        except ValueError as error:
            results[name] = {"accepted": False, "refusal": str(error)[:300]}
        terminal = json.loads((leaf / f"config34-proof-{election_id}.terminal.json").read_text())
        results[name]["terminal"] = {
            key: terminal[key]
            for key in ("natural_exit", "timed_out", "signalled", "sandbox_setup_failed")
        }
    ok = (
        results["genuine"].get("verdict") == proof.VERDICT
        and results["genuine"]["terminal"]["natural_exit"] == 0
        and not results["foreign-anchor"]["accepted"]
        and "does not start at the authenticated block" in results["foreign-anchor"]["refusal"]
        and results["foreign-anchor"]["terminal"]["natural_exit"] == 1
    )
    record = {
        "source_sha": source_sha,
        "binding_sha256": hashlib.sha256(
            (REPO / "scripts/x02_four_node_inputs.json").read_bytes()
        ).hexdigest(),
        "launcher": "x02_four_node.verifier_sandbox_argv",
        "election_id": election_id,
        "results": results,
        "status": "pass" if ok else "fail",
    }
    print(json.dumps(record, indent=1, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
