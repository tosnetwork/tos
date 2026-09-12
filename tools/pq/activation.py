#!/usr/bin/env python3
"""Read-only v16 readiness proposal. Never signs, submits or activates a network.

Operator evidence is an input, not proof of its truth: artifact integrity is
checked here; independent review and hardware identity remain human duties.
"""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan(document: dict, root: Path) -> dict:
    if document.get("current_version") != 15 or document.get("target_version") != 16:
        raise ValueError("this rehearsal supports only the explicit v15 -> v16 transition")
    network = document.get("network")
    caps = document.get("capabilities")
    if type(network) is not int or not -(1 << 31) <= network < 1 << 31:
        raise ValueError("invalid network ID")
    if type(caps) is not int or not 0 <= caps < 1 << 64:
        raise ValueError("invalid capability mask")
    approvals = document.get("approvals", {})
    for name in ("security_review", "nonrefundable_loss_model", "release", "validator_operations"):
        approval = approvals.get(name, {})
        if approval.get("accepted") is not True or not approval.get("owner") or not approval.get("reference"):
            raise ValueError("missing explicit owner approval: " + name)
    evidence = document.get("evidence", {})
    for name in ("rust_cpp_parity", "module_e2e", "production_load", "activation_rehearsal"):
        item = evidence.get(name, {})
        path = (root / item.get("path", "")).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file() or digest(path) != item.get("sha256"):
            raise ValueError("missing or modified evidence: " + name)
        report = json.loads(path.read_text())
        if report.get("success") is not True:
            raise ValueError("failed evidence: " + name)
        # Agreement between two builds is a property of the binaries, not of a
        # chain. Such evidence declares itself network-independent instead of
        # naming a network it never ran against; everything else must match.
        if report.get("scope") == "network-independent":
            if report.get("network") is not None:
                raise ValueError("network-independent evidence must not name a network: " + name)
        elif report.get("network") != network:
            raise ValueError("failed or foreign-network evidence: " + name)
        if report.get("source_commit") != document.get("release_commit"):
            raise ValueError("evidence does not bind the proposed release")
        if name == "production_load" and report.get("qualification") != "production-validator":
            raise ValueError("CI/microbench evidence cannot qualify a production validator")
    roster = document.get("validators", [])
    if not roster or len({v.get("id") for v in roster}) != len(roster):
        raise ValueError("empty or duplicate validator roster")
    for validator in roster:
        if (not validator.get("id") or validator.get("acknowledged") is not True
                or validator.get("supports_version", 0) < 16
                or validator.get("release_commit") != document.get("release_commit")):
            raise ValueError("every configured validator must acknowledge the same v16 release")
    release = document.get("release_commit", "")
    if len(release) != 40 or any(c not in "0123456789abcdef" for c in release):
        raise ValueError("release must be a full commit hash")
    # ConfigParam 8 payload (not a signed transaction or a deployment instruction).
    payload = bytes([0xc4]) + (16).to_bytes(4, "big") + caps.to_bytes(8, "big")
    return {"proposal_only": True, "network_activated": False, "network": network,
            "current_version": 15, "target_version": 16, "capabilities_preserved": caps,
            "config8_payload_hex": payload.hex(), "release_commit": release,
            "validators": [v["id"] for v in roster],
            "warning": "A validated proposal is not activation. Apply only through the network's approved configuration process."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("manifest", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    result = plan(json.loads(args.manifest.read_text()), args.manifest.resolve().parent)
    with args.out.open("x") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
