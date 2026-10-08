#!/usr/bin/env python3
"""Copy public capture material for mobile re-verification at controlled fixture time."""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

from pytosiq_core.boc.deserialize import Boc


def export(capture: Path, sdk: Path, output: Path):
    if output.exists():
        raise ValueError("fresh fixture output required")
    anchor = json.loads((capture / "anchor.json").read_text())
    fixture = json.loads(sdk.read_text())
    point = None
    reads = {}
    for role in ("wallet", "module", "vault"):
        request = (capture / f"{role}-proof-request.json").read_bytes()
        requested = json.loads(request)
        result = json.loads((capture / f"{role}-proof-result.json").read_text())
        if (
            result.get("status") != "verified"
            or requested.get("mode") != "live"
            or result.get("mode") != "live"
            or result.get("interface") != "tos-proof-verify/1"
            or result.get("anchor") != anchor
            or result.get("request_sha256") != hashlib.sha256(request).hexdigest()
        ):
            raise ValueError("verified capture/request identity mismatch")
        identity = {
            key: result["target"][key]
            for key in ("workchain", "shard", "seqno", "root_hash", "file_hash")
        }
        if requested.get("target") != identity:
            raise ValueError("explicit captured target required")
        if point is not None and identity != point:
            raise ValueError("capture checkpoint mismatch")
        point = identity
        account = result.get("account", {})

        def cell(field):
            roots = Boc(bytes.fromhex(field)).deserialize()
            if len(roots) != 1:
                raise ValueError("SDK fixture root count")
            return roots[0]

        expected_address = "0:" + cell(fixture["output"][role + "_init"]).hash.hex()
        if (
            account.get("exists") is not True
            or account.get("active") is not True
            or account.get("address") != requested.get("account")
            or account.get("address") != expected_address
            or account.get("code_hash") != cell(fixture["input"][role + "_code"]).hash.hex()
            or account.get("data_hash") != cell(fixture["output"][role + "_data"]).hash.hex()
        ):
            raise ValueError("active account capture required")
        material = capture / f"{role}-material"
        if not material.is_dir() or not (material / "account.tl").is_file():
            raise ValueError("raw account proof material required")
        for file in material.iterdir():
            if (
                file.is_symlink()
                or not file.is_file()
                or re.fullmatch(
                    r"(?:masterchain-info|config|account|exec-config|libraries|chain-\d{4}|descent-\d{4})\.tl",
                    file.name,
                )
                is None
            ):
                raise ValueError("unexpected raw proof material entry")
        reads[role] = result
    output.mkdir(parents=True)
    shutil.copyfile(capture / "anchor.json", output / "anchor.json")
    shutil.copyfile(sdk, output / "public-genesis-accounts.json")
    files = {}
    for role in reads:
        directory = output / role
        directory.mkdir()
        shutil.copyfile(capture / f"{role}-proof-request.json", directory / "request.json")
        shutil.copytree(capture / f"{role}-material", directory / "material")
    for file in sorted(output.rglob("*")):
        if file.is_file():
            raw = file.read_bytes()
            files[str(file.relative_to(output))] = {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "scope": "PUBLIC TEST: raw genesis tuple proofs for native mobile re-verification; not fresh live operation or custody acceptance",
                "controlled_now": max(read["live"]["now"] for read in reads.values()),
                "target": point,
                "files": files,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--sdk-fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    export(args.capture, args.sdk_fixture, args.out)
