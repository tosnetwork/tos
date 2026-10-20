#!/usr/bin/env python3
"""Offline codec/state/transaction replay and fail-closed architecture comparison."""

import argparse
import copy
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def difference(expected, actual, path="$"):
    if type(expected) is not type(actual):
        return path, expected, actual
    if isinstance(expected, dict):
        for key in sorted(expected.keys() | actual.keys()):
            if key not in expected or key not in actual:
                return f"{path}.{key}", expected.get(key, "<missing>"), actual.get(key, "<missing>")
            result = difference(expected[key], actual[key], f"{path}.{key}")
            if result:
                return result
    elif isinstance(expected, list):
        for index, (left, right) in enumerate(zip(expected, actual)):
            result = difference(left, right, f"{path}[{index}]")
            if result:
                return result
        if len(expected) != len(actual):
            return path + ".length", len(expected), len(actual)
    elif expected != actual:
        return path, expected, actual
    return None


def check_records(expected, actual, label):
    result = difference(expected, actual)
    if result:
        field, left, right = result
        raise ValueError(
            f"{label}: first differing item/field {field}: expected {canonical(left)}, got {canonical(right)}"
        )


def read_manifest(path):
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != 1 or not manifest.get("blocks") or not manifest.get("expected"):
        raise ValueError("empty or unsupported corpus manifest")
    files = {}
    for entry in manifest["files"]:
        relative = entry["path"]
        full = (path.parent / relative).resolve(strict=True)
        if not full.is_relative_to(path.parent.resolve()) or relative in files:
            raise ValueError(f"invalid/duplicate corpus path: {relative}")
        data = full.read_bytes()
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"corpus SHA-256/size mismatch: {relative}")
        if not (entry.get("source_block") or entry.get("source_blocks")):
            raise ValueError(f"missing chain provenance: {relative}")
        files[relative] = full
    if len(set(manifest["blocks"])) != len(manifest["blocks"]) or len(
        set(manifest["supplements"])
    ) != len(manifest["supplements"]):
        raise ValueError("duplicate corpus selection")
    if (
        not 200 <= len(manifest["blocks"]) <= 500
        or sum(e["size"] for e in manifest["files"]) + path.stat().st_size > 20_000_000
    ):
        raise ValueError("corpus count/size outside its reviewed bounds")
    if set(manifest["blocks"] + manifest["supplements"]) != files.keys():
        raise ValueError("unreferenced or missing corpus file")
    return manifest, files


def read_lines(path):
    lines = path.read_text().splitlines()
    if not lines:
        raise ValueError(f"empty architecture output: {path}")
    records = [json.loads(line) for line in lines]
    if path.read_bytes() != ("\n".join(canonical(record) for record in records) + "\n").encode():
        raise ValueError(f"noncanonical JSON lines: {path}")
    return records


def run(args, manifest, files):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rel02-") as directory:
        root = Path(directory)
        for name in ("blocks", "supplements"):
            (root / name).write_text("".join(str(files[p]) + "\n" for p in manifest[name]))
        command = [
            str(args.executable.resolve()),
            "--run",
            str(root / "blocks"),
            str(root / "supplements"),
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, text=True, timeout=args.timeout, check=False
        )
        observed = [json.loads(line) for line in result.stdout.splitlines()]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("\n".join(canonical(record) for record in observed) + "\n")
        check_records(manifest["expected"], observed, "on-chain oracle")
        if result.returncode:
            raise ValueError(
                f"native replay exited {result.returncode} despite matching emitted records"
            )
    elapsed = time.monotonic() - started
    print(
        f"PASS: {len(manifest['blocks'])} blocks, {len(observed)} records, {elapsed:.3f}s",
        file=sys.stderr,
    )
    if args.metrics:
        args.metrics.write_text(
            json.dumps(
                {
                    "architecture": platform.machine(),
                    "seconds": elapsed,
                    "blocks": len(manifest["blocks"]),
                    "records": len(observed),
                },
                indent=2,
            )
            + "\n"
        )


def controls(args, baseline):
    receipts = []
    with tempfile.TemporaryDirectory(prefix="rel02-controls-") as directory:
        temporary = Path(directory)
        copied = temporary / "corpus"
        shutil.copytree(args.manifest.resolve().parent, copied)
        control = copy.copy(args)
        control.manifest = copied / args.manifest.name
        control.output = temporary / "control.jsonl"
        control.metrics = None
        original_manifest = control.manifest.read_bytes()
        manifest = json.loads(original_manifest)
        file = copied / manifest["blocks"][0]
        original_bytes = file.read_bytes()
        altered = bytearray(original_bytes)
        altered[len(altered) // 2] ^= 1
        file.write_bytes(altered)
        try:
            read_manifest(control.manifest)
        except ValueError as error:
            if "SHA-256/size mismatch" not in str(error):
                raise
            receipts.append({"control": "corpus-byte", "exit": 1, "reason": str(error)})
        else:
            raise ValueError("corpus-byte control was accepted")
        file.write_bytes(original_bytes)
        restored, files = read_manifest(control.manifest)
        run(control, restored, files)
        if control.output.read_bytes() != baseline:
            raise ValueError("corpus-byte restoration changed outputs")
        receipts.append({"control": "corpus-byte-restored", "exit": 0})
        manifest["expected"][0]["new_state_hash"] = "0" * 64
        control.manifest.write_text(json.dumps(manifest))
        modified, files = read_manifest(control.manifest)
        try:
            run(control, modified, files)
        except ValueError as error:
            if "on-chain oracle: first differing item/field" not in str(
                error
            ) or "new_state_hash" not in str(error):
                raise
            receipts.append({"control": "expected-state", "exit": 1, "reason": str(error)})
        else:
            raise ValueError("expected-state control was accepted")
        control.manifest.write_bytes(original_manifest)
        restored, files = read_manifest(control.manifest)
        run(control, restored, files)
        if control.output.read_bytes() != baseline:
            raise ValueError("expected-state restoration changed outputs")
        receipts.append({"control": "expected-state-restored", "exit": 0})
    args.output.with_suffix(".controls.json").write_text(json.dumps(receipts, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).parent / "corpus/manifest.json"
    )
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metrics", type=Path)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--controls", action="store_true")
    parser.add_argument("--compare", nargs=2, type=Path)
    args = parser.parse_args()
    try:
        manifest, files = read_manifest(args.manifest.resolve())
        if args.compare:
            for path in args.compare:
                check_records(manifest["expected"], read_lines(path), str(path))
            if args.compare[0].read_bytes() != args.compare[1].read_bytes():
                raise ValueError("architecture files differ despite equal records")
            print(
                "PASS: both architecture outputs are byte-identical and equal the on-chain oracle"
            )
        elif args.executable and args.output:
            run(args, manifest, files)
            if args.controls:
                controls(args, args.output.read_bytes())
        else:
            parser.error("provide --executable and --output, or --compare")
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"REL-02 FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
