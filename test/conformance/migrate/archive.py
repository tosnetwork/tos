#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Drive the offline archive replay and check exported transaction contexts against the chain.

    archive.py replay --tool <conformance-archive-replay> --out DIR --source NAME
                      --packs ROOT=SHA256LIST [--packs ...] [--cell-packs ROOT=SHA256LIST ...]
                      [--zerostate MC.boc --basestate BASE.boc] [--mc-limit N] [--max-mismatches N]
                      [--export DIR --export-from N --export-to N --export-limit N] [--timeout S]
        Check every package against its SHA-256 list (a package missing from the list, or a listed
        package that is absent or differs, stops the run), replay them, and write DIR/manifest.json:
        the inputs (paths, sizes, SHA-256), the replay summary and the wall time.
    archive.py chain <target> <export dir>
        Run ``<target> txn`` over the exported contexts and require every effect to be an accepted
        transaction with the on-chain transaction and new account hashes. The chain is the oracle.
    archive.py rel02 <tool> <corpus dir> <work dir>
        Replay the committed REL-02 corpus (hydrated mode, no starting state) and require every
        block's identity and state hashes, and the transaction count, to equal the corpus oracle.
    archive.py slice <tool> <target> <work dir> --packs ... --zerostate ... --basestate ... --mc-limit N
        Replay a bounded slice of real history from genesis, export its contexts, run ``chain``.
        Exits 77 (a visible ctest skip) when an input does not exist on this host.

The replay tool's exit codes: 0 no mismatch, 3 mismatches, 1 the replay could not run.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))

# The runner is loaded from its own directory (it is not a package).
c: Any = importlib.import_module("conformance")

Json = dict[str, Any]
SKIP = 77
CHAIN_BATCH = 400


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 22):
            digest.update(chunk)
    return digest.hexdigest()


def read_sha_list(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise SystemExit(f"{path}:{number}: not a SHA-256 list line")
        name = parts[1].strip().removeprefix("*").removeprefix("./")
        if name in entries:
            raise SystemExit(f"{path}:{number}: {name} listed twice")
        entries[name] = parts[0].lower()
    return entries


PACK_BASE = re.compile(r"(?:^|/)(?:key\.)?archive\.(\d+)(?:\.|$)")


def pack_base(name: str) -> int:
    match = PACK_BASE.search(name)
    if match is None:
        raise SystemExit(f"{name}: not an archive package name")
    return int(match.group(1))


def verified_packs(spec: str, verify: bool, below: int | None = None) -> tuple[list[Path], Json]:
    """Every .pack under ROOT (with a base below ``below``, when given), checked against the list."""
    if "=" not in spec:
        raise SystemExit(f"--packs {spec}: ROOT=SHA256LIST[=GLOB] required")
    root_text, list_text, *rest = spec.split("=", 2)
    pattern = rest[0] if rest else "*.pack"
    root, listing = Path(root_text), Path(list_text)
    listed = {
        k: v
        for k, v in read_sha_list(listing).items()
        if k.endswith(".pack") and fnmatch.fnmatch(k, pattern)
    }
    found = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*.pack")
        if fnmatch.fnmatch(p.relative_to(root).as_posix(), pattern)
    )
    if below is not None:
        listed = {k: v for k, v in listed.items() if pack_base(k) < below}
        found = [n for n in found if pack_base(n) < below]
    unlisted = sorted(set(found) - listed.keys())
    absent = sorted(listed.keys() - set(found))
    if unlisted or absent:
        raise SystemExit(
            f"{root}: {len(unlisted)} packages not listed {unlisted[:3]}, {len(absent)} listed but absent {absent[:3]}"
        )
    differing: list[str] = []
    total = 0
    paths: list[Path] = []
    for name in found:
        path = root / name
        total += path.stat().st_size
        if verify and sha256_file(path) != listed[name]:
            differing.append(name)
        paths.append(path)
    if differing:
        raise SystemExit(
            f"{root}: {len(differing)} packages differ from {listing}: {differing[:3]}"
        )
    canonical = "".join(f"{listed[n]}  {n}\n" for n in found).encode()
    return paths, {
        "root": str(root),
        "glob": pattern,
        "sha256_list": str(listing),
        "sha256_list_sha256": sha256_file(listing),
        "packages": len(found),
        "bytes": total,
        "packages_digest": hashlib.sha256(canonical).hexdigest(),
        "verified": verify,
        "packages_below_base": below,
    }


def write_list(path: Path, items: list[Path]) -> Path:
    path.write_text("".join(f"{p}\n" for p in items))
    return path


def state_input(path: str) -> Json:
    p = Path(path)
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": sha256_file(p)}


def replay(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    packs: list[Path] = []
    pack_sets: list[Json] = []
    for spec in args.packs:
        paths, info = verified_packs(spec, not args.skip_verify, args.packs_below)
        packs += paths
        pack_sets.append(info)
    cell_packs: list[Path] = []
    cell_sets: list[Json] = []
    for spec in args.cell_packs or []:
        paths, info = verified_packs(spec, not args.skip_verify)
        cell_packs += paths
        cell_sets.append(info)
    verify_seconds = time.monotonic() - started
    command = [
        args.tool,
        "--out",
        str(out),
        "--source",
        args.source,
        "--packs",
        str(write_list(out / "packs.list", packs)),
    ]
    if cell_packs:
        command += ["--cell-packs", str(write_list(out / "cell-packs.list", cell_packs))]
    if args.zerostate:
        command += ["--zerostate", args.zerostate]
    if args.basestate:
        command += ["--basestate", args.basestate]
    for flag in (
        "mc_limit",
        "max_mismatches",
        "export",
        "export_from",
        "export_to",
        "export_limit",
    ):
        value = getattr(args, flag)
        if value is not None:
            command += ["--" + flag.replace("_", "-"), str(value)]
    replay_started = time.monotonic()
    done = subprocess.run(
        command, capture_output=True, text=True, timeout=args.timeout, check=False
    )
    replay_seconds = time.monotonic() - replay_started
    (out / "replay.stderr").write_text(done.stderr[-100000:])
    if done.returncode not in (0, 3):
        raise SystemExit(f"replay failed ({done.returncode}): {done.stderr.strip()[-2000:]}")
    summary = cast(Json, json.loads((out / "summary.json").read_text()))
    manifest: Json = {
        "source": args.source,
        "tool_sha256": sha256_file(Path(args.tool)),
        "packages": pack_sets,
        "cell_packages": cell_sets,
        "zerostate": state_input(args.zerostate) if args.zerostate else None,
        "basestate": state_input(args.basestate) if args.basestate else None,
        "command": [str(x) for x in command],
        "exit": done.returncode,
        "verify_seconds": round(verify_seconds),
        "replay_seconds": round(replay_seconds),
        "summary": summary,
        "outputs": {
            name: {"bytes": (out / name).stat().st_size, "sha256": sha256_file(out / name)}
            for name in ("blocks.jsonl", "summary.json")
        },
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    print(
        json.dumps(
            {k: summary[k] for k in ("masterchain", "shardchain", "transactions", "mismatches")}
        )
    )
    return done.returncode


def chain(target: str, export_dir: Path) -> int:
    lines = c.read_jsonl(export_dir / "contexts.jsonl")
    blobs = c.load_blobs(export_dir / "contexts.blobs.json")
    if not lines:
        raise SystemExit(f"{export_dir}: no exported contexts")
    contexts: list[Json] = []
    for number, line in enumerate(lines, 1):
        ctx = cast(Json, c.resolve(line["context"], blobs))
        c.validate_context("txn", ctx, f"{export_dir}:{number}")
        contexts.append(ctx)
    differences = refused = 0
    for start in range(0, len(contexts), CHAIN_BATCH):
        batch = contexts[start : start + CHAIN_BATCH]
        effects = c.run_target(target, "txn", batch)
        for line, effect in zip(lines[start : start + CHAIN_BATCH], effects, strict=True):
            if c.is_refusal(effect):
                refused += 1
                print(f"REFUSED {line['fixture_id']}: {effect['harness_error']}")
                continue
            want = {
                "outcome": "accepted",
                "transaction_hash": line["chain"]["transaction_hash"].upper(),
                "account_hash": line["chain"]["account_hash"].upper(),
            }
            got = {key: effect.get(key) for key in want}
            if got != want:
                differences += 1
                if differences <= 20:
                    print(f"DIFF {line['fixture_id']}: chain {want} target {effect}")
    print(
        f"checked {len(contexts)} transactions against the chain, {differences} differences, {refused} refused"
    )
    return 1 if differences or refused else 0


def rel02(tool: str, corpus: Path, work: Path) -> int:
    manifest = json.loads((corpus / "manifest.json").read_text())
    work.mkdir(parents=True, exist_ok=True)
    blocks = write_list(work / "blocks.list", [corpus / p for p in manifest["blocks"]])
    cells = write_list(work / "cells.list", [corpus / p for p in manifest["supplements"]])
    done = subprocess.run(
        [
            tool,
            "--out",
            str(work),
            "--source",
            "rel02",
            "--blocks",
            str(blocks),
            "--cells",
            str(cells),
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if done.returncode not in (0, 3):
        raise SystemExit(f"replay failed ({done.returncode}): {done.stderr.strip()[-2000:]}")
    summary = json.loads((work / "summary.json").read_text())
    expected = manifest["expected"]
    want_blocks = {(b["workchain"], b["seqno"]): b for b in expected if b["kind"] == "block"}
    want_tx = sum(1 for r in expected if r["kind"] == "transaction")
    got_blocks = {
        (r["workchain"], r["seqno"]): r for r in c.read_jsonl(work / "blocks.jsonl") if "seqno" in r
    }
    problems: list[str] = []
    if got_blocks.keys() != want_blocks.keys():
        problems.append(f"replayed {len(got_blocks)} blocks, corpus has {len(want_blocks)}")
    for key, want in want_blocks.items():
        got = got_blocks.get(key)
        if got is None:
            continue
        for field in ("root_hash", "file_hash", "old_state_hash", "new_state_hash"):
            if got.get(field) != want[field]:
                problems.append(f"{key} {field}: corpus {want[field]}, replay {got.get(field)}")
        if got["status"] != "ok":
            problems.append(
                f"{key} status {got['status']}: {got.get('mismatches') or got.get('refusals')}"
            )
    tx = summary["transactions"]
    if not tx["onchain"] == tx["executed"] == tx["matched"] == want_tx:
        problems.append(f"transactions {tx}, corpus has {want_tx}")
    if summary["mismatches"] or done.returncode:
        problems.append(f"mismatches {summary['mismatch_details']}")
    for problem in problems[:20]:
        print(f"FAIL {problem}")
    print(
        f"rel02: {len(got_blocks)} blocks, {tx['matched']}/{want_tx} transactions matched, "
        f"{summary['mismatches']} mismatches, {len(problems)} problems"
    )
    return 1 if problems else 0


def slice_test(args: argparse.Namespace) -> int:
    inputs = [args.zerostate, args.basestate] + [p for s in args.packs for p in s.split("=")[:2]]
    missing = [p for p in inputs if not os.path.exists(p)]
    if missing:
        print(f"SKIP: archive inputs not present on this host: {missing}")
        return SKIP
    work = Path(args.out)
    if args.packs_below is None:
        args.packs_below = args.mc_limit + 1
    args.export = str(work / "export")
    args.export_from = 1
    args.export_to = args.mc_limit
    code = replay(args)
    summary = json.loads((work / "summary.json").read_text())
    tx = summary["transactions"]
    problems: list[str] = []
    if code != 0 or summary["mismatches"]:
        problems.append(f"mismatches {summary['mismatch_details']}")
    for chain_name in ("masterchain", "shardchain"):
        stats = summary[chain_name]
        if (
            stats["refused"]
            or stats["absent"]
            or stats["hydrated_mode"]
            or stats["unlinked_starts"]
        ):
            problems.append(f"{chain_name} {stats}")
    if summary["masterchain"]["ok"] != args.mc_limit:
        problems.append(f"masterchain replayed {summary['masterchain']['ok']} of {args.mc_limit}")
    if not tx["onchain"] == tx["executed"] == tx["matched"] > 0:
        problems.append(f"transactions {tx}")
    if summary["exported_contexts"] != min(tx["matched"], args.export_limit or 5000):
        problems.append(f"exported {summary['exported_contexts']} of {tx['matched']}")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        return 1
    return chain(args.target, Path(args.export))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def replay_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--source", default="archive")
        p.add_argument("--packs", action="append", required=True)
        p.add_argument("--cell-packs", action="append")
        p.add_argument("--zerostate")
        p.add_argument("--basestate")
        p.add_argument("--mc-limit", type=int)
        p.add_argument("--max-mismatches", type=int)
        p.add_argument("--export-limit", type=int)
        p.add_argument("--skip-verify", action="store_true")
        p.add_argument(
            "--packs-below", type=int, help="only packages whose base seqno is below this"
        )
        p.add_argument("--timeout", type=int, default=6 * 3600)

    p = sub.add_parser("replay")
    p.add_argument("--tool", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--export")
    p.add_argument("--export-from", type=int)
    p.add_argument("--export-to", type=int)
    replay_options(p)
    p = sub.add_parser("chain")
    p.add_argument("target")
    p.add_argument("export_dir")
    p = sub.add_parser("rel02")
    p.add_argument("tool")
    p.add_argument("corpus")
    p.add_argument("work")
    p = sub.add_parser("slice")
    p.add_argument("tool")
    p.add_argument("target")
    p.add_argument("out")
    replay_options(p)
    args = parser.parse_args(argv)
    if args.command == "replay":
        return replay(args)
    if args.command == "chain":
        return chain(args.target, Path(args.export_dir))
    if args.command == "rel02":
        return rel02(args.tool, Path(args.corpus), Path(args.work))
    if args.mc_limit is None or not args.zerostate or not args.basestate:
        raise SystemExit("slice: --mc-limit, --zerostate and --basestate are required")
    return slice_test(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
