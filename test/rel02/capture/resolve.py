"""Find original archive cells for every pruned cell the replay reads.

The diagnostic replay (epoch-replay.cpp plus diagnostic.patch) names each pruned cell it reads and
continues with the next block. Each named hash is looked up in the cell index; the preferred source is
a part already selected, then a block with a two-validator id, then the nearest block. The selected
parts are exactly what assemble.py packs, so the final unmodified replay sees the same cells.

A run of the diagnostic replay counts only when it exited 0 and accounted for every selected block:
each block is announced once, in order, and either reports a failure or emits its block record. A
child that crashes, is killed, times out or stops early is refused, so "no failing blocks" can only
come from a run that replayed the whole selection.
"""

import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

DEFAULT_TIMEOUT = 600


def block_key(path):
    """(workchain, seqno) of a block file named WORKCHAIN-SEQNO.boc."""
    wc, seq = Path(path).stem.rsplit("-", 1)
    return int(wc), int(seq)


def refuse(message, result=None) -> NoReturn:
    if result is not None and result.stderr:
        message += "\nstderr tail:\n" + result.stderr[-2000:]
    raise SystemExit(message)


def run_replay(command, blocks_list, supplements_list, blocks, timeout):
    """Run the diagnostic replay once and return (misses, failing blocks, records).

    blocks are the paths listed in blocks_list, in order. The run is refused unless the child
    exited 0 and its output covers exactly those blocks.
    """
    if not blocks:
        refuse("diagnostic replay: empty block selection")
    argv = list(command) + ["--run", str(blocks_list), str(supplements_list)]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        refuse(f"diagnostic replay timed out after {timeout}s: {argv}")
    except OSError as error:
        refuse(f"diagnostic replay could not start: {error}")
    if r.returncode:
        refuse(f"diagnostic replay exited {r.returncode}", r)

    announced, misses, failed = [], [], []
    cur = None
    for line in r.stderr.splitlines():
        m = re.match(r"replay (\S+)$", line)
        if m:
            cur = m.group(1)
            announced.append(cur)
        m = re.match(r"pruned cell ([0-9A-F]{64}) while reading (.*)", line)
        if m:
            if cur is None:
                refuse(f"diagnostic replay reported a cell before any block: {line}", r)
            misses.append((m.group(1), m.group(2), cur))
        m = re.match(r"DIAGFAIL (\S+) (.*)", line)
        if m:
            if m.group(1) != cur or (failed and failed[-1] == cur):
                refuse(f"diagnostic failure outside its block: {line}", r)
            failed.append(cur)
            if "prunned branch" not in m.group(2):
                refuse(f"replay failure that is not a missing cell: {line}", r)
    expected = [str(b) for b in blocks]
    if announced != expected:
        done = 0
        while done < min(len(announced), len(expected)) and announced[done] == expected[done]:
            done += 1
        refuse(
            f"diagnostic replay announced {len(announced)} of {len(expected)} selected blocks"
            f" (first {done} in order)",
            r,
        )

    records, recorded = [], []
    for n, line in enumerate(r.stdout.splitlines(), 1):
        try:
            rec = json.loads(line)
        except ValueError:
            refuse(f"diagnostic replay stdout line {n} is not a record: {line[:200]!r}", r)
        if not isinstance(rec, dict) or rec.get("kind") not in ("block", "transaction"):
            refuse(f"diagnostic replay stdout line {n} is not a record: {line[:200]!r}", r)
        records.append(rec)
        if rec["kind"] == "block":
            recorded.append((rec.get("workchain"), rec.get("seqno")))
    selection = [block_key(b) for b in expected]
    if len(set(recorded)) != len(recorded):
        refuse("diagnostic replay emitted a block record twice", r)
    if not set(recorded) <= set(selection):
        refuse(
            f"diagnostic replay emitted unselected blocks {sorted(set(recorded) - set(selection))}",
            r,
        )
    # A block that failed may have emitted its block record before the failing read.
    unrecorded = [b for b in expected if block_key(b) not in set(recorded) and b not in failed]
    if unrecorded:
        refuse(
            f"diagnostic replay emitted no record and no failure for {len(unrecorded)} blocks,"
            f" first {unrecorded[0]}",
            r,
        )
    return misses, len(failed), records


def walk(c, seen, out):
    if id(c) in seen:
        return
    seen.add(id(c))
    if not c.is_exotic:
        out.add(c.get_hash(0)[:16])
    for r in c.refs:
        walk(r, seen, out)


def load_index(lib, work, zs):
    idx = {}
    zero = set()
    for r in lib.Cell.from_boc(zs.read_bytes()):
        walk(r, set(), zero)
    for h in zero:
        idx[h] = [("zs", 0, 0)]
    for wc in (-1, 0):
        for p in sorted((work / f"idx{wc}").glob("*.bin")):
            b = p.read_bytes()
            o = 0
            while o < len(b):
                seq, part, n = struct.unpack_from("<IBI", b, o)
                o += 9
                for i in range(n):
                    h = b[o + 32 * i : o + 32 * i + 16]
                    v = idx.setdefault(h, [])
                    if len(v) < 64:
                        v.append((wc, seq, part))
                o += 32 * n
    return idx


def main():
    # The other capture programs, written beside this file from capture-commands.json.
    import lib  # pyright: ignore[reportMissingImports]
    import pack  # pyright: ignore[reportMissingImports]

    W = lib.WORK
    ZS = Path(os.environ["GENESIS_ZEROSTATE"])
    REPLAY = os.environ["REPLAY_DIAG"].split()
    timeout = int(os.environ.get("REPLAY_DIAG_TIMEOUT", DEFAULT_TIMEOUT))
    blocks = json.loads(Path(sys.argv[1]).read_text())
    verified = {tuple(x) for x in json.loads(Path(sys.argv[2]).read_text())}
    state = Path(sys.argv[3])
    sources = {}
    idx = load_index(lib, W, ZS)
    print("index", len(idx), flush=True)
    bdir = W / "resolve"
    bdir.mkdir(exist_ok=True)

    def block_path(wc, seq):
        p = bdir / f"{wc}-{seq}.boc"
        p.write_bytes(lib.get("block", wc, seq)[0])
        return str(p)

    def part_path(key):
        if key == "zs":
            return str(ZS)
        wc, seq = map(int, key.split(":"))
        parts = sorted(set(sources[key]["parts"]))
        root = lib.Cell.one_from_boc(lib.get("block", wc, seq)[0])
        cells = [root.refs[2]] + ([root.refs[3]] if 2 in parts else [])
        p = bdir / f"part-{wc}-{seq}-{''.join(map(str, parts))}.boc"
        p.write_bytes(pack.write_multi(cells))
        return str(p)

    paths = [block_path(*map(int, b.split(":"))) for b in blocks]
    (W / "resolve.blocks").write_text("".join(p + "\n" for p in paths))
    records = []
    for it in range(1000):
        (W / "resolve.sup").write_text("".join(part_path(s) + "\n" for s in sorted(sources)))
        misses, fails, records = run_replay(
            REPLAY, W / "resolve.blocks", W / "resolve.sup", paths, timeout
        )
        print(
            f"iteration {it}: sources {len(sources)} failing blocks {fails} missing cells {len(misses)}",
            flush=True,
        )
        if not fails:
            break
        added = 0
        for h, what, target in misses:
            found = idx.get(bytes.fromhex(h)[:16])
            if not found:
                raise SystemExit(f"no original preimage of {h} ({what}, {target})")
            twc, tseq = block_key(target)

            def score(o):
                key = "zs" if o[0] == "zs" else f"{o[0]}:{o[1]}"
                have = key in sources and (o[2] != 2 or 2 in sources[key]["parts"])
                if o[0] == "zs":
                    return (0 if have else 1, 2, 1, 0)
                return (
                    0 if have else 1,
                    0 if (o[0], o[1]) in verified else 1,
                    0 if o[0] == twc else 1,
                    abs(o[1] - tseq),
                )

            best = min(found, key=score)
            key = "zs" if best[0] == "zs" else f"{best[0]}:{best[1]}"
            if key not in sources:
                sources[key] = dict(
                    parts=[best[2]], cell=h, first_needed_by=Path(target).name, stage=what
                )
                added += 1
            elif best[2] == 2 and 2 not in sources[key]["parts"]:
                sources[key]["parts"].append(2)
                added += 1
        state.write_text(json.dumps(sources, indent=1, sort_keys=True) + "\n")
        if not added:
            raise SystemExit("no progress")
    else:
        raise SystemExit("blocks still failing after 1000 iterations")
    state.write_text(json.dumps(sources, indent=1, sort_keys=True) + "\n")
    print("resolved", len(sources), "sources;", len(records), "records")


if __name__ == "__main__":
    main()
