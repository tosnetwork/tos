#!/usr/bin/env python3
"""Fetch the part of a phase-1 ceremony this circuit needs.

Two published BLS12-381 powers-of-tau ceremonies are large enough, and the
choice between them is a custody decision rather than a technical one.  The
default is Zcash's Sapling ceremony; Filecoin's is kept as an alternative.
Either way the accumulator stores each of its five sections in ascending power
order, so what we need is a prefix of *every section* rather than a prefix of
the file -- five byte ranges, about eighteen megabytes.

This script does one thing: it copies those ranges and records where they came
from.  It decides nothing.  The ranges, the file size to expect and the
provenance text all come out of the Rust `phase1-ranges` binary, which derives
them from each ceremony's published size, and everything that has to be true of
the bytes afterwards is checked by `verify-phase1-slice`, which parses them
into curve points and runs the pairing checks.  Fetching and judging are kept
apart on purpose: this half needs the network and no cryptography, and that
half needs cryptography and no network.

    uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1
    uv run python scripts/shielded-pool-phase1-slice.py --transcript filecoin ...

Writes `phase1-<transcript>-2m<exponent>.bin` and a `.json` record beside it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CEREMONY = REPO / "tools/shielded-pool-ceremony"

# The digest a challenge file opens with, where there is one. A transcript of
# records has none, and says so in its descriptor.
HEAD_DIGEST_BYTES = 64


class Failed(Exception):
    pass


def log(message: str) -> None:
    print(f"[phase1] {message}", flush=True)


def plan(transcript: str, exponent: int) -> dict:
    """What to fetch, from the module that derives it.

    Not recomputed here.  Two copies of this arithmetic is two chances to get
    it wrong, and the Rust one is the copy with tests behind it.
    """
    result = subprocess.run(
        ["cargo", "run", "--release", "--quiet", "--bin", "phase1-ranges",
         "--", transcript, str(exponent)],
        cwd=CEREMONY,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise Failed(f"could not read the layout:\n{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout)


def head(url: str) -> int:
    request = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(request, timeout=180) as response:
        length = response.headers.get("Content-Length")
        if length is None:
            raise Failed(
                "the server did not report a Content-Length, so the file cannot be identified")
        return int(length)


def fetch_range(url: str, offset: int, length: int) -> bytes:
    """One range, with the server's answer checked rather than assumed.

    A server that ignores the Range header answers 200 with the whole file --
    a hundred gigabytes of it -- so the status code is the thing to check, not
    the bytes that arrive.
    """
    end = offset + length - 1
    request = urllib.request.Request(url, headers={"Range": f"bytes={offset}-{end}"})
    with urllib.request.urlopen(request, timeout=3600) as response:
        if response.status != 206:
            raise Failed(
                f"asked for bytes {offset}-{end} and the server answered {response.status} "
                "rather than 206; it is sending the whole file, not the range")
        content_range = response.headers.get("Content-Range", "")
        if not content_range.startswith(f"bytes {offset}-{end}/"):
            raise Failed(f"the server returned a different range: {content_range!r}")
        data = response.read(length)
    if len(data) != length:
        raise Failed(f"asked for {length} bytes at {offset} and received {len(data)}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(REPO / "artifacts/phase1"))
    parser.add_argument("--transcript", default="zcash",
                        help="which phase-1 ceremony to inherit: zcash (default) or filecoin. "
                             "A custody decision, not a technical one -- see "
                             "doc/shielded-pool-ceremony.md")
    parser.add_argument("--exponent", type=int, default=15,
                        help="the QAP domain exponent to slice at. The circuit decides this; "
                             "pass it only for a circuit that has changed.")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"phase1-{args.transcript}-2m{args.exponent}"
    slice_path = out / f"{stem}.bin"
    record_path = out / f"{stem}.json"

    log("reading the layout from the Rust module that derives it ...")
    described = plan(args.transcript, args.exponent)
    ranges = described["ranges"]
    url = described["url"]
    expect_bytes = described["file_bytes"]
    wanted = sum(r["length"] for r in ranges)
    log(f"ceremony {described['transcript']} (2^{described['power']})")
    log(f"inheriting: {described['custody']}")
    log(f"{len(ranges)} ranges, {wanted:,} bytes in total")

    log(f"identifying {url} ...")
    try:
        size = head(url)
    except urllib.error.URLError as error:
        raise Failed(f"could not reach the transcript: {error}") from error
    if size != expect_bytes:
        raise Failed(
            f"the file is {size:,} bytes and the layout describes one of {expect_bytes:,}. "
            "Every offset below is for a different file, so nothing is fetched.")
    log(f"it is the {size:,} bytes the layout describes")

    # Where the file opens with one, the digest chaining it to the previous
    # entry. Not verified -- verifying a digest chain means replaying the whole
    # transcript -- but recorded, so a deployment can be held against the
    # published attestations.
    digest = None
    if described["head_digest"]:
        digest = fetch_range(url, 0, HEAD_DIGEST_BYTES).hex()
        log(f"head digest {digest}")
    else:
        log(f"no head digest; identified by: {described['published_checksums']}")

    pieces: list[bytes] = []
    for entry in ranges:
        log(f"{entry['name']}: {entry['points']:,} points, "
            f"{entry['length']:,} bytes at offset {entry['offset']:,}")
        data = fetch_range(url, entry["offset"], entry["length"])
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        log(f"  sha256 {entry['sha256']}")
        pieces.append(data)

    body = b"".join(pieces)
    slice_path.write_bytes(body)

    record = {
        "transcript": described["transcript"],
        "source_url": url,
        "source_bytes": expect_bytes,
        "source_power": described["power"],
        "slice_power": args.exponent,
        "transcript_hash": digest,
        "published_checksums": described["published_checksums"],
        "custody": described["custody"],
        "ranges": [
            {
                "name": e["name"],
                "offset": e["offset"],
                "length": e["length"],
                "points": e["points"],
                "sha256": e["sha256"],
            }
            for e in ranges
        ],
        "slice_sha256": hashlib.sha256(body).hexdigest(),
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n")

    log(f"wrote {slice_path} ({len(body):,} bytes) and {record_path}")
    log("")
    log("Nothing above says the bytes are a powers-of-tau string. Run:")
    log(f"  cargo run --release --manifest-path {CEREMONY}/Cargo.toml \\")
    log(f"      --bin verify-phase1-slice -- {slice_path} {record_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failed as error:
        print(f"[phase1] FAILED: {error}", file=sys.stderr)
        sys.exit(1)
