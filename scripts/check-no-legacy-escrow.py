#!/usr/bin/env python3
"""Fails if any part of the removed stablecoin escrow v1 reappears in the tree.

Escrow v1 was removed outright: its source, frozen BOC, release manifest,
build/embed/test scripts, CMake wiring, sandbox suite and the rehearsal and
evidence paths that deployed or read it. Nothing in the remaining tree refers
to it, so nothing would notice its return. This check does, by fingerprint:

1. Code hashes. Both code hashes v1 ever had, as hex text in any case or as raw
   32 bytes, anywhere in any file.
2. Bytecode artifacts. Every v1 BOC that was ever committed, recognised by
   content: the SHA-256 of the file as committed, of the decoded BOC, and its
   Git blob id. Beyond that, every BOC found in the tree (a raw .boc file, or
   a base64 or hex BOC embedded in any text file) is parsed and the hash of
   every cell in it is compared with both code hashes, so v1 code re-serialized
   with other BOC flags, or wrapped in a StateInit, is caught as well.
3. Source and build paths. Any file whose path, or any file whose content,
   names the v1 source, artifact, protocol id, build target, sandbox suite,
   deploy opt-in, or the rehearsal and evidence scripts that deployed or read
   it; and any file whose content is a v1 contract source ever committed.

Exempt: this file, which holds the fingerprints, and historical evidence
directories, which record what was built at the time.

A parser that silently fails would make the cell-hash check pass on anything,
so every run first parses the frozen escrow v2 BOC and requires its root hash
to equal the code hash in the v2 release manifest.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Code hashes (TVM cell representation hashes) of every v1 release.
V1_CODE_HASHES = (
    "c16bdd617d0f60aa071bcdc985af4ffa7b53d93aba983901961418302d58b3eb",
    "c9df2f743534978ad5b521aab8c09c081ff56769769c00ee9e68eac7c681a685",
)

# Every v1 bytecode artifact ever committed, by content.
V1_ARTIFACTS = (
    {
        "code_hash": V1_CODE_HASHES[0],
        "git_blob": "b2cd1981cba5838cdafb6242c36c07bdacdda9df",
        "file_sha256": "321e7cb3ab5e1405bd91ca6b9e857a0f83fa974733b1fb5a5cfd332181aaa0b5",
        "boc_sha256": "5ceb9728ccfdb8691c2c84c01e0141fe44d314b8de913d48d3e95957c9ec2ec5",
    },
    {
        "code_hash": V1_CODE_HASHES[1],
        "git_blob": "9c18b939f874b3684b111f7b37461b946694a092",
        "file_sha256": "f25c4112585ec296679d4d66f4b1d68ec4dab76b84169e5de4e29d3dee056c66",
        "boc_sha256": "fdbb52a25b9e43f50cd27e03bbd2020245e2d8b31b76b5ff203454bfbc645048",
    },
)

# Every v1 contract source ever committed, by content, so a renamed copy is
# caught even when nothing in it names v1.
V1_SOURCES = (
    {
        "git_blob": "06506bab464e6e9b1c70ef2d071ce5229f356052",
        "sha256": "443b25a0ffb542ea4e8d543b06cc17b654e3cf29f2a9c7a4a4fb3064869eeddf",
    },
    {
        "git_blob": "2a6b0985663207371800eee698dc0736bdc6f363",
        "sha256": "50d94d1edc9125db32f85c3b848e27fd6726e0eb3e0767ada7b3d4a7d79d65a5",
    },
    {
        "git_blob": "5ec5a0a9c49c6fb01c8f659bef525f3276478784",
        "sha256": "649affe98290a607d5c6befb7457d6504ba34877b2c583f213d0782949376bf9",
    },
    {
        "git_blob": "6db07b9a54d278d52bf777bc899a6277a8391cd8",
        "sha256": "066339a38d033a93babb39e5e86c3f8bfc9658e5cb35dfd1c0897ff8a24c56bc",
    },
)

# Names of the v1 source, artifacts, manifest, protocol ids, build targets,
# deploy opt-in, and the scripts that deployed or read v1. Matched in lower
# case against both file paths and file contents.
V1_PATH_NEEDLES = (
    "stablecoin-escrow-v1",
    "stablecoin_escrow_v1",
    "stablecoin_escrow_sandbox",
    "allow-deprecated-escrow-v1",
    "allow_deprecated_escrow_v1",
    "local-paid-rehearsal",
    "local_paid_rehearsal",
    "software-work-paid-evidence",
    "software_work_paid_evidence",
)

# File names alone are matched more broadly: no file may be named after v1.
V1_NAME_NEEDLES = V1_PATH_NEEDLES + ("escrow-v1", "escrow_v1")

THIS_FILE = "scripts/check-no-legacy-escrow.py"
EXEMPT_FILES = {THIS_FILE}
EXEMPT_PREFIXES = (
    # Raw logs of past builds and runs, kept as evidence of what ran at the time.
    "tools/node-health-monitor/evidence/",
)

V2_BOC = "crypto/smartcont/tos-service-stablecoin-escrow-v2.boc.base64"
V2_RELEASE = "crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json"

BOC_MAGIC = bytes.fromhex("b5ee9c72")
BASE64_BOC = re.compile(rb"te6cc[A-Za-z0-9+/]+={0,2}")
HEX_BOC = re.compile(rb"b5ee9c72[0-9a-f]+")
WHITESPACE = re.compile(rb"\s+")
# Embedded BOCs larger than this are not code; skipping them bounds the work.
MAX_EMBEDDED_BOC = 1 << 20


class BocError(ValueError):
    """The bytes are not a standard BOC this parser understands."""


def _uint(data: bytes, offset: int, size: int) -> int:
    end = offset + size
    if size < 0 or end > len(data):
        raise BocError("truncated BOC")
    return int.from_bytes(data[offset:end], "big")


def read_boc(data: bytes) -> tuple[list[tuple[int, int, bytes, list[int]]], list[int]]:
    """The cells (d1, d2, data, reference indexes) and root indexes of a
    standard BOC. Raises BocError for anything that is not a well-formed
    standard BOC."""
    if data[:4] != BOC_MAGIC:
        raise BocError("not a standard BOC")
    flags = _uint(data, 4, 1)
    has_index = bool(flags & 0x80)
    has_crc = bool(flags & 0x40)
    size = flags & 0x07
    offset_size = _uint(data, 5, 1)
    if not 1 <= size <= 4 or not 1 <= offset_size <= 8:
        raise BocError("bad BOC header sizes")
    position = 6
    cell_count = _uint(data, position, size)
    root_count = _uint(data, position + size, size)
    position += 3 * size
    total_size = _uint(data, position, offset_size)
    position += offset_size
    roots = [_uint(data, position + i * size, size) for i in range(root_count)]
    position += root_count * size
    if any(root >= cell_count for root in roots):
        raise BocError("root index out of range")
    if has_index:
        position += cell_count * offset_size
    end = position + total_size
    if end + (4 if has_crc else 0) > len(data):
        raise BocError("truncated BOC cell data")

    cells = []
    for _ in range(cell_count):
        d1 = _uint(data, position, 1)
        d2 = _uint(data, position + 1, 1)
        position += 2
        if d1 & 0x10:
            position += (bin(d1 >> 5).count("1") + 1) * 34
        data_length = (d2 >> 1) + (d2 & 1)
        payload = data[position : position + data_length]
        if len(payload) != data_length:
            raise BocError("truncated cell data")
        position += data_length
        ref_count = d1 & 0x07
        if ref_count > 4:
            raise BocError("cell has more than four references")
        refs = [_uint(data, position + i * size, size) for i in range(ref_count)]
        position += ref_count * size
        cells.append((d1, d2, payload, refs))
    if position > end:
        raise BocError("cell data overruns its declared size")
    return cells, roots


def parse_boc(data: bytes) -> tuple[list[bytes | None], list[int]]:
    """Representation hashes of the cells of a standard BOC, and its root indexes.

    A cell whose level is not zero (a pruned branch, or anything above one) has
    no plain code hash to compare; its entry is None."""
    cells, roots = read_boc(data)
    cell_count = len(cells)
    hashes: list[bytes | None] = [None] * cell_count
    depths = [0] * cell_count
    for index in range(cell_count - 1, -1, -1):
        d1, d2, payload, refs = cells[index]
        if any(ref <= index or ref >= cell_count for ref in refs):
            raise BocError("cell reference is not to a later cell")
        if d1 >> 5 or any(hashes[ref] is None for ref in refs):
            continue
        descriptor = bytes([(d1 & 0x0F), d2])
        child_depths = b"".join(depths[ref].to_bytes(2, "big") for ref in refs)
        child_hashes = b"".join(hashes[ref] for ref in refs)
        hashes[index] = hashlib.sha256(descriptor + payload + child_depths + child_hashes).digest()
        depths[index] = 1 + max((depths[ref] for ref in refs), default=-1)
    return hashes, roots


def boc_cell_hashes(data: bytes) -> list[bytes]:
    """Representation hashes of every level-0 cell in a standard BOC."""
    hashes, _ = parse_boc(data)
    return [value for value in hashes if value is not None]


def boc_root_hash(data: bytes) -> bytes:
    hashes, roots = parse_boc(data)
    if len(roots) != 1 or hashes[roots[0]] is None:
        raise BocError("expected one level-0 root cell")
    return hashes[roots[0]]


def embedded_bocs(content: bytes) -> list[bytes]:
    """BOCs embedded as base64 or hex text, with line breaks ignored."""
    found = []
    lowered = content.lower()
    if b"te6cc" in content:
        for match in BASE64_BOC.finditer(WHITESPACE.sub(b"", content)):
            text = match.group()
            if len(text) > MAX_EMBEDDED_BOC * 2:
                continue
            text = text[: len(text) - len(text) % 4]
            try:
                found.append(base64.b64decode(text, validate=True))
            except (binascii.Error, ValueError):
                continue
    if BOC_MAGIC.hex().encode() in lowered:
        for match in HEX_BOC.finditer(WHITESPACE.sub(b"", lowered)):
            text = match.group()
            if len(text) > MAX_EMBEDDED_BOC * 2:
                continue
            try:
                found.append(bytes.fromhex(text[: len(text) - len(text) % 2].decode()))
            except ValueError:
                continue
    return found


def tracked_files(root: Path) -> list[str]:
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        return [name for name in result.stdout.decode().split("\0") if name]
    files = []
    for directory, _, names in os.walk(root):
        for name in names:
            files.append((Path(directory) / name).relative_to(root).as_posix())
    return files


def is_exempt(path: str) -> bool:
    return path in EXEMPT_FILES or path.startswith(EXEMPT_PREFIXES)


def git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def content_needles() -> list[tuple[bytes, str]]:
    needles = [
        (needle.encode(), f"names a removed v1 path ({needle})") for needle in V1_PATH_NEEDLES
    ]
    for code_hash in V1_CODE_HASHES:
        needles.append((code_hash.encode(), f"contains a v1 code hash ({code_hash})"))
    for artifact in V1_ARTIFACTS:
        for kind in ("file_sha256", "boc_sha256", "git_blob"):
            needles.append(
                (artifact[kind].encode(), f"contains a v1 artifact fingerprint ({artifact[kind]})")
            )
    return needles


def scan_file(path: str, content: bytes) -> list[str]:
    failures = []
    lowered_path = path.lower()
    for needle in V1_NAME_NEEDLES:
        if needle in lowered_path:
            failures.append(f"{path}: the path names the removed escrow v1 ({needle})")
            break

    lowered = content.lower()
    for needle, message in content_needles():
        if needle in lowered:
            failures.append(f"{path}: {message}")
    for code_hash in V1_CODE_HASHES:
        if bytes.fromhex(code_hash) in content:
            failures.append(f"{path}: contains a v1 code hash as raw bytes ({code_hash})")

    file_sha256 = hashlib.sha256(content).hexdigest()
    blob = git_blob_id(content)
    for artifact in V1_ARTIFACTS:
        if (
            file_sha256 in (artifact["file_sha256"], artifact["boc_sha256"])
            or blob == artifact["git_blob"]
        ):
            failures.append(f"{path}: is the v1 artifact with code hash {artifact['code_hash']}")

    for source in V1_SOURCES:
        if file_sha256 == source["sha256"] or blob == source["git_blob"]:
            failures.append(f"{path}: is a v1 contract source (blob {source['git_blob']})")

    bocs = embedded_bocs(content)
    if content[:4] == BOC_MAGIC:
        bocs.append(content)
    boc_digests = {artifact["boc_sha256"] for artifact in V1_ARTIFACTS}
    code_hashes = {bytes.fromhex(value) for value in V1_CODE_HASHES}
    for boc in bocs:
        if hashlib.sha256(boc).hexdigest() in boc_digests:
            failures.append(f"{path}: embeds a v1 BOC artifact")
        try:
            hashes = boc_cell_hashes(boc)
        except BocError:
            continue
        for value in code_hashes.intersection(hashes):
            failures.append(f"{path}: contains a cell with v1 code hash {value.hex()}")
    return failures


def scan_tree(root: Path) -> list[str]:
    failures = []
    for path in tracked_files(root):
        if is_exempt(path):
            continue
        full = root / path
        if full.is_symlink() or not full.is_file():
            # Only the name of a symlink is checked; its target is a file of its own.
            failures.extend(scan_file(path, b""))
            continue
        try:
            content = full.read_bytes()
        except OSError as error:
            failures.append(f"{path}: unreadable ({error})")
            continue
        failures.extend(scan_file(path, content))
    return failures


def parser_control(root: Path) -> list[str]:
    """The cell-hash check reproduces a known code hash, or it checks nothing."""
    manifest = json.loads((root / V2_RELEASE).read_text())
    expected = manifest["code_hash"].split(":", 1)[1]
    encoded = (root / V2_BOC).read_bytes()
    try:
        actual = boc_root_hash(base64.b64decode(WHITESPACE.sub(b"", encoded), validate=True)).hex()
    except (BocError, binascii.Error, ValueError) as error:
        return [f"{V2_BOC}: the BOC parser cannot read the frozen v2 artifact ({error})"]
    if actual != expected:
        return [f"{V2_BOC}: the BOC parser computes {actual}, the manifest says {expected}"]
    return []


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    failures = parser_control(root) + scan_tree(root)
    for failure in failures:
        print(f"removed escrow v1 check failed: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("removed escrow v1: no code hash, artifact or path of it is in the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
