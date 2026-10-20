#!/usr/bin/env python3
"""Fails if any part of the removed stablecoin escrow reappears in the tree.

The stablecoin escrow (v1, then v2) and the third-party stablecoin reference
contracts were removed outright: source, frozen BOCs, release manifests,
build/embed/test scripts, CMake wiring, sandbox suites, deploy tooling and the
rehearsal and evidence paths that deployed or read them. Nothing in the
remaining tree refers to them, so nothing would notice their return. This
check does, by fingerprint:

1. Code hashes. Every code hash v1 or v2 ever had, as hex text in any case or as
   raw 32 bytes, anywhere in any file.
2. Bytecode artifacts. Every v1 or v2 BOC that was ever committed, recognised by
   content: the SHA-256 of the file as committed, of the decoded BOC, and its
   Git blob id. Beyond that, every BOC found in the tree (a raw .boc file, or
   a base64 or hex BOC embedded in any text file) is parsed and the hash of
   every cell in it is compared with those code hashes, so escrow code re-serialized
   with other BOC flags, or wrapped in a StateInit, is caught as well.
3. Source and build paths. Any file whose path, or any file whose content,
   names the v1 or v2 source, artifact, protocol id, build target, sandbox
   suite, deploy opt-in, deploy policy, the stablecoin reference contracts, or
   the rehearsal and evidence scripts that deployed or read them; and any file
   whose content is a v1 or v2 contract source ever committed.

Exempt: this file, which holds the fingerprints, and historical evidence
directories and inventories, which record what was built at the time.

A parser that silently fails would make the cell-hash check pass on anything,
so every run first parses the frozen native registry BOC and requires its root
hash to equal the code hash in the registry's release manifest.
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


# Every v2 release's code hash, artifact and source, by content, so a renamed re-add of the
# v2 escrow is caught the same way as v1.
V2_CODE_HASHES = (
    "5a2ee6f907a03738d2eef3586ece125ebd6e10b8dbd91408e0fa4a3fd2bf51ba",
    "889f7254f37c21735a4da33f902f70b08d01b9393e6b5bc4cf78d85406afd9ce",
    "8a430b5d2b3e0c719aa156b1c60d6a13a9405009b09bc771b14b8167d5e5509b",
    "8bb0b7c809b9abfc8c3446a6a283f8cf4278c31dadc7f3bbd377d984e7d27544",
    "b4a6bb10b9771b7a6fecec890c25c5f18e049db0e22997d37ca7c0a434cec4fe",
    "caaa56fc1e10d967d754e79de52a2a2d601a58f73e1b84fe0bc2976aa605bff3",
    "d6d53a11bcda151b2e7d6b4b2f275eeadea8eb9b66496c24b0b7c54453d6d209",
    "e3b74c1284b9cd4b278c2f395a274b9194e4c986b058cf426265cb8c438ea4d6",
)

V2_ARTIFACTS = (
    {
        "code_hash": "e3b74c1284b9cd4b278c2f395a274b9194e4c986b058cf426265cb8c438ea4d6",
        "git_blob": "00a55af187fd9d50828aab5675b27c30567a33c3",
        "file_sha256": "7e7a2348a8d54df19cff8edffc58b487f110b6a8626fdc7c4033ffaee94fdbaa",
        "boc_sha256": "85c00f00498b4666e6163312c09de6518799aaa719e1c45d5eed7894fc8949b2",
    },
    {
        "code_hash": "b4a6bb10b9771b7a6fecec890c25c5f18e049db0e22997d37ca7c0a434cec4fe",
        "git_blob": "120d40495bea35b7cd6d06ef4ed3838173ee74cf",
        "file_sha256": "f58a647502e9a87e3f4271dd754d068f412f44465b796b8186a6c36b453e2805",
        "boc_sha256": "0e04680d011887f6ab4dfd059bd96b2ba647463170473356fccd6b4caab30e5e",
    },
    {
        "code_hash": "8a430b5d2b3e0c719aa156b1c60d6a13a9405009b09bc771b14b8167d5e5509b",
        "git_blob": "6b2cc81e3210a20c48943a8a8711089c39ebd690",
        "file_sha256": "c901091553d2da595554b4d4e3803ea08f7fdd150f37f3fd55c041cbb1d94946",
        "boc_sha256": "10c8adfcbfb4ebe390cfb3da07b7348d630a89726a66d436f5d177a0ae8ab5af",
    },
    {
        "code_hash": "8bb0b7c809b9abfc8c3446a6a283f8cf4278c31dadc7f3bbd377d984e7d27544",
        "git_blob": "8c7865c872a82d242e64fe42cb9a4e4f665ea3fb",
        "file_sha256": "3ab16d0f9bd8118d7f6ff5c079dee2c32aef9edf11c8a3ab8cb644a28b708610",
        "boc_sha256": "cb6ca9b958230c55222d521e29c7222cb24121fdc48e9add1edc696f2860b2f0",
    },
    {
        "code_hash": "caaa56fc1e10d967d754e79de52a2a2d601a58f73e1b84fe0bc2976aa605bff3",
        "git_blob": "a2798d9edcf0c359b75b843b3741c35296cf2418",
        "file_sha256": "55fbee88e4aab7e71b98f594d55a753dd5644d6cfff1f27eb04b215359dffc96",
        "boc_sha256": "db48f74be8a3309040502eb3a857da7f5074e07af2a7e7c6afa719882422c4c8",
    },
    {
        "code_hash": "d6d53a11bcda151b2e7d6b4b2f275eeadea8eb9b66496c24b0b7c54453d6d209",
        "git_blob": "a78d4fe03ddbbda69cf53156d95694c6cfa13d39",
        "file_sha256": "65472e49c35de9a7391d3661f1e31fd3a2510dfdd716d55eac3daa1cff15cfbc",
        "boc_sha256": "eb78f401e41ea292fe51466e2ef49466a8e62d8bd170b13f616f0efba130b113",
    },
    {
        "code_hash": "889f7254f37c21735a4da33f902f70b08d01b9393e6b5bc4cf78d85406afd9ce",
        "git_blob": "c2ac67305e2768aaa0eac3f72b78ff1cf5deeb04",
        "file_sha256": "222d46b0a18e6c65534a5b41046af66e1c7ee0b0552b4a4be4136fa0f4ba00bb",
        "boc_sha256": "63f4fa1cedebcd20c99d340ebe451703001d612109dbaa5050e57f84d695aac7",
    },
    {
        "code_hash": "5a2ee6f907a03738d2eef3586ece125ebd6e10b8dbd91408e0fa4a3fd2bf51ba",
        "git_blob": "c3bfab2df612d04560462b1c1677b3eaae2dd3e8",
        "file_sha256": "c3921c8576f2b5a9a6630027ec574488db0ffe00782f17d99a811c352429cbd6",
        "boc_sha256": "324f7d5fca5edd0a00728daad9e59bf15e158545cc4a39dae17aab2f0f12e9a7",
    },
)

V2_SOURCES = (
    {
        "git_blob": "3cb069eb265b95bf4f3eabbba4f252190e677be5",
        "sha256": "8a9a8cb87d102e7702f08a7d1f5e37daa90e071bcfac0f453352fd72805a929c",
    },
    {
        "git_blob": "5a51b39bdb2cd8889214f05ffea293fb395f890a",
        "sha256": "c12ec9e9181a924567e9847dcc747c5fd96e163d9937be0ef872f2f5e58ec5e9",
    },
    {
        "git_blob": "93e3dd6871da6a7dd0ecc0490b557d9a12b346be",
        "sha256": "76dd4017f1719224d4dd13b7056de137c080ddd016cfee6d7378fe7bdc0e7c89",
    },
    {
        "git_blob": "d61cb6211b6666e06db5994024258044186e4fe7",
        "sha256": "16bc3e24876169f578f9f1bb8c738ab94ccb0fba3b3e2e1279a026079aec53eb",
    },
    {
        "git_blob": "d98bcfa42316401c5edb3e10e901ca67f18600da",
        "sha256": "162b372a1779684b122a3998c9fa66f934f04e9e5d59fb2a27c5ae0957313990",
    },
    {
        "git_blob": "df662bb38ec76757bf106522a4e30e9c4df68af5",
        "sha256": "5d0493b467192899f2b2c87c11a282d4f8dac15733cfe1216e78e6cb01c5b05f",
    },
    {
        "git_blob": "e1addff6b9cdfb4049d656a3fa0899b38c866c5b",
        "sha256": "f5ff1c11a3adf0fb98027ed53aa84a02f7563c100d10d14a78cecf0cefd61f7a",
    },
    {
        "git_blob": "ebb5dea512c5b4cabf3c7827789b9d2b3bb4d179",
        "sha256": "7fe12c0b9317af33aa35222d7d714a68f2623f7934591c11ce6f6f8e6dae7aaf",
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
    # The v2 escrow, its deploy policy and the stablecoin reference contracts,
    # removed after v1.
    "stablecoin-escrow-v2",
    "stablecoin_escrow_v2",
    "stablecoin-escrow",
    "stablecoin_escrow",
    "escrow_deploy_policy",
    "usdt-jetton-master",
    "test-usdt-wallet",
    "tos-service-test-usdt",
)

# File names alone are matched more broadly: no file may be named after v1.
V1_NAME_NEEDLES = V1_PATH_NEEDLES + ("escrow-v1", "escrow_v1")

THIS_FILE = "scripts/check-no-legacy-escrow.py"
EXEMPT_FILES = {
    THIS_FILE,
    # A build-input inventory of a past run, kept as evidence of what was built.
    "scripts/x02_four_node_inputs.json",
}
EXEMPT_PREFIXES = (
    # Raw logs and indexes of past builds and runs, kept as evidence of what ran
    # at the time.
    "tools/node-health-monitor/evidence/",
    "doc/evidence/",
)

# The BOC parser proves itself on a frozen artifact that is still in the tree.
CONTROL_BOC = "crypto/smartcont/tos-service-native-registry-v1.boc.base64"
CONTROL_RELEASE = "crypto/smartcont/tos-service-native-registry-v1.release.json"

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
    for code_hash in V1_CODE_HASHES + V2_CODE_HASHES:
        needles.append((code_hash.encode(), f"contains a removed escrow code hash ({code_hash})"))
    for artifact in V1_ARTIFACTS + V2_ARTIFACTS:
        for kind in ("file_sha256", "boc_sha256", "git_blob"):
            needles.append(
                (
                    artifact[kind].encode(),
                    f"contains a removed escrow artifact fingerprint ({artifact[kind]})",
                )
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
    for code_hash in V1_CODE_HASHES + V2_CODE_HASHES:
        if bytes.fromhex(code_hash) in content:
            failures.append(f"{path}: contains a removed escrow code hash as raw bytes ({code_hash})")

    file_sha256 = hashlib.sha256(content).hexdigest()
    blob = git_blob_id(content)
    for artifact in V1_ARTIFACTS + V2_ARTIFACTS:
        if (
            file_sha256 in (artifact["file_sha256"], artifact["boc_sha256"])
            or blob == artifact["git_blob"]
        ):
            failures.append(
                f"{path}: is the removed escrow artifact with code hash {artifact['code_hash']}"
            )

    for source in V1_SOURCES + V2_SOURCES:
        if file_sha256 == source["sha256"] or blob == source["git_blob"]:
            failures.append(f"{path}: is a removed escrow contract source (blob {source['git_blob']})")

    bocs = embedded_bocs(content)
    if content[:4] == BOC_MAGIC:
        bocs.append(content)
    boc_digests = {artifact["boc_sha256"] for artifact in V1_ARTIFACTS + V2_ARTIFACTS}
    code_hashes = {bytes.fromhex(value) for value in V1_CODE_HASHES + V2_CODE_HASHES}
    for boc in bocs:
        if hashlib.sha256(boc).hexdigest() in boc_digests:
            failures.append(f"{path}: embeds a removed escrow BOC artifact")
        try:
            hashes = boc_cell_hashes(boc)
        except BocError:
            continue
        for value in code_hashes.intersection(hashes):
            failures.append(f"{path}: contains a cell with removed escrow code hash {value.hex()}")
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
    manifest = json.loads((root / CONTROL_RELEASE).read_text())
    expected = manifest["code_hash"].split(":", 1)[1]
    encoded = (root / CONTROL_BOC).read_bytes()
    try:
        actual = boc_root_hash(base64.b64decode(WHITESPACE.sub(b"", encoded), validate=True)).hex()
    except (BocError, binascii.Error, ValueError) as error:
        return [f"{CONTROL_BOC}: the BOC parser cannot read the frozen control artifact ({error})"]
    if actual != expected:
        return [f"{CONTROL_BOC}: the BOC parser computes {actual}, the manifest says {expected}"]
    return []


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    failures = parser_control(root) + scan_tree(root)
    for failure in failures:
        print(f"removed stablecoin escrow check failed: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("removed stablecoin escrow: no code hash, artifact or path of it is in the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
