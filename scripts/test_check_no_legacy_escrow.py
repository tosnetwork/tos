"""The removed-escrow-v1 guard fails for every kind of fingerprint it holds.

Every planted fingerprint is built from the guard's own constants, so this file
names nothing the guard looks for. The real v1 artifacts are read back from Git
history by their blob ids; a checkout without that history fails here rather
than skipping, because those are the cases that show the guard recognises the
actual bytecode.

Runs with the standard library only: python3 scripts/test_check_no_legacy_escrow.py
"""

import base64
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "check_no_legacy_escrow", ROOT / "scripts/check-no-legacy-escrow.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def historical_blob(blob: str) -> bytes:
    shown = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-p", blob], capture_output=True)
    if shown.returncode != 0:
        raise AssertionError(
            f"v1 blob {blob} is not in this checkout's history; run with full history "
            "(fetch-depth 0)"
        )
    return shown.stdout


def historical_artifact(artifact: dict) -> bytes:
    """The committed base64 file of a v1 artifact, from Git history."""
    return historical_blob(artifact["git_blob"])


def decoded(artifact: dict) -> bytes:
    return base64.b64decode(re.sub(rb"\s", b"", historical_artifact(artifact)), validate=True)


def write_boc(cells, roots, *, size: int, offset_size: int, with_index: bool = False) -> bytes:
    """Serialize cells (d1, d2, data, refs) as a standard BOC with the given widths."""
    body = b""
    offsets = []
    for d1, d2, payload, refs in cells:
        body += bytes([d1, d2]) + payload + b"".join(ref.to_bytes(size, "big") for ref in refs)
        offsets.append(len(body))
    flags = (0x80 if with_index else 0) | size
    header = check.BOC_MAGIC + bytes([flags, offset_size])
    header += len(cells).to_bytes(size, "big") + len(roots).to_bytes(size, "big")
    header += (0).to_bytes(size, "big") + len(body).to_bytes(offset_size, "big")
    header += b"".join(root.to_bytes(size, "big") for root in roots)
    if with_index:
        header += b"".join(offset.to_bytes(offset_size, "big") for offset in offsets)
    return header + body


def reserialized(boc: bytes) -> bytes:
    """The same cells with wider reference and offset fields and an index."""
    cells, roots = check.read_boc(boc)
    return write_boc(cells, roots, size=3, offset_size=4, with_index=True)


def wrapped_in_state_init(boc: bytes) -> bytes:
    """A StateInit whose code is the given BOC's root and whose data is empty."""
    cells, roots = check.read_boc(boc)
    shifted = [(d1, d2, payload, [ref + 1 for ref in refs]) for d1, d2, payload, refs in cells]
    code = roots[0] + 1
    empty = len(shifted) + 1
    # split_depth absent, special absent, code present, data present, no library.
    state_init = (2, 1, bytes([0b00110100]), [code, empty])
    return write_boc([state_init, *shifted, (0, 0, b"", [])], [0], size=2, offset_size=2)


class SyntheticTree(unittest.TestCase):
    """A tree without .git, so the guard walks the filesystem."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts/deploy.py").write_text("print('escrow v2 only')\n")

    def tearDown(self):
        self.dir.cleanup()

    def plant(self, relative: str, content: bytes) -> list[str]:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        failures = check.scan_tree(self.root)
        target.unlink()
        return failures

    def assert_refused(self, relative: str, content: bytes, reason: str):
        failures = self.plant(relative, content)
        self.assertTrue(any(reason in failure for failure in failures), failures)

    def test_clean_tree_passes(self):
        self.assertEqual(check.scan_tree(self.root), [])

    def test_a_file_named_after_v1_is_refused(self):
        for needle in check.V1_NAME_NEEDLES:
            with self.subTest(needle=needle):
                self.assert_refused(f"crypto/smartcont/tos-{needle}.fc", b";;\n", "the path names")

    def test_any_file_naming_a_v1_path_is_refused(self):
        for needle in check.V1_PATH_NEEDLES:
            for relative in ("scripts/deploy.py", "CMakeLists.txt", "doc/NOTES.md", "a/b.bin"):
                with self.subTest(needle=needle, file=relative):
                    content = f"see {needle.upper()}.fc\n".encode()
                    self.assert_refused(relative, content, "names a removed v1 path")

    def test_either_code_hash_in_any_form_is_refused(self):
        for code_hash in check.V1_CODE_HASHES:
            forms = {
                "lower": f"tvm-cell-sha256:{code_hash}\n".encode(),
                "upper": f"CODE = 0x{code_hash.upper()}\n".encode(),
            }
            for form, content in forms.items():
                with self.subTest(code_hash=code_hash, form=form):
                    self.assert_refused("scripts/vector.json", content, "v1 code hash")
            with self.subTest(code_hash=code_hash, form="raw"):
                content = b"\x00\x01" + bytes.fromhex(code_hash) + b"\xff"
                self.assert_refused("fixtures/state.bin", content, "as raw bytes")

    def test_each_artifact_fingerprint_text_is_refused(self):
        for artifact in check.V1_ARTIFACTS:
            for kind in ("file_sha256", "boc_sha256", "git_blob"):
                with self.subTest(artifact=artifact["code_hash"], kind=kind):
                    content = f"pin: {artifact[kind]}\n".encode()
                    self.assert_refused("release.json", content, "artifact fingerprint")

    def test_each_historical_artifact_is_refused_under_any_name(self):
        for artifact in check.V1_ARTIFACTS:
            committed = historical_artifact(artifact)
            boc = decoded(artifact)
            self.assertEqual(check.boc_root_hash(boc).hex(), artifact["code_hash"])
            planted = {
                "committed file": ("crypto/smartcont/innocent.boc.base64", committed),
                "decoded BOC": ("crypto/smartcont/innocent.boc", boc),
            }
            for label, (relative, content) in planted.items():
                with self.subTest(artifact=artifact["code_hash"], form=label):
                    self.assert_refused(relative, content, "is the v1 artifact")

    def test_each_historical_source_is_refused_under_any_name(self):
        for source in check.V1_SOURCES:
            with self.subTest(source=source["git_blob"]):
                content = historical_blob(source["git_blob"])
                self.assert_refused(
                    "crypto/smartcont/escrow-next.fc", content, "v1 contract source"
                )

    def test_embedded_artifacts_are_refused(self):
        for artifact in check.V1_ARTIFACTS:
            boc = decoded(artifact)
            encoded = base64.b64encode(boc).decode()
            wrapped = "\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
            planted = {
                "base64 literal": f'const CODE: &str = "{encoded}";\n',
                "wrapped base64": f"code = '''\n{wrapped}\n'''\n",
                "hex literal": f"CODE = bytes.fromhex('{boc.hex()}')\n",
                "upper hex": f"CODE = 0x{boc.hex().upper()}\n",
            }
            for label, content in planted.items():
                with self.subTest(artifact=artifact["code_hash"], form=label):
                    self.assert_refused("tests/vector.rs", content.encode(), "embeds a v1 BOC")

    def test_v1_code_in_another_serialization_is_refused_by_cell_hash(self):
        for artifact in check.V1_ARTIFACTS:
            boc = decoded(artifact)
            variants = {
                "re-serialized": reserialized(boc),
                "inside a StateInit": wrapped_in_state_init(boc),
            }
            for label, variant in variants.items():
                with self.subTest(artifact=artifact["code_hash"], form=label):
                    self.assertNotEqual(variant, boc)
                    failures = self.plant("vectors/state-init.boc", variant)
                    self.assertFalse(any("embeds a v1 BOC" in f for f in failures), failures)
                    self.assertTrue(
                        any(
                            f"cell with v1 code hash {artifact['code_hash']}" in f for f in failures
                        ),
                        failures,
                    )
                    text = f'{{"boc": "{base64.b64encode(variant).decode()}"}}\n'.encode()
                    failures = self.plant("vectors/state-init.json", text)
                    self.assertTrue(any("cell with v1 code hash" in f for f in failures), failures)

    def test_other_bocs_pass(self):
        v2 = (ROOT / check.V2_BOC).read_bytes()
        boc = base64.b64decode(re.sub(rb"\s", b"", v2))
        for relative, content in {
            "v2.boc.base64": v2,
            "v2.boc": boc,
            "v2-state-init.boc": wrapped_in_state_init(boc),
        }.items():
            with self.subTest(file=relative):
                self.assertEqual(self.plant(relative, content), [])

    def test_only_historical_evidence_and_the_guard_itself_are_exempt(self):
        needle = check.V1_PATH_NEEDLES[0].encode()
        for prefix in check.EXEMPT_PREFIXES:
            self.assertEqual(self.plant(f"{prefix}run/build.log", b"building " + needle), [])
        self.assertEqual(self.plant(check.THIS_FILE, b"NEEDLE = " + needle), [])
        self.assertTrue(self.plant("tools/node-health-monitor/notes.md", b"see " + needle))
        self.assertTrue(self.plant("scripts/check-other.py", b"NEEDLE = " + needle))


class Fingerprints(unittest.TestCase):
    def committed_v1_blobs(self, suffix: str) -> set[str]:
        """Blob ids of every v1 file with this suffix committed in this branch's history."""
        pattern = f":(glob)**/*{check.V1_PATH_NEEDLES[0]}{suffix}"
        commits = subprocess.run(
            ["git", "-C", str(ROOT), "log", "--format=%H", "HEAD", "--", pattern],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        blobs = set()
        for commit in commits:
            listing = subprocess.run(
                ["git", "-C", str(ROOT), "ls-tree", "-r", commit, "--", "crypto/smartcont"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for line in listing.splitlines():
                meta, path = line.split("\t", 1)
                if path.endswith(f"{check.V1_PATH_NEEDLES[0]}{suffix}"):
                    blobs.add(meta.split()[2])
        return blobs

    def test_every_committed_v1_artifact_is_fingerprinted(self):
        committed = self.committed_v1_blobs(".boc.base64")
        self.assertTrue(committed, "no v1 artifact found in history: is this a shallow clone?")
        fingerprinted = {artifact["git_blob"] for artifact in check.V1_ARTIFACTS}
        self.assertEqual(committed, fingerprinted)

    def test_every_committed_v1_source_is_fingerprinted(self):
        committed = self.committed_v1_blobs(".fc")
        self.assertTrue(committed, "no v1 source found in history: is this a shallow clone?")
        self.assertEqual(committed, {source["git_blob"] for source in check.V1_SOURCES})
        for source in check.V1_SOURCES:
            content = historical_blob(source["git_blob"])
            self.assertEqual(check.hashlib.sha256(content).hexdigest(), source["sha256"])

    def test_each_artifact_matches_its_recorded_hashes(self):
        for artifact in check.V1_ARTIFACTS:
            with self.subTest(artifact=artifact["code_hash"]):
                committed = historical_artifact(artifact)
                boc = decoded(artifact)
                self.assertEqual(
                    check.hashlib.sha256(committed).hexdigest(), artifact["file_sha256"]
                )
                self.assertEqual(check.hashlib.sha256(boc).hexdigest(), artifact["boc_sha256"])
                self.assertEqual(check.boc_root_hash(boc).hex(), artifact["code_hash"])

    def test_both_code_hashes_belong_to_an_artifact(self):
        self.assertEqual(
            set(check.V1_CODE_HASHES), {artifact["code_hash"] for artifact in check.V1_ARTIFACTS}
        )
        self.assertEqual(len(check.V1_CODE_HASHES), 2)


class ParserControl(unittest.TestCase):
    def test_the_parser_reproduces_the_v2_code_hash(self):
        self.assertEqual(check.parser_control(ROOT), [])

    def test_the_parser_control_fails_when_the_hash_does_not_reproduce(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            for relative in (check.V2_BOC, check.V2_RELEASE):
                (repo / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / relative, repo / relative)
            manifest = json.loads((repo / check.V2_RELEASE).read_text())
            manifest["code_hash"] = "tvm-cell-sha256:" + "00" * 32
            (repo / check.V2_RELEASE).write_text(json.dumps(manifest))
            self.assertTrue(check.parser_control(repo))


class RepositoryCheck(unittest.TestCase):
    def test_this_repository_passes(self):
        self.assertEqual(check.scan_tree(ROOT), [])

    def test_the_command_fails_on_a_planted_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            for relative in (check.V2_BOC, check.V2_RELEASE):
                (repo / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / relative, repo / relative)
            command = ["python3", str(ROOT / "scripts/check-no-legacy-escrow.py"), str(repo)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            (repo / "code.boc").write_bytes(decoded(check.V1_ARTIFACTS[1]))
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 1, refused.stdout)
            self.assertIn("code.boc", refused.stderr)


if __name__ == "__main__":
    unittest.main()
