import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("z01_proof_controls", ROOT / "scripts/z01_proof_controls.py")
assert SPEC and SPEC.loader
controls = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controls)

# A stand-in with the production checker's argument order and check order:
# file hash, then root hash, then state proof binding, then Param30 cell hash.
# Its "root" is SHA-256 over b"root" + block bytes and a valid state proof is
# b"state:" + root; it lets the matrix logic be exercised without live proofs.
FAKE_CHECKER = r'''
import hashlib, sys
wc, shard, seqno, root, file, block, state, config, param = sys.argv[1:]
def reject(message):
    sys.stderr.write("Z01_CONFIG_PROOF_REJECT: " + message + "\n")
    sys.exit(1)
data = open(block, "rb").read()
if hashlib.sha256(data).hexdigest() != file:
    reject("block BOC file hash differs from full BlockIdExt")
actual_root = hashlib.sha256(b"root" + data).hexdigest()
if actual_root != root:
    reject("block BOC root hash differs from full BlockIdExt")
if open(state, "rb").read() != b"state:" + actual_root.encode():
    reject("state/config proof does not match the block ID")
cell = hashlib.sha256(open(param, "rb").read()).hexdigest()
if cell != MODE_EXPECTED:
    reject("ConfigParam30 cell differs from proven state")
print(f"Z01_CONFIG_PROOF_OK seqno={seqno} root={root} file={file} param30={cell}")
'''


def build(directory: Path, checker_body: str | None = None) -> tuple[Path, str, Path, str]:
    block = b"block-bytes-" * 8
    root = hashlib.sha256(b"root" + block).hexdigest()
    file = hashlib.sha256(block).hexdigest()
    param = b"genuine-param30"
    expected = hashlib.sha256(param).hexdigest()
    originals = {
        "block_boc": block,
        "state_proof": b"state:" + root.encode(),
        "config_proof": b"config-proof",
        "param30_boc": param,
        "wrong_param30_boc": b"genuine-param28",
        "other_block_state_proof": b"state:" + ("ab" * 32).encode(),
    }
    manifest = {"schema": "tos.z01.config30-quartet.v1",
                "block_id": {"workchain": -1, "shard": 1 << 63, "seqno": 12,
                             "root_hash": root, "file_hash": file},
                "expected_param30_cell_hash": expected}
    for key, raw in originals.items():
        path = directory / f"{key}.bin"
        path.write_bytes(raw)
        manifest[key] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest_path = directory / "quartet.json"
    manifest_raw = json.dumps(manifest, sort_keys=True).encode()
    manifest_path.write_bytes(manifest_raw)
    checker = directory / "checker.py"
    body = checker_body if checker_body is not None else FAKE_CHECKER
    checker.write_text(body.replace("MODE_EXPECTED", repr(expected)))
    return (checker, hashlib.sha256(checker.read_bytes()).hexdigest(),
            manifest_path, hashlib.sha256(manifest_raw).hexdigest())


class ProofControlMatrix(unittest.TestCase):
    def run_matrix(self, checker_body: str | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            checker, checker_sha, manifest, manifest_sha = build(directory, checker_body)
            return controls.run_matrix(checker, checker_sha, manifest, manifest_sha,
                                       directory / "out", [sys.executable])

    def test_ordered_checker_passes_every_control(self):
        verdict = self.run_matrix()
        self.assertTrue(verdict["passed"], verdict["failures"])
        self.assertEqual(set(verdict["controls"]), set(controls.EXPECTED))
        self.assertEqual(verdict["controls"]["positive"]["exit"], 0)

    def test_checker_printing_uppercase_digests_passes(self):
        # The native checker prints td's uppercase to_hex(); only letter case differs.
        upper = FAKE_CHECKER.replace(
            'print(f"Z01_CONFIG_PROOF_OK seqno={seqno} root={root} file={file} param30={cell}")',
            'print(f"Z01_CONFIG_PROOF_OK seqno={seqno} root={root.upper()} file={file.upper()} '
            'param30={cell.upper()}")')
        self.assertNotEqual(upper, FAKE_CHECKER)
        verdict = self.run_matrix(upper)
        self.assertTrue(verdict["passed"], verdict["failures"])

    def test_positive_output_binds_real_native_bytes(self):
        # Byte-exact stdout of the native checker in the four-node live attempt
        # at masterchain 11; the same bytes were retained on all four nodes.
        root = "0eb765e2da7e18706a7312e26256096f657a16440b60c0c3ea4eefcff2a6fa1c"
        file = "48eab1201f0eca6e170f65b985ec7d2ab611098da5b625521c53559203816e44"
        param30 = "a922fc0cb6bacfee2d49645da25394f069447d8c250e4a0fb5ed75ba23cdd9e5"
        real = (b"Z01_CONFIG_PROOF_OK seqno=11 "
                b"root=0EB765E2DA7E18706A7312E26256096F657A16440B60C0C3EA4EEFCFF2A6FA1C "
                b"file=48EAB1201F0ECA6E170F65B985EC7D2AB611098DA5B625521C53559203816E44 "
                b"param30=A922FC0CB6BACFEE2D49645DA25394F069447D8C250E4A0FB5ED75BA23CDD9E5\n")
        self.assertEqual(hashlib.sha256(real).hexdigest(),
                         "507109437d363cff7690794d06eb21e8bc62e29acd858bbd1c7c2da822fff0b5")
        self.assertTrue(controls.positive_output_matches(real, 11, root, file, param30))
        self.assertFalse(controls.positive_output_matches(real, 12, root, file, param30))
        self.assertFalse(controls.positive_output_matches(real, 11, "1" + root[1:], file, param30))
        self.assertFalse(controls.positive_output_matches(real, 11, root, file[:-1] + "0", param30))
        self.assertFalse(controls.positive_output_matches(real, 11, root, file, "b" + param30[1:]))
        self.assertFalse(controls.positive_output_matches(real, 11, file, root, param30))
        self.assertFalse(controls.positive_output_matches(real.rstrip(b"\n"), 11, root, file, param30))
        self.assertFalse(controls.positive_output_matches(real + real, 11, root, file, param30))
        self.assertFalse(controls.positive_output_matches(real.replace(b"root=0", b"root=G"), 11, root, file, param30))

    def test_checker_that_refuses_everything_fails_positive_and_later_checks(self):
        refuse = ("import sys\nsys.stderr.write('Z01_CONFIG_PROOF_REJECT: "
                  "block BOC file hash differs from full BlockIdExt\\n')\nsys.exit(1)\n")
        verdict = self.run_matrix(refuse)
        self.assertFalse(verdict["passed"])
        self.assertEqual(set(verdict["failures"]),
                         {"positive", "wrong_root_hash", "mutated_block_byte_consistent_file_hash",
                          "wrong_param30_cell", "state_proof_from_other_block"})

    def test_checker_without_param30_comparison_is_caught(self):
        weakened = FAKE_CHECKER.replace("if cell != MODE_EXPECTED:", "if False:")
        verdict = self.run_matrix(weakened)
        self.assertEqual(verdict["failures"], ["wrong_param30_cell"])

    def test_checker_without_root_comparison_is_caught(self):
        weakened = FAKE_CHECKER.replace("if actual_root != root:", "if False:")
        verdict = self.run_matrix(weakened)
        self.assertIn("wrong_root_hash", verdict["failures"])
        self.assertIn("mutated_block_byte_consistent_file_hash", verdict["failures"])

    def test_manifest_and_binary_are_bound_before_any_run(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            checker, checker_sha, manifest, manifest_sha = build(directory)
            with self.assertRaisesRegex(controls.ControlError, "proof checker differs"):
                controls.run_matrix(checker, "00" * 32, manifest, manifest_sha, directory / "a",
                                    [sys.executable])
            with self.assertRaisesRegex(controls.ControlError, "manifest differs"):
                controls.run_matrix(checker, checker_sha, manifest, "00" * 32, directory / "b",
                                    [sys.executable])
            data = json.loads(manifest.read_bytes())
            data["wrong_param30_boc"] = data["param30_boc"]
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(controls.ControlError, "byte-identical"):
                controls.run_matrix(checker, checker_sha, manifest,
                                    hashlib.sha256(manifest.read_bytes()).hexdigest(),
                                    directory / "c", [sys.executable])
            self.assertFalse((directory / "c").exists())

    def test_block_bytes_must_hash_to_full_id(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            _, _, manifest, _ = build(directory)
            data = json.loads(manifest.read_bytes())
            data["block_id"]["file_hash"] = "11" * 32
            with self.assertRaisesRegex(controls.ControlError, "not the full-ID file hash"):
                controls.load_quartet(data)

    def test_each_negative_changes_exactly_its_input(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            _, _, manifest, _ = build(directory)
            quartet = controls.load_quartet(json.loads(manifest.read_bytes()))
            inputs = controls.control_inputs(quartet)
            genuine = inputs["positive"]
            for name, row in inputs.items():
                changed = sorted(key for key in row if row[key] != genuine[key])
                expected = {"positive": [], "wrong_root_hash": ["root"],
                            "wrong_file_hash": ["file"], "mutated_block_byte": ["block_boc"],
                            "mutated_block_byte_consistent_file_hash": ["block_boc", "file"],
                            "wrong_param30_cell": ["param30_boc"],
                            "state_proof_from_other_block": ["state_proof"]}[name]
                self.assertEqual(changed, expected, name)


if __name__ == "__main__":
    unittest.main()
