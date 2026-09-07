"""Locked-source and entropy reachability gates; not a cryptographic security proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
import unittest
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "curve25519-dalek": ("5.0.2", "10042b03cfc92e505e9d33d2827d5c0f0d36989a"),
    "merlin": ("4.1.0", "ee857c79347e0e2201e5192523faea13ac9bf451"),
}
TAGS = {
    "curve25519-dalek": ("e527e3a83b2647ac8e82fd27158a55593717e25e", PINS["curve25519-dalek"][1]),
    "bulletproofs": ("def04efbf9d435a22306eae2c1a967f15ad43239", "961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82"),
    "merlin": ("fb9aae0179e42c7e4872d26485f19c1a03710182", PINS["merlin"][1]),
}
FORBIDDEN = re.compile(r"\b(?:rand|rand_chacha|getrandom|RandomState|HashMap|HashSet|AssertUnwindSafe)\b|\bbuild_rng\s*\(|"
                       r"\b(?:verify_multiple|verify_batch|verify_multiple_with_rng|verify_batch_with_rng)\s*\(")


def run(*args):
    return subprocess.run(args, cwd=ROOT, env=dict(os.environ, CARGO_NET_OFFLINE="true"),
                          check=True, capture_output=True, text=True).stdout


def rejected(source):
    # Intentionally conservative: a suspicious token requires review even in a
    # comment/string. This lexical guard is not a Rust call-graph analyzer.
    return bool(FORBIDDEN.search(source))


def validate_vendor(directory):
    manifest = json.loads((directory / "SOURCE_MANIFEST.json").read_text())
    actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != set(manifest["sha256"]) | {"SOURCE_MANIFEST.json"}:
        raise ValueError("unexpected or missing vendored file")
    for path, digest in manifest["sha256"].items():
        file = directory / path
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError(f"vendored source drift: {path}")


class KernelGates(unittest.TestCase):
    def test_annotated_tag_objects_bind_the_commits(self):
        for name, (tag_object, commit) in TAGS.items():
            path = ROOT / "fixtures" / (name + ".tag")
            self.assertEqual(run("git", "hash-object", "-t", "tag", str(path)).strip(), tag_object)
            self.assertEqual(path.read_text().splitlines()[0], "object " + commit)

    def test_verifier_entry_closure_and_negative_controls(self):
        paths = ("src/ffi.rs", "src/relation.rs",
                 "vendor/bulletproofs/src/range_proof/deterministic.rs")
        for path in paths:
            source = (ROOT / path).read_text()
            self.assertFalse(rejected(source), path)
        for injected in ("rand::rng()", "Scalar::random(&mut rand::rng())",
                         "transcript.build_rng()", "HashMap::new()", "HashSet::new()",
                         "RandomState::new()", "getrandom::fill(out)", "AssertUnwindSafe(callback)",
                         "proof.verify_multiple()", "collector.verify_batch()"):
            self.assertTrue(rejected(injected), injected)

    def test_normal_dependency_graph_has_no_entropy_provider(self):
        graph = run("cargo", "tree", "--locked", "--offline", "-e", "normal", "--prefix", "none")
        names = {line.split()[0] for line in graph.splitlines() if line.strip()}
        self.assertTrue({"bulletproofs", "merlin", "curve25519-dalek"} <= names)
        self.assertFalse(names & {"rand", "getrandom", "rand_chacha", "orchard", "halo2_proofs"}, graph)

    def test_pins_and_registry_archives(self):
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        packages = lock["package"]
        for name, (version, revision) in PINS.items():
            entries = [p for p in packages if p["name"] == name]
            self.assertEqual(len(entries), 1, name)
            self.assertEqual(entries[0]["version"], version)
            self.assertTrue(entries[0]["source"].endswith("#" + revision), name)
            self.assertIn("rev=" + revision, entries[0]["source"])
        self.assertFalse(any(p["name"] in {"orchard", "halo2_proofs", "halo2_gadgets"} for p in packages))
        home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
        for package in packages:
            if package.get("source", "").startswith("registry+"):
                archives = list((home / "registry/cache").glob(f'*/{package["name"]}-{package["version"]}.crate'))
                self.assertTrue(archives, f'missing locked archive: {package["name"]}')
                self.assertTrue(any(hashlib.sha256(p.read_bytes()).hexdigest() == package["checksum"] for p in archives), package["name"])
        metadata = json.loads(run("cargo", "metadata", "--locked", "--offline", "--format-version=1"))
        for package in metadata["packages"]:
            if (package.get("source") or "").startswith("registry+"):
                entry = next(p for p in packages if p["name"] == package["name"] and p["version"] == package["version"])
                archives = (home / "registry/cache").glob(f'*/{entry["name"]}-{entry["version"]}.crate')
                archive = next(p for p in archives if hashlib.sha256(p.read_bytes()).hexdigest() == entry["checksum"])
                directory = Path(package["manifest_path"]).parent
                with tarfile.open(archive) as source:
                    for member in source.getmembers():
                        if not member.isfile():
                            continue
                        relative = Path(member.name).relative_to(f'{entry["name"]}-{entry["version"]}')
                        self.assertNotIn("..", relative.parts)
                        with source.extractfile(member) as stream:
                            self.assertEqual(hashlib.sha256((directory / relative).read_bytes()).digest(),
                                             hashlib.sha256(stream.read()).digest(), f'{entry["name"]}/{relative}')
            if package["name"] not in PINS:
                continue
            directory = Path(package["manifest_path"]).parent
            revision = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
            self.assertEqual(revision, PINS[package["name"]][1])
            subprocess.run(["git", "-C", str(directory), "diff", "--exit-code", "HEAD", "--"], check=True, capture_output=True)
            untracked = subprocess.check_output(["git", "-C", str(directory), "ls-files", "--others"], text=True).splitlines()
            # The package manager's empty extraction marker is not compilable source.
            self.assertFalse(set(untracked) - {".cargo-ok"}, untracked)

    def test_vendored_source_manifest_and_tamper_control(self):
        manifest = json.loads((ROOT / "vendor/bulletproofs/SOURCE_MANIFEST.json").read_text())
        self.assertEqual(manifest["revision"], "961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82")
        validate_vendor(ROOT / "vendor/bulletproofs")
        with tempfile.TemporaryDirectory(prefix="uno-vendor-control-") as scratch:
            directory = Path(scratch) / "vendor"
            shutil.copytree(ROOT / "vendor/bulletproofs", directory)
            validate_vendor(directory)
            extra = directory / "build.rs"
            extra.write_text('fn main() { panic!("unvetted build script"); }')
            with self.assertRaises(ValueError):
                validate_vendor(directory)
            extra.unlink()
            source = directory / "src/lib.rs"
            source.write_bytes(source.read_bytes() + b"\n// injected source drift\n")
            with self.assertRaises(ValueError):
                validate_vendor(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
