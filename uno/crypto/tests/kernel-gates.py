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
MIRRORS = {name: "https://github.com/tosnetwork/" + name for name in PINS}
TAGS = {
    "curve25519-dalek": ("e527e3a83b2647ac8e82fd27158a55593717e25e", PINS["curve25519-dalek"][1]),
    "bulletproofs": ("def04efbf9d435a22306eae2c1a967f15ad43239", "961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82"),
    "merlin": ("fb9aae0179e42c7e4872d26485f19c1a03710182", PINS["merlin"][1]),
}
FORBIDDEN = re.compile(r"\b(?:rand|rand_chacha|getrandom|RandomState|HashMap|HashSet|AssertUnwindSafe)\b|\bbuild_rng\s*\(|"
                       r"\b(?:verify_multiple|verify_batch|verify_multiple_with_rng|verify_batch_with_rng)\s*\(")

# Changing this reviewed patch set requires an explicit provenance review, not
# merely recomputing the manifest's current-tree hashes during a source refresh.
LOCAL_PATCHES = {
    "locked-build-inputs": "Cargo.toml",
    "constant-time-inner-product": "src/inner_product_proof.rs",
    "test-only-residual-export": "src/lib.rs",
    "deterministic-module-and-feature-boundary": "src/range_proof/mod.rs",
    "independent-range-residuals": "src/range_proof/deterministic.rs",
}


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def upstream_before_patch(data, patch):
    # Offsets address final UTF-8 bytes. Undo from right to left, so changing a
    # suffix cannot shift any earlier offset. No fuzzy matching or file writes.
    edits = patch["edits"]
    if not edits or not patch["reason"].strip():
        raise ValueError("local patch lacks edits or rationale")
    end = 0
    for edit in edits:
        offset, before, after = edit["offset"], edit["before"].encode(), edit["after"].encode()
        if type(offset) is not int or offset < end or before == after:
            raise ValueError("invalid or overlapping local patch edit")
        if offset > len(data) or data[offset:offset + len(after)] != after:
            raise ValueError("declared local patch is absent or changed")
        end = offset + len(after)
    for edit in reversed(edits):
        offset, before, after = edit["offset"], edit["before"].encode(), edit["after"].encode()
        data = data[:offset] + before + data[offset + len(after):]
    return data


def run(*args):
    return subprocess.run(args, cwd=ROOT, env=dict(os.environ, CARGO_NET_OFFLINE="true"),
                          check=True, capture_output=True, text=True).stdout


def rejected(source):
    # Intentionally conservative: a suspicious token requires review even in a
    # comment/string. This lexical guard is not a Rust call-graph analyzer.
    return bool(FORBIDDEN.search(source))


def normal_feature_rows():
    graph = run("cargo", "tree", "--locked", "--offline", "-e", "normal", "--prefix", "none",
                "--format", "{p}|{f}", "--no-dedupe")
    return sorted(set(line.replace(str(ROOT), "<KERNEL>") for line in graph.splitlines() if line))


def validate_vendor(directory):
    manifest = json.loads((directory / "SOURCE_MANIFEST.json").read_text())
    patches = manifest.get("local_patches", [])
    if (len(patches) != len(LOCAL_PATCHES) or
            {p["id"]: p["path"] for p in patches} != LOCAL_PATCHES):
        raise ValueError("reviewed local patch set changed")
    by_path = {p["path"]: p for p in patches}
    upstream = manifest["upstream_git_blobs"]
    if not set(upstream) <= set(manifest["sha256"]) or not set(by_path) <= set(manifest["sha256"]):
        raise ValueError("upstream or patch file missing from source set")
    actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != set(manifest["sha256"]) | {"SOURCE_MANIFEST.json"}:
        raise ValueError("unexpected or missing vendored file")
    for path, digest in manifest["sha256"].items():
        file = directory / path
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError(f"vendored source drift: {path}")
        data = file.read_bytes()
        if path in by_path:
            patch = by_path[path]
            if patch["upstream_git_blob"] != upstream.get(path):
                raise ValueError("local patch has a different upstream base")
            data = upstream_before_patch(data, patch)
        if path in upstream:
            if git_blob(data) != upstream[path]:
                raise ValueError(f"undeclared upstream delta: {path}")
        elif path not in by_path or data:
            raise ValueError(f"undeclared added source: {path}")


def validate_checkout_status(directory):
    status = subprocess.check_output(["git", "-C", str(directory), "status", "--porcelain=v1",
                                      "--untracked-files=all", "--ignored"], text=True).splitlines()
    # Only the package manager's extraction marker is permitted outside Git.
    if any(line not in {"?? .cargo-ok", "!! .cargo-ok"} for line in status):
        raise ValueError(f"git dependency checkout drift: {status}")


class KernelGates(unittest.TestCase):
    # Set/feature equality is an inventory check, not evidence of dependency auditing.
    def test_normal_feature_graph_matches_inventory_snapshot(self):
        expected = json.loads((ROOT / "fixtures/verifier-feature-graph.json").read_text())
        self.assertEqual(normal_feature_rows(), expected["normal_package_features"])

    def test_mirror_dependency_sources(self):
        # Acquisition identity is separate from the immutable upstream object.
        # Cover the wallet and vendored dev graph as well as the verifier graph.
        declarations = (
            (ROOT / "Cargo.toml", "dependencies", ("curve25519-dalek", "merlin")),
            (ROOT.parent / "prover/Cargo.toml", "dependencies", ("curve25519-dalek",)),
            (ROOT / "vendor/bulletproofs/Cargo.toml", "dependencies", ("curve25519-dalek", "merlin")),
            (ROOT / "vendor/bulletproofs/Cargo.toml", "dev-dependencies", ("curve25519-dalek",)),
        )
        for path, section, names in declarations:
            manifest = tomllib.loads(path.read_text())
            for name in names:
                with self.subTest(path=path, section=section, name=name):
                    self.assertEqual(manifest[section][name]["git"], MIRRORS[name])
                    self.assertEqual(manifest[section][name]["rev"], PINS[name][1])
        for path in (ROOT / "Cargo.lock", ROOT.parent / "prover/Cargo.lock"):
            packages = tomllib.loads(path.read_text())["package"]
            for name, (version, revision) in PINS.items():
                entries = [p for p in packages if p["name"] == name]
                self.assertEqual(len(entries), 1, (path, name))
                self.assertEqual(entries[0]["version"], version)
                self.assertEqual(entries[0]["source"],
                                 f"git+{MIRRORS[name]}?rev={revision}#{revision}")

    def test_rehashed_undeclared_vendor_changes_are_rejected(self):
        for path in ("src/generators.rs", "src/inner_product_proof.rs", "build.rs"):
            with self.subTest(path=path), tempfile.TemporaryDirectory(prefix="uno-rehashed-control-") as scratch:
                directory = Path(scratch) / "vendor"
                shutil.copytree(ROOT / "vendor/bulletproofs", directory)
                file = directory / path
                data = (file.read_bytes() if file.exists() else b"") + b"\n// unreviewed delta\n"
                file.write_bytes(data)
                manifest = json.loads((directory / "SOURCE_MANIFEST.json").read_text())
                manifest["sha256"][path] = hashlib.sha256(data).hexdigest()
                (directory / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    validate_vendor(directory)

    def test_required_patch_survives_upstream_refresh(self):
        for remove_declaration in (False, True):
            with self.subTest(remove=remove_declaration), tempfile.TemporaryDirectory(prefix="uno-patch-revert-") as scratch:
                directory = Path(scratch) / "vendor"
                shutil.copytree(ROOT / "vendor/bulletproofs", directory)
                manifest = json.loads((directory / "SOURCE_MANIFEST.json").read_text())
                patch = next(p for p in manifest["local_patches"] if p["id"] == "constant-time-inner-product")
                file = directory / patch["path"]
                upstream = upstream_before_patch(file.read_bytes(), patch)
                self.assertEqual(git_blob(upstream), "4f23df6f251b617f9cd9438745453d912a9fd2e5")
                file.write_bytes(upstream)
                manifest["sha256"][patch["path"]] = hashlib.sha256(upstream).hexdigest()
                if remove_declaration:
                    manifest["local_patches"].remove(patch)
                (directory / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    validate_vendor(directory)

    def test_declared_patch_base_is_checked(self):
        with tempfile.TemporaryDirectory(prefix="uno-patch-base-") as scratch:
            directory = Path(scratch) / "vendor"
            shutil.copytree(ROOT / "vendor/bulletproofs", directory)
            manifest = json.loads((directory / "SOURCE_MANIFEST.json").read_text())
            manifest["local_patches"][0]["upstream_git_blob"] = "0" * 40
            (directory / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                validate_vendor(directory)

    def test_patch_byte_matching_is_exact(self):
        patch = {"reason": "test replacement", "edits": [{"offset": 1, "before": "old", "after": "new"}]}
        self.assertEqual(upstream_before_patch(b"xnewz", patch), b"xoldz")
        with self.assertRaises(ValueError):
            upstream_before_patch(b"xbadz", patch)

    def test_annotated_tag_objects_bind_the_commits(self):
        for name, (tag_object, commit) in TAGS.items():
            path = ROOT / "fixtures" / (name + ".tag")
            self.assertEqual(run("git", "hash-object", "-t", "tag", str(path)).strip(), tag_object)
            self.assertEqual(path.read_text().splitlines()[0], "object " + commit)

    def test_verifier_entry_closure_and_negative_controls(self):
        # New first-party modules must enter the gate without a manual whitelist
        # edit. Only the exact test-only fixture module is excluded.
        paths = sorted(p.relative_to(ROOT) for p in (ROOT / "src").rglob("*.rs")
                       if p != ROOT / "src/tests.rs")
        paths.append(Path("vendor/bulletproofs/src/range_proof/deterministic.rs"))
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
            validate_checkout_status(directory)

    def test_checkout_status_rejects_untracked_build_script(self):
        with tempfile.TemporaryDirectory(prefix="uno-checkout-control-") as scratch:
            directory=Path(scratch)
            subprocess.run(["git", "init", "--quiet", str(directory)], check=True)
            validate_checkout_status(directory)
            (directory / ".cargo-ok").write_bytes(b"")
            validate_checkout_status(directory)
            (directory / "build.rs").write_text("fn main() {}")
            with self.assertRaises(ValueError):
                validate_checkout_status(directory)

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
