"""Compare unchanged upstream Rust against local patches, with isolated controls."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REV = "961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82"
TAG = "def04efbf9d435a22306eae2c1a967f15ad43239"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode() + result.stdout.decode())
    return result.stdout


def compare(expected, actual):
    left, right = expected.splitlines(), actual.splitlines()
    if len(left) != 90 or len(right) != 90:
        return {"guard": "corpus-count"}
    for a, b in zip(left, right):
        aa, bb = a.split(b"\t"), b.split(b"\t")
        if len(aa) != 5 or len(bb) != 5 or aa[0] != bb[0]:
            return {"guard": "corpus-schema"}
        for index, label in enumerate(["proof-bytes", "commitment-bytes", "transcript-tail", "rng-consumption"], 1):
            if aa[index] != bb[index]:
                return {"guard": label, "case": aa[0].decode()}
    return {"guard": "equal", "cases": 90}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-git", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("gates", ROOT / "tests/kernel-gates.py")
    gates = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gates)
    gates.validate_vendor(ROOT / "vendor/bulletproofs")
    git = ["git", "--git-dir=" + str(args.upstream_git.resolve())]
    assert run(git + ["rev-parse", "v5.3.0"]).decode().strip() == TAG
    assert run(git + ["rev-parse", "v5.3.0^{}"]).decode().strip() == REV
    upstream = work / "upstream"
    upstream.mkdir()
    with tarfile.open(fileobj=io.BytesIO(run(git + ["archive", REV]))) as archive:
        archive.extractall(upstream, filter="data")
    manifest = json.loads((ROOT / "vendor/bulletproofs/SOURCE_MANIFEST.json").read_text())
    for name, blob in manifest["upstream_git_blobs"].items():
        assert gates.git_blob((upstream / name).read_bytes()) == blob, name
    local = work / "local"
    shutil.copytree(ROOT / "vendor/bulletproofs", local)
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    checkouts = cargo_home / "git/checkouts"
    paths = {}
    for name, (_, revision) in gates.PINS.items():
        matches = sorted(checkouts.glob(name + "-*/" + revision[:7]))
        assert matches, (name, "missing authenticated checkout")
        for checkout in matches:
            gates.validate_checkout_status(checkout)
            assert run(["git", "-C", str(checkout), "rev-parse", "HEAD"]).decode().strip() == revision
        paths[name] = matches[0] / ("curve25519-dalek" if name == "curve25519-dalek" else "")
    source = (ROOT / "tests/patch-differential.rs").read_bytes()
    for side in ["upstream", "local"]:
        harness = work / (side + "-harness")
        (harness / "src").mkdir(parents=True)
        (harness / "src/main.rs").write_bytes(source)
        content = f'''[package]
name = "patch-differential"
version = "0.0.0"
edition = "2021"
[workspace]
[dependencies]
bulletproofs = {{ path = "../{side}" }}
rand = "=0.10.1"
'''
        for name, path in paths.items():
            content += f'{name} = {{ path = {json.dumps(str(path))} }}\n'
        for organization in ["xelis-project", "tosnetwork"]:
            for name, path in paths.items():
                content += f'\n[patch."https://github.com/{organization}/{name}"]\n'
                content += f'{name} = {{ path = {json.dumps(str(path))} }}\n'
        (harness / "Cargo.toml").write_text(content)
        shutil.copyfile(ROOT / "rust-toolchain.toml", harness / "rust-toolchain.toml")
        shutil.copyfile(ROOT / "Cargo.lock", harness / "Cargo.lock")
        # Resolve only the test harness graph; normal node manifests are untouched.
        run(["cargo", "metadata", "--format-version=1"], cwd=harness)
        run(["cargo", "fetch", "--locked"], cwd=harness)
        shutil.copyfile(harness / "Cargo.lock", output / (side + ".Cargo.lock"))

    locks = [tomllib.loads((output / (side + ".Cargo.lock")).read_text())["package"]
             for side in ["upstream", "local"]]
    assert locks[0] == locks[1], "the two harnesses must resolve identical dependencies"

    events = []

    def execute(side, label):
        harness = work / (side + "-harness")
        cmd = ["cargo", "build", "--release", "--locked", "--offline", "-j32"]
        result = subprocess.run(cmd, cwd=harness, capture_output=True)
        (output / (label + ".build.log")).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"build failure is not behavioral evidence: {label}; see {output}")
        binary = harness / "target/release/patch-differential"
        result = subprocess.run([binary], capture_output=True)
        (output / (label + ".stderr.log")).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f"corpus producer failed: {label}")
        (output / (label + ".tsv")).write_bytes(result.stdout)
        events.append({"label": label, "build_exit": 0, "run_exit": 0,
                       "binary_sha256": sha(binary.read_bytes()), "corpus_sha256": sha(result.stdout),
                       "build_log": (output / (label + ".build.log")).read_text(),
                       "run_stderr": result.stderr.decode()})
        print(label, flush=True)
        return result.stdout

    reference = execute("upstream", "upstream-baseline")
    baseline = execute("local", "local-baseline")
    assert compare(reference, baseline)["guard"] == "equal"
    file = local / "src/inner_product_proof.rs"
    original = file.read_bytes()
    controls = []
    # Inject one wrong point after each of the four secret-scalar MSMs.
    # The prover continues successfully, so only the byte-comparison guard fires.
    for ordinal in range(4):
        positions = []
        for point in [b"L", b"R"]:
            anchor = b"let " + point + b" = RistrettoPoint::multiscalar_mul("
            start = 0
            while (position := original.find(anchor, start)) >= 0:
                end = original.index(b".compress();", position) + len(b".compress();")
                positions.append((position, end, point))
                start = end
        positions.sort()
        assert len(positions) == 4
        start, end, point = positions[ordinal]
        before = original[start:end]
        after = before.replace(b"= RistrettoPoint::", b"= (RistrettoPoint::", 1).replace(
            b")\n            .compress()", b") + Q)\n            .compress()", 1)
        assert after != before
        mutant = original[:start] + after + original[end:]
        file.write_bytes(mutant)
        try:
            corpus = execute("local", f"wrong-msm-{ordinal}")
            failure = compare(reference, corpus)
            assert failure["guard"] == "proof-bytes", failure
        finally:
            file.write_bytes(original)
        restored = file.read_bytes()
        assert restored == original
        replay = restored[:start] + after + restored[end:]
        assert sha(replay) == sha(mutant)
        controls.append({"site": ordinal, "path": "src/inner_product_proof.rs", "offset": start,
                         "from": before.decode(), "to": after.decode(),
                         "original_sha256": sha(original), "mutant_sha256": sha(mutant),
                         "restored_sha256": sha(restored), "restore_audit_sha256": sha(replay),
                         "result": failure})
    restored_corpus = execute("local", "local-restored")
    assert compare(reference, restored_corpus)["guard"] == "equal"
    report = {"schema": 1, "unit": "constant-time-proof-byte-differential", "upstream_revision": REV,
              "upstream_tag_object": TAG, "base_commit": run(["git", "rev-parse", "HEAD"], ROOT).decode().strip(),
              "harness_sha256": sha(source), "runner_sha256": sha(Path(__file__).read_bytes()),
              "dependency_lock_sha256": sha((output / "upstream.Cargo.lock").read_bytes()),
              "toolchain": run(["rustc", "-Vv"], work / "local-harness").decode(),
              "scope": "Shared-base primitive patch semantics only; no independent implementation or relation oracle.",
              "build": "Unchanged upstream tree; root Cargo patches select authenticated identical dalek/Merlin checkouts. std enabled in both test harnesses.",
              "comparison": compare(reference, baseline), "events": events, "controls": controls}
    (output / "measurement.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: 90 byte-identical cases and four individually attributed behavioral controls", flush=True)


if __name__ == "__main__":
    main()
