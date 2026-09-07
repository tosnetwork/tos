"""Replay negative controls for the lexical gate, ABI unwind and runtime trap."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--target-dir", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix="uno-boundary-controls-"))
    source = scratch / "crypto"
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns("target", "__pycache__"))
    env = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(args.target_dir))

    def run(label, command, expected, must_contain):
        result = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        if result.returncode != expected or must_contain not in log:
            raise RuntimeError(f"{label}: invalid instrument result {result.returncode}; see {args.output}; source={source}")

    gate = source / "tests/kernel-gates.py"
    original = gate.read_text()
    gate.write_text(original.replace("return bool(FORBIDDEN.search(source))", "return False"))
    run("disabled-lexical-gate", ["python3", str(gate),
        "KernelGates.test_verifier_entry_closure_and_negative_controls"], 1, "FAILED (failures=")
    gate.write_text(original)

    gate.write_text(original.replace('if actual != set(manifest["sha256"]) | {"SOURCE_MANIFEST.json"}:', 'if False:'))
    run("removed-vendor-file-set", ["python3", str(gate),
        "KernelGates.test_vendored_source_manifest_and_tamper_control"], 1, "FAILED (failures=")
    gate.write_text(original)
    gate.write_text(original.replace('if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:', 'if False:'))
    run("removed-vendor-hash-check", ["python3", str(gate),
        "KernelGates.test_vendored_source_manifest_and_tamper_control"], 1, "FAILED (failures=")
    gate.write_text(original)

    ffi = source / "src/ffi.rs"
    original = ffi.read_text()
    ffi.write_text(original.replace("match catch_unwind(f) {", "match Ok::<_, Box<dyn std::any::Any + Send>>(f()) {"))
    run("removed-unwind-containment", ["cargo", "test", "--locked", "--offline", "--release", "-j48", "--lib",
        "borrowed_abi_layout_spans_and_panic_recovery", "--", "--nocapture"], 101, "thread caused non-unwinding panic")
    ffi.write_text(original)

    cpp = source / "tests/balance-abi.cpp"
    original = cpp.read_text()
    cpp.write_text(original.replace("      forbid_entropy();", "      // Deliberately removed trap installation."))
    binary = scratch / "trap-mutant"
    run("trap-mutant-build", ["c++", "-std=c++17", "-O2", "-Iinclude", str(cpp), str(args.archive),
        "-lpthread", "-ldl", "-lm", "-o", str(binary)], 0, "")
    run("removed-runtime-trap", [str(binary), str(source / "fixtures/balance-kernel-v1.txt")], 2,
        "entropy trap negative control did not fire")
    cpp.write_text(original)
    run("restored-boundary", ["cargo", "test", "--locked", "--offline", "--release", "-j48", "--lib",
        "borrowed_abi_layout_spans_and_panic_recovery"], 0, "1 passed; 0 failed")
    shutil.rmtree(scratch)
    print(f"PASS: lexical, vendor set/hash, unwind and runtime trap controls all failed; {args.output}")


if __name__ == "__main__":
    main()
