"""Measure verifier entropy gates using compiled, single-source controls."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work, output = args.work_dir.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    fixture = work / "crypto"
    shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns("target", "__pycache__"))
    gates = module("source_gates", fixture / "tests/kernel-gates.py")
    symbols = module("symbol_gates", fixture / "tests/kernel-symbols.py")
    gates.validate_vendor(fixture / "vendor/bulletproofs")
    events, controls = [], []
    rust_target = work / "cargo-target"
    cmake_source = work / "cmake-source"
    cmake_source.mkdir()
    (cmake_source / "CMakeLists.txt").write_text(f'''cmake_minimum_required(VERSION 3.16)
project(uno_entropy_measurement LANGUAGES CXX)
find_package(Threads REQUIRED)
add_executable(entropy-probe "{fixture}/tests/balance-abi.cpp")
target_include_directories(entropy-probe PRIVATE "{fixture}/include")
target_compile_features(entropy-probe PRIVATE cxx_std_17)
target_link_libraries(entropy-probe PRIVATE "{rust_target}/release/libtos_uno_crypto_prototype.a" Threads::Threads dl m)
''')
    build_dir = work / "cmake-build"
    binary = build_dir / "entropy-probe"
    corpus = fixture / "fixtures/balance-kernel-v2.txt"

    def command(label, command, expected=0, cwd=fixture, env=None):
        result = subprocess.run(command, cwd=cwd, capture_output=True, env=env)
        stdout, stderr = result.stdout.decode(), result.stderr.decode()
        (output / (label + ".stdout.log")).write_text(stdout)
        (output / (label + ".stderr.log")).write_text(stderr)
        events.append({"label": label, "command": [str(x) for x in command],
                       "exit": result.returncode, "stdout": stdout, "stderr": stderr})
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f"{label}: exit {result.returncode}, expected {expected}; full logs in {output}")
        return result

    def build(label):
        command(label + "-rust", ["cargo", "build", "--locked", "--offline", "--release", "-j32", "--target-dir", str(rust_target)])
        command(label + "-link", ["cmake", "--build", str(build_dir), "-j32"])
        return digest(binary.read_bytes())

    def lexical():
        files = sorted(p for p in (fixture / "src").rglob("*.rs") if p != fixture / "src/tests.rs")
        files.append(fixture / "vendor/bulletproofs/src/range_proof/deterministic.rs")
        return [str(p.relative_to(fixture)) for p in files if gates.rejected(p.read_text())]

    def observe(label, entropy):
        rejected = lexical()
        graph = symbols.inspect(str(binary))
        result = command(label + "-runtime", [binary, corpus, "--entropy-worker"],
                         expected=-signal.SIGSYS if entropy else 0)
        if entropy:
            assert rejected == ["src/relation.rs"], rejected
            target = next(entry for entry in graph if entry["entry"] == "uno_crypto_verify_v2")
            assert target["forbidden"], "the symbol gate must independently detect the RNG reconnection"
            assert all(not entry["forbidden"] for entry in graph if entry is not target)
        else:
            assert rejected == [], rejected
            assert all(not entry["forbidden"] for entry in graph), graph
        return {"source_rejected_files": rejected, "symbol_graph": graph,
                "runtime_exit": result.returncode, "binary_sha256": digest(binary.read_bytes())}

    def mutate(label, path, before, after, action):
        file = fixture / path
        original = file.read_bytes()
        before, after = before.encode(), after.encode()
        assert original.count(before) == 1, label
        offset = original.index(before)
        mutant = original.replace(before, after, 1)
        file.write_bytes(mutant)
        try:
            result = action()
        finally:
            file.write_bytes(original)
        restored = file.read_bytes()
        assert restored == original
        replay = restored[:offset] + after + restored[offset + len(before):]
        assert digest(replay) == digest(mutant)
        controls.append({"label": label, "path": path, "offset": offset,
                         "from": before.decode(), "to": after.decode(),
                         "original_sha256": digest(original), "mutant_sha256": digest(mutant),
                         "restored_sha256": digest(restored), "restore_audit_sha256": digest(replay),
                         "result": result})

    command("configure", ["cmake", "-S", str(cmake_source), "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release"])
    build("normal-baseline")
    command("normal-canary", [binary, corpus, "--entropy-canary"], expected=-signal.SIGSYS)
    normal = observe("normal-baseline", False)
    command("normal-full-corpus", [binary, corpus])
    normal_tree = command("normal-features", ["cargo", "tree", "--locked", "--offline", "-e", "normal,features", "--prefix", "none"]).stdout.decode()
    command("normal-dependency-gate", [sys.executable, fixture / "tests/kernel-gates.py", "KernelGates.test_normal_dependency_graph_has_no_entropy_provider"])
    command("normal-feature-gate", [sys.executable, fixture / "tests/kernel-gates.py", "KernelGates.test_normal_feature_graph_matches_inventory_snapshot"])
    normal_lock = digest((fixture / "Cargo.lock").read_bytes())

    # This feature change adds no entropy provider. Only the exact feature gate
    # should reject it; a package-name blacklist would miss it.
    feature_before = next(line for line in (fixture/"Cargo.toml").read_text().splitlines() if line.startswith("merlin = "))
    feature_after = feature_before.replace("default-features = false", 'default-features = false, features = ["std"]')
    expected_features = gates.normal_feature_rows()
    def change_feature():
        build("changed-transcript-feature")
        observation = observe("changed-transcript-feature", False)
        actual = gates.normal_feature_rows()
        assert actual != expected_features
        command("changed-feature-gate", [sys.executable, fixture / "tests/kernel-gates.py", "KernelGates.test_normal_feature_graph_matches_inventory_snapshot"], expected=1)
        return {"guard": "normal-feature-snapshot", "added": sorted(set(actual)-set(expected_features)),
                "removed": sorted(set(expected_features)-set(actual)), "other_gates": observation}
    mutate("changed-transcript-feature", "Cargo.toml", feature_before, feature_after, change_feature)

    # A libc entropy call exercises dynamic-import reachability without adding
    # a Rust RNG dependency or matching the conservative first-party lexer.
    foreign_anchor = "    let range = RangeProof::from_bytes(proof).map_err(|_| Error::UNO_CRYPTO_DECODE)?;"
    foreign_after = ('    extern "C" { fn getentropy(buffer: *mut u8, len: usize) -> i32; }\n'
                     '    let mut entropy_probe = [0u8; 1];\n'
                     '    unsafe { std::hint::black_box(getentropy(entropy_probe.as_mut_ptr(), entropy_probe.len())); }\n'+foreign_anchor)
    def foreign_entropy():
        build("foreign-entropy-import")
        assert lexical() == []
        graph = symbols.inspect(str(binary))
        target = next(entry for entry in graph if entry["entry"] == "uno_crypto_verify_v2")
        assert any(name.split("@")[0] == "getentropy" for name in target["forbidden"])
        result = command("foreign-entropy-runtime", [binary, corpus, "--entropy-worker"], expected=-signal.SIGSYS)
        return {"guard": "reachable-dynamic-entropy-import", "source_rejected_files": [],
                "symbol_graph": graph, "runtime_exit": result.returncode,
                "binary_sha256": digest(binary.read_bytes())}
    mutate("foreign-entropy-import", "src/relation.rs", foreign_anchor, foreign_after, foreign_entropy)

    # Removing only this syscall rule must make the direct canary fail its
    # expected SIGSYS criterion; no file-read trap can catch a direct getrandom.
    trap_before = '''    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
'''

    def removed_trap():
        build("removed-getrandom-rule")
        result = command("removed-getrandom-rule-canary", [binary, corpus, "--entropy-canary"])
        return {"guard": "canary-must-signal-sigsys", "expected_signal": int(signal.SIGSYS),
                "actual_exit": result.returncode, "criterion_passed": False}

    mutate("remove-getrandom-trap", "tests/balance-abi.cpp", trap_before, "", removed_trap)
    build("trap-restored")
    command("restored-canary", [binary, corpus, "--entropy-canary"], expected=-signal.SIGSYS)

    # A test-only expanded dependency graph permits compiling real RNG calls.
    # Its admission is measured separately; it is never accepted as the normal
    # verifier graph. Each subsequent source control changes only one source.
    manifest_file = fixture / "Cargo.toml"
    manifest_original = manifest_file.read_bytes()
    manifest_expanded = manifest_original.replace(b"[dependencies]\n", b'[dependencies]\nrand = "=0.10.1"\n', 1)
    manifest_file.write_bytes(manifest_expanded)
    try:
        build("expanded-graph-baseline")
        expanded = observe("expanded-graph-baseline", False)
        admitted = command("expanded-dependency-gate", [sys.executable, fixture / "tests/kernel-gates.py", "KernelGates.test_normal_dependency_graph_has_no_entropy_provider"], expected=1)
        anchor = "    let range = RangeProof::from_bytes(proof).map_err(|_| Error::UNO_CRYPTO_DECODE)?;"
        calls = [
            ("random-scalar", "    std::hint::black_box(Scalar::random(&mut rand::rng()));\n" + anchor),
            ("transcript-rng", "    std::hint::black_box(relation.transcript.clone().build_rng().finalize(&mut rand::rng()));\n" + anchor),
            ("random-container", "    std::hint::black_box(std::collections::HashMap::<u64, u64>::new());\n" + anchor),
        ]
        for label, replacement in calls:
            def action(label=label):
                build(label)
                return observe(label, True)
            mutate(label, "src/relation.rs", anchor, replacement, action)
        before = '''    range.verify_independent(&generators, &PedersenGens::default(),
        &mut range_transcript(relation.transcript), &relation.ranges, 64)'''
        after = '''    range.verify_multiple_with_rng(&generators, &PedersenGens::default(),
        &mut range_transcript(relation.transcript), &relation.ranges, 64, &mut rand::rng())'''

        def collector():
            build("random-collector")
            return observe("random-collector", True)

        mutate("random-collector", "src/relation.rs", before, after, collector)
        build("expanded-restored")
        observe("expanded-restored", False)
    finally:
        manifest_file.write_bytes(manifest_original)
    assert manifest_file.read_bytes() == manifest_original
    assert manifest_original.replace(b"[dependencies]\n", b'[dependencies]\nrand = "=0.10.1"\n', 1) == manifest_expanded
    controls.append({"label": "admit-runtime-rand-dependency", "path": "Cargo.toml",
                     "from": "[dependencies]\n", "to": '[dependencies]\nrand = "=0.10.1"\n',
                     "original_sha256": digest(manifest_original), "mutant_sha256": digest(manifest_expanded),
                     "restored_sha256": digest(manifest_file.read_bytes()), "restore_audit_sha256": digest(manifest_expanded),
                     "result": {"dependency_gate_exit": admitted.returncode, "dormant_rng_observation": expanded}})
    assert digest((fixture / "Cargo.lock").read_bytes()) == normal_lock
    build("normal-restored")
    observe("normal-restored", False)
    command("restored-feature-gate", [sys.executable, fixture / "tests/kernel-gates.py", "KernelGates.test_normal_feature_graph_matches_inventory_snapshot"])
    # Empty PATH removes the actual disassembler dependency. Failure must not
    # become a skipped or successful symbol inspection.
    empty_path = work / "empty-path"
    empty_path.mkdir()
    missing = command("missing-disassembler", [sys.executable, fixture / "tests/kernel-symbols.py", binary],
                      expected=1, env=dict(os.environ, PATH=str(empty_path)))
    report = {"schema": 1, "unit": "verifier-rng-call-closure-controls",
              "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "runner_sha256": digest(Path(__file__).read_bytes()), "normal_lock_sha256": normal_lock,
              "measured_sources": {str(p.relative_to(fixture)): digest(p.read_bytes()) for p in
                                   [fixture/"tests/kernel-symbols.py", fixture/"tests/kernel-gates.py",
                                    fixture/"tests/balance-abi.cpp", fixture/"fixtures/verifier-feature-graph.json"]},
              "normal_features": normal_tree, "baseline": normal, "controls": controls, "events": events,
              "missing_dependency_exit": missing.returncode,
              "scope": "Source review, direct/GOT reachability and exercised runtime paths; unresolved indirect calls require review. No milestone acceptance."}
    (output / "measurement.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: four compiled RNG reconnections trapped; removed trap and dependency controls fired")


if __name__ == "__main__":
    main()
