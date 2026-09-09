"""Nonzero-factor acceptance and observed residual differential, with controls."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def sha(data): return hashlib.sha256(data).hexdigest()


def records(data):
    rows = [line.split("\t") for line in data.splitlines()]
    assert rows and all(len(row) == 3 for row in rows)
    result = {row[0]: row[1:] for row in rows}
    assert len(result) == len(rows)
    return result


def compare(reference, candidate, all_tails=False):
    left, right = records(reference), records(candidate)
    assert left.keys() == right.keys()
    for key in left:
        if left[key][0] != right[key][0]:
            return {"guard": "acceptance", "case": key, "reference": left[key][0], "candidate": right[key][0]}
        if (all_tails or left[key][0] == "1") and left[key][1] != right[key][1]:
            return {"guard": "transcript-tail", "case": key}
    return {"guard": "equal", "cases": len(left), "accepted": sum(v[0] == "1" for v in left.values())}


def observed(data):
    result, key = {}, None
    for line in data.splitlines():
        fields = line.split("\t")
        if fields[0] == "BEGIN": key = fields[1]
        elif fields[0] == "OBS":
            assert key is not None and key not in result
            result[key] = [json.loads(x) for x in fields[1:]]
    return result


def compare_residuals(upstream, local):
    left, right = observed(upstream), observed(local)
    assert left.keys() == right.keys(), "residual observation coverage mismatch"
    assert len(left) >= 144
    for key in left:
        assert len(left[key]) == 1 and len(right[key]) == 4
        if left[key][0] != right[key][3]:
            return {"guard": "residual-reconstruction", "case": key}
        if key.endswith("/ip-only-response"):
            assert right[key][0] != [0]*32 and right[key][1] == [0]*32, key
    return {"guard": "equal", "observed_cases": len(left),
            "isolated_ip_cases": sum(k.endswith("/ip-only-response") for k in right)}


def boundary(data):
    rows = {r[0]: r[1:] for r in (line.split("\t") for line in data.splitlines())}
    assert len(rows) == 19
    for label, expected in [("zero", "1"), ("ip", "0"), ("poly", "0")]:
        if rows["boundary/"+label] != [expected]: return {"guard": "residual-"+label}
    for i in range(16):
        if rows[f"collision/{i}"][:2] != ["1", "0"]: return {"guard": "collision", "case": i}
    return {"guard": "equal", "cases": 19}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ct-work", required=True, type=Path, help="Restored work directory of the authenticated CT unit")
    parser.add_argument("--upstream-git", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--only-polynomial-sign", action="store_true")
    parser.add_argument("--only-weighted-boundary", action="store_true")
    args = parser.parse_args()
    assert not (args.only_polynomial_sign and args.only_weighted_boundary)
    work, output = args.work_dir.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=False); output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("gates", ROOT / "tests/kernel-gates.py")
    gates = importlib.util.module_from_spec(spec); spec.loader.exec_module(gates)
    gates.validate_vendor(ROOT / "vendor/bulletproofs")
    manifest = json.loads((ROOT / "vendor/bulletproofs/SOURCE_MANIFEST.json").read_text())
    git = ["git", "--git-dir="+str(args.upstream_git.resolve())]
    assert subprocess.check_output(git+["rev-parse", "v5.3.0^{}"], text=True).strip() == manifest["revision"]
    assert subprocess.check_output(git+["rev-parse", "v5.3.0"], text=True).strip() == gates.TAGS["bulletproofs"][0]
    entries = subprocess.check_output(git+["ls-tree", "-rz", manifest["revision"]]).split(b"\0")
    upstream_blobs = {}
    for entry in entries:
        if not entry: continue
        header, name = entry.split(b"\t", 1)
        mode, kind, blob = header.split()
        assert kind == b"blob", "unexpected submodule in oracle tree"
        upstream_blobs[name.decode()] = (mode.decode(), blob.decode())
    def authenticate_upstream(directory):
        actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
        assert actual == upstream_blobs.keys(), "upstream file inventory drift"
        for name, (mode, blob) in upstream_blobs.items():
            file = directory/name
            assert file.is_symlink() == (mode == "120000"), name
            data = os.readlink(file).encode() if file.is_symlink() else file.read_bytes()
            assert gates.git_blob(data) == blob, name
    authenticate_upstream(args.ct_work/"upstream")
    for name, blob in manifest["upstream_git_blobs"].items():
        assert gates.git_blob((args.ct_work / "upstream" / name).read_bytes()) == blob, name
    # The complete source inventory, including potential build scripts and files
    # absent from the vendored subset, is authenticated against Git objects.
    shutil.copytree(args.ct_work / "upstream", work / "upstream")
    shutil.copytree(ROOT / "vendor/bulletproofs", work / "local")
    corpus = ROOT.parents[1] / "doc/measurements/uno-m2-ct-differential/upstream-baseline.tsv"
    source = (ROOT / "tests/range-differential.rs").read_bytes()
    for side in ["upstream", "local"]:
        harness = work / (side + "-harness"); (harness / "src").mkdir(parents=True)
        (harness / "src/main.rs").write_bytes(source)
        content = (args.ct_work / (side + "-harness/Cargo.toml")).read_text()
        for name, (_, revision) in gates.PINS.items():
            path = Path(tomllib.loads(content)["dependencies"][name]["path"])
            gates.validate_checkout_status(path)
            assert subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip() == revision
        content = content.replace('name = "patch-differential"', 'name = "range-differential"')
        content = content.replace(f'bulletproofs = {{ path = "../{side}" }}',
                                  f'bulletproofs = {{ path = "../{side}", default-features = false }}')
        content += '\n[features]\ndefault = ["std-proof"]\nstd-proof = ["bulletproofs/std"]\nindependent = []\n'
        content += 'residual-export = '+('["bulletproofs/kernel-test"]' if side == "local" else '[]')+'\n'
        (harness / "Cargo.toml").write_text(content)
        lock = (args.ct_work / (side + "-harness/Cargo.lock")).read_text().replace('name = "patch-differential"', 'name = "range-differential"')
        (harness / "Cargo.lock").write_text(lock)
        shutil.copyfile(ROOT / "rust-toolchain.toml", harness / "rust-toolchain.toml")
        shutil.copyfile(harness / "Cargo.lock", output / (side + ".Cargo.lock"))
    assert tomllib.loads((output/"upstream.Cargo.lock").read_text()) == tomllib.loads((output/"local.Cargo.lock").read_text())
    events, controls, probes = [], [], []

    def execute(side, label, features=(), factor=1, residual=False):
        harness = work / (side + "-harness")
        cmd = ["cargo", "build", "--locked", "--offline", "--release", "-j32", "--no-default-features"]
        if features: cmd += ["--features", ",".join(features)]
        b = subprocess.run(cmd, cwd=harness, capture_output=True, text=True)
        (output/(label+".build.stdout.log")).write_text(b.stdout)
        (output/(label+".build.stderr.log")).write_text(b.stderr)
        assert b.returncode == 0, f"{label}: build failure is not behavioral evidence; {output}"
        binary = harness / "target/release/range-differential"
        r = subprocess.run([binary, "residuals"] if residual else [binary, corpus, str(factor)], capture_output=True, text=True)
        (output/(label+".tsv")).write_text(r.stdout)
        (output/(label+".stderr.log")).write_text(r.stderr)
        assert r.returncode == 0, f"{label}: producer did not finish; {output}"
        events.append({"label": label, "build_command": cmd, "build_exit": b.returncode, "run_exit": r.returncode,
                       "binary_sha256": sha(binary.read_bytes()), "stdout_sha256": sha(r.stdout.encode()),
                       "stderr_sha256": sha(r.stderr.encode())})
        print(label, flush=True)
        return r

    def replacement(label, side, path, before, after, action, bucket=controls):
        file = work/side/path; original = file.read_bytes(); before, after = before.encode(), after.encode()
        assert original.count(before) == 1, label
        offset = original.index(before); mutant = original.replace(before, after, 1); file.write_bytes(mutant)
        try: result = action()
        finally: file.write_bytes(original)
        restored = file.read_bytes(); assert restored == original
        replay = restored[:offset]+after+restored[offset+len(before):]; assert sha(replay) == sha(mutant)
        bucket.append({"label": label, "side": side, "path": path, "offset": offset, "from": before.decode(), "to": after.decode(),
                       "original_sha256": sha(original), "mutant_sha256": sha(mutant), "restored_sha256": sha(restored),
                       "restore_audit_sha256": sha(replay), "result": result})
        return result

    std = ["std-proof"]; independent = ["std-proof", "independent"]; exported = independent+["residual-export"]
    def weighted_control():
        baseline = execute("local", "weighted-boundary-baseline", exported, residual=True)
        assert boundary(baseline.stdout)["guard"] == "equal"
        archived = ROOT.parents[1]/"doc/measurements/uno-m2-range-differential/residual-boundary.tsv"
        assert baseline.stdout == archived.read_text(), "the original 16 inputs and c values must be reused exactly"
        committed = subprocess.check_output(["git", "show", "HEAD:uno/crypto/tests/range-differential.rs"], cwd=ROOT)
        assert committed == (work/"local-harness/src/main.rs").read_bytes()
        before = "u8::from(independent_residuals_zero(ip, poly)), hex(&c.to_bytes())"
        after = "u8::from((ip + c * poly).is_identity()), hex(&c.to_bytes())"
        def weighted():
            result = execute("local", "weighted-boundary-replacement", exported, residual=True)
            left = {row[0]: row[1:] for row in (line.split("\t") for line in baseline.stdout.splitlines())}
            right = {row[0]: row[1:] for row in (line.split("\t") for line in result.stdout.splitlines())}
            assert left.keys() == right.keys() and len(left) == 19
            for key in ["boundary/zero", "boundary/ip", "boundary/poly"]:
                assert left[key] == right[key], key
            differences = []
            for i in range(16):
                key = f"collision/{i}"
                assert left[key][0] == right[key][0] == "1"
                assert left[key][2] == right[key][2], "c changed"
                assert left[key][1] == "0" and right[key][1] == "1", key
                differences.append({"case": key, "c": left[key][2], "split_accepts": False, "weighted_accepts": True})
            return {"guard": "split-predicate-acceptance", "criterion_passed": False,
                    "differing_cases": len(differences), "cases": differences}
        replacement("weighted-residual-predicate", "local-harness", "src/main.rs", before, after, weighted)
        restored = execute("local", "weighted-boundary-restored", exported, residual=True)
        assert restored.stdout == baseline.stdout
        assert (work/"local-harness/src/main.rs").read_bytes() == committed
        return {"committed_harness_sha256": sha(committed), "baseline_corpus_sha256": sha(baseline.stdout.encode()),
                "archived_corpus_sha256": sha(archived.read_bytes()), "cases": 16,
                "mutation_location": "Test harness residual-boundary call site; vendored verifier source stays unchanged."}
    if args.only_weighted_boundary:
        result = weighted_control()
        gates.validate_vendor(work/"local"); authenticate_upstream(work/"upstream")
        report = {"schema": 1, "unit": "weighted-versus-split-residual-predicate", "comparison": result,
                  "controls": controls, "events": events,
                  "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "runner_sha256": sha(Path(__file__).read_bytes()), "harness_sha256": sha(source),
                  "scope": "Residual-level predicate comparison only. No full proof construction, no claim about practical applicability to the upstream protocol, and no examination of transcript-derived c in that protocol."}
        (output/"measurement.json").write_text(json.dumps(report,indent=2)+"\n")
        print("PASS: all 16 archived cases reject under the split predicate and accept under the weighted predicate; exact restore audit passed")
        return
    upstream = execute("upstream", "upstream-factor-1", std)
    baseline = execute("local", "local-independent", independent)
    comparison = compare(upstream.stdout, baseline.stdout); assert comparison["guard"] == "equal", comparison
    assert comparison["accepted"] == 72, comparison
    def sign_control():
        def wrong_sign():
            r = execute("local", "wrong-polynomial-sign", independent)
            failure = compare(upstream.stdout, r.stdout)
            assert failure["guard"] == "acceptance" and failure["case"].endswith("/valid"), failure
            return failure
        replacement("wrong-polynomial-sign", "local", "src/range_proof/deterministic.rs",
                    "-self.t_x_blinding]),", "self.t_x_blinding]),", wrong_sign)
    if args.only_polynomial_sign:
        committed = subprocess.check_output(["git", "show", "HEAD:uno/crypto/vendor/bulletproofs/src/range_proof/deterministic.rs"], cwd=ROOT)
        assert committed == (work/"local/src/range_proof/deterministic.rs").read_bytes()
        sign_control()
        restored = execute("local", "local-restored", independent)
        assert restored.stdout == baseline.stdout
        gates.validate_vendor(work/"local"); authenticate_upstream(work/"upstream")
        report = {"schema": 1, "unit": "committed-source-polynomial-sign-control", "comparison": comparison,
                  "controls": controls, "events": events, "committed_source_sha256": sha(committed),
                  "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "runner_sha256": sha(Path(__file__).read_bytes()), "harness_sha256": sha(source),
                  "scope": "A single coefficient mutation starting directly from committed source, without observation adapters. The acceptance guard is measured, not the observed-residual comparator."}
        (output/"measurement.json").write_text(json.dumps(report,indent=2)+"\n")
        print("PASS: committed-source polynomial sign control, compiled rejection, byte-exact restore audit")
        return
    for factor in [2, 255]:
        result = execute("upstream", f"upstream-factor-{factor}", std, factor=factor)
        assert compare(upstream.stdout, result.stdout, True)["guard"] == "equal"
    for label, features in [("local-original-api", std), ("local-no-std", ["independent"]), ("local-test-export", exported)]:
        result = execute("local", label, features)
        reference = upstream if label == "local-original-api" else baseline
        assert compare(reference.stdout, result.stdout, True)["guard"] == "equal"

    up_anchor = "        if mega_check.is_identity().into() {"
    up_probe = '        std::eprintln!("OBS\\t{:?}", mega_check.compress().to_bytes());\n'+up_anchor
    up_observation = None
    def observe_up():
        nonlocal up_observation
        up_observation = execute("upstream", "upstream-observed", std)
        assert up_observation.stdout == upstream.stdout
        return {"unchanged_acceptance_and_tails": True}
    replacement("observe-upstream-residual", "upstream", "src/range_proof/mod.rs", up_anchor, up_probe, observe_up, probes)
    local_anchor = "        if !independent_residuals_zero(ip, poly) { return Err(ProofError::VerificationError); }"
    local_probe = '        std::eprintln!("OBS\\t{:?}\\t{:?}\\t{:?}\\t{:?}", ip.compress().to_bytes(), poly.compress().to_bytes(), _c.to_bytes(), (ip + _c * poly).compress().to_bytes());\n'+local_anchor
    decomposition = None
    def observe_local():
        nonlocal decomposition
        result = execute("local", "local-observed", independent)
        assert result.stdout == baseline.stdout
        decomposition = compare_residuals(up_observation.stderr, result.stderr)
        assert decomposition["guard"] == "equal", decomposition
        return decomposition
    replacement("observe-independent-residuals", "local", "src/range_proof/deterministic.rs", local_anchor, local_probe, observe_local, probes)
    sign_control()
    residual_baseline = execute("local", "residual-boundary", exported, residual=True)
    assert boundary(residual_baseline.stdout)["guard"] == "equal"
    weighted_comparison = weighted_control()
    original = "    ip.is_identity() && poly.is_identity()"
    def drop_ip():
        r = execute("local", "omit-ip-check", independent)
        failure = compare(upstream.stdout, r.stdout)
        assert failure["guard"] == "acceptance" and failure["case"].endswith("/ip-only-response"), failure
        return failure
    replacement("omit-ip-check", "local", "src/range_proof/deterministic.rs", original, "    poly.is_identity()", drop_ip)
    for label, after, expected in [("omit-poly-check", "    ip.is_identity()", "residual-poly"),
                                   ("merge-residuals", "    (ip + poly).is_identity()", "collision")]:
        def action(label=label, expected=expected):
            r = execute("local", label, exported, residual=True)
            failure = boundary(r.stdout); assert failure["guard"] == expected, failure
            return failure
        replacement(label, "local", "src/range_proof/deterministic.rs", original, after, action)
    def omit_c():
        r = execute("local", "omit-c-event", independent)
        failure = compare(upstream.stdout, r.stdout)
        assert failure["guard"] == "transcript-tail", failure
        return failure
    replacement("omit-c-event", "local", "src/range_proof/deterministic.rs", '        let _c = t.challenge_scalar(b"c");',
                '        let _c = Scalar::ONE;', omit_c)
    restored = execute("local", "local-restored", independent)
    assert restored.stdout == baseline.stdout
    gates.validate_vendor(work/"local")
    authenticate_upstream(work/"upstream")
    for name, blob in manifest["upstream_git_blobs"].items(): assert gates.git_blob((work/"upstream"/name).read_bytes()) == blob
    report = {"schema": 1, "unit": "nonzero-factor-range-patch-differential", "comparison": comparison,
              "weighted_boundary": weighted_comparison,
              "residual_decomposition": decomposition, "controls": controls, "observation_adapters": probes, "events": events,
              "runner_sha256": sha(Path(__file__).read_bytes()), "harness_sha256": sha(source),
              "corpus_sha256": sha(corpus.read_bytes()), "upstream_revision": manifest["revision"],
              "authenticated_upstream_files": len(upstream_blobs),
              "upstream_tree": subprocess.check_output(git+["rev-parse", manifest["revision"]+"^{tree}"], text=True).strip(),
              "toolchain": subprocess.check_output(["rustc", "-Vv"], cwd=work/"local-harness", text=True),
              "base_commit": subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
              "scope": "Shared-base patch semantics, finite empirical coverage. No external SEND/COLLECT oracle or independent implementation. Collision inputs exercise the residual boundary, not forged full Fiat-Shamir proofs.",
              "zero_factor_exception": "Excluded by D41 decision memo@91ef26f9 and recorded separately. Honest Scalar::random zero probability is approximately 2^-252; not a claim of a practical attack."}
    (output/"measurement.json").write_text(json.dumps(report,indent=2)+"\n")
    print("PASS: nonzero acceptance, residual reconstruction, feature parity, collision boundary and five compiled controls")


if __name__ == "__main__": main()
