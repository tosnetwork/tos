#!/usr/bin/env python3
"""Instrument an isolated verifier copy; never edit the kernel-owned tree.

Counters observe iterator consumption and operation sites, not the host formula.
The copy is diagnostic code, not a supply-chain-accepted or deployable kernel.
"""
import argparse
import hashlib
import difflib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    temporary = None
    if args.output:
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="workchain-proof-trace-")
        output = Path(temporary.name)
    isolated = output / "crypto"
    shutil.copytree(source / "uno/crypto", isolated,
                    ignore=shutil.ignore_patterns("target", "__pycache__"))
    edits = []

    def edit(name, before, after):
        path = isolated / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError(f"instrumentation anchor is not unique: {name}: {before}")
        expected = original.replace(before, after, 1)
        patch = "".join(difflib.unified_diff(original.splitlines(True), expected.splitlines(True),
                                            fromfile="a/" + name, tofile="b/" + name))
        # Standard git, not the interactive agent's private patch helper.
        # This is a mechanical instrumentation rewrite of the isolated copy.
        subprocess.run(["git", "apply", "--no-index", "--whitespace=nowarn", "-"],
                       cwd=isolated, input=patch, text=True, check=True)
        if path.read_text() != expected:
            raise ValueError("instrumentation changed unexpected bytes")
        edits.append({"path": name, "from": before, "to": after,
                      "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                      "after_sha256": hashlib.sha256(expected.encode()).hexdigest()})

    root = "vendor/bulletproofs/src/"
    edit(root + "lib.rs", "extern crate alloc;", """extern crate alloc;
pub static OPERATION_TRACE_COUNTS: [core::sync::atomic::AtomicU64; 9] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 9];
pub fn operation_trace_count(index: usize) {
    OPERATION_TRACE_COUNTS[index].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}""")
    edit("src/lib.rs", "pub mod ffi;", """pub mod ffi;
/// cbindgen:ignore
#[unsafe(no_mangle)]
pub extern "C" fn workchain_proof_trace_read(index: usize) -> u64 {
    bulletproofs::OPERATION_TRACE_COUNTS[index].load(core::sync::atomic::Ordering::Relaxed)
}
/// cbindgen:ignore
#[unsafe(no_mangle)]
pub extern "C" fn workchain_proof_trace_reset() {
    for value in &bulletproofs::OPERATION_TRACE_COUNTS {
        value.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}""")
    edit("src/relation.rs", "CompressedRistretto(*bytes).decompress().ok_or(Error::UNO_CRYPTO_DECODE)",
         "bulletproofs::operation_trace_count(3);\n    CompressedRistretto(*bytes).decompress().ok_or(Error::UNO_CRYPTO_DECODE)")
    for expression in ["Scalar::from(limits.max_balance) * g", "Scalar::from(limits.max_value) * g",
                       "Scalar::from(fee) * g", "e * target"]:
        edit("src/relation.rs", expression, "{ bulletproofs::operation_trace_count(1); " + expression + " }")
    edit("src/relation.rs", "ranges.iter().map(Point::compress)",
         "ranges.iter().map(|p| { bulletproofs::operation_trace_count(4); p.compress() })")
    edit("src/relation.rs", "Scalar::from_canonical_bytes(*s)",
         "{ bulletproofs::operation_trace_count(7); Scalar::from_canonical_bytes(*s) }")
    edit("src/relation.rs", 'transcript.append_message(b"authenticated-context", context);',
         'transcript.append_message(b"authenticated-context", { for _ in context { bulletproofs::operation_trace_count(8); } context });')
    edit("src/relation.rs", "Point::vartime_multiscalar_mul(zs, row)",
         "{ bulletproofs::operation_trace_count(6); Point::vartime_multiscalar_mul(zs.iter().inspect(|_| bulletproofs::operation_trace_count(0)), row) }")
    edit(root + "generators.rs", "B_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(",
         "B_blinding: { crate::operation_trace_count(2); RistrettoPoint::hash_from_bytes::<Sha3_512>(")
    edit(root + "generators.rs", "RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),\n            ),",
         "RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),\n            ) },")
    edit(root + "generators.rs", "Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))",
         "{ crate::operation_trace_count(2); Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes)) }")
    edit(root + "inner_product_proof.rs", "challenges.push(transcript.challenge_scalar(b\"u\"));",
         "crate::operation_trace_count(5);\n            challenges.push(transcript.challenge_scalar(b\"u\"));")
    edit(root + "range_proof/deterministic.rs", "optional_multiscalar_mul(scalars, points)",
         "optional_multiscalar_mul(scalars.inspect(|_| crate::operation_trace_count(0)), points)")
    edit(root + "range_proof/deterministic.rs", "-self.t_x_blinding]),",
         "-self.t_x_blinding]).inspect(|_| crate::operation_trace_count(0)),")
    for expression in ["self.A.decompress()", "self.S.decompress()", "p.decompress()",
                       "self.T_1.decompress()", "self.T_2.decompress()", "v.decompress()"]:
        # The two L/R iterators intentionally have identical closures: patch
        # their distinct whole expressions instead of relying on first match.
        if expression == "p.decompress()":
            for side in ["L_vec", "R_vec"]:
                old = f"self.ipp_proof.{side}.iter().map(|p| p.decompress())"
                edit(root + "range_proof/deterministic.rs", old,
                     f"self.ipp_proof.{side}.iter().map(|p| {{ crate::operation_trace_count(3); p.decompress() }})")
        else:
            edit(root + "range_proof/deterministic.rs", expression,
                 "{ crate::operation_trace_count(3); " + expression + " }")
    (output / "instrumentation.json").write_text(json.dumps(edits, indent=2) + "\n")
    env = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(output / "target"))
    with (output / "build.log").open("w") as log:
        result = subprocess.run(["cargo", "build", "--locked", "--offline", "--release", "-j32"],
                                cwd=isolated, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        print((output / "build.log").read_text(), flush=True)
        result.check_returncode()
    build = args.build.resolve()
    commands = subprocess.check_output(
        ["ninja", "-C", str(build), "-t", "commands", "test-workchain-proof-backend"], text=True).splitlines()
    objects = {}
    for relative in ["crypto/test/test-workchain-proof-backend.cpp", "crypto/block/workchain-proof-backend.cpp"]:
        candidates = [line for line in commands if " -c " in line and line.endswith("/" + relative)
                      and "CMakeFiles/test-workchain-proof-backend.dir/" in line]
        if len(candidates) != 1:
            raise ValueError(f"missing unique compilation command: {relative}")
        command = shlex.split(candidates[0])
        obj = output / (Path(relative).name + ".o")
        old_obj = command[command.index("-o") + 1]
        objects[old_obj] = str(obj)
        for flag, value in [("-o", str(obj)), ("-MF", str(obj) + ".d"), ("-MT", str(obj))]:
            command[command.index(flag) + 1] = value
        command.append("-DWORKCHAIN_PROOF_OPERATION_TRACE")
        subprocess.run(command, cwd=build, check=True)
    candidates = [line for line in commands if " -o test-workchain-proof-backend " in line]
    if len(candidates) != 1:
        raise ValueError("missing unique trace link command")
    command = shlex.split(candidates[0])
    if command[:2] != [":", "&&"] or command[-2:] != ["&&", ":"]:
        raise ValueError("unexpected link command framing")
    command = command[2:-2]
    archive = "uno/crypto/cargo-target/release/libtos_uno_crypto_prototype.a"
    if command.count(archive) != 1:
        raise ValueError("missing unique kernel archive")
    command = [objects.get(item, item) for item in command]
    command[command.index(archive)] = str(output / "target/release/libtos_uno_crypto_prototype.a")
    command[command.index("-o") + 1] = str(output / "trace")
    subprocess.run(command, cwd=build, check=True)
    with (output / "trace.log").open("w") as log:
        result = subprocess.run([str(output / "trace"), str(source / "uno/crypto/fixtures/balance-kernel-v2.txt")],
                                stdout=log, stderr=subprocess.STDOUT)
    # Emit diagnostics before temporary-directory cleanup, also on failure.
    print((output / "trace.log").read_text(), flush=True)
    result.check_returncode()


if __name__ == "__main__":
    main()
