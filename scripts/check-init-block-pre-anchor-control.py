#!/usr/bin/env python3
"""Red-before control for publishing from a node that joined at an init block.

The init-block publisher regression must fail on the validation path that existed
before anchors were proven with backward block proofs: that path read the held zero
state as a state (GetState) and looked the init block up by height (LookupBlock). A
node that joined at a nonzero init block never held the zero state, so publication
could not pass. This runner restores exactly that path in the validation worker,
runs the same init-block join -> create/publish -> third-node bootstrap test against
the restored worker and requires the original refusal, then runs the same test with
the normal worker and requires success.

The worker source is mutated in place only for one build and restored in `finally`;
its hash is checked before and after. The lifecycle test itself is always compiled
from the unmodified checkout. Run it after the init-block fixture exists, from the
checkout root, with no other build using the Cargo target directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tosctl/src/Cargo.toml"
SOURCE = ROOT / "tosctl/src/node-control/node-data-sync/src/native_validation.rs"
TEST = "native_lifecycle::production_init_block_source_publishes_and_bootstraps_a_third_node"
SUCCESS = "PRODUCTION_INIT_BLOCK_PUBLISH_BOOTSTRAP_OK"
MARKER = "INIT_BLOCK_PRE_ANCHOR_CONTROL_OK"

# The validation path before anchor proofs: the held zero state is read as a state.
ZERO_READ_ANCHOR = b'    let what = format!("GetBlock for frontier {}", describe(frontier));\n'
ZERO_READ = b"""    let what = format!("GetState for held zero state {}", describe(&held.zero));
    let zero: tos::lite_server::BlockState = downcast(
        &what,
        query(client, &what, &tos::rpc::lite_server::GetState { id: held.zero.native()? }).await?,
    )?;
    ensure!(
        zero.id() == &held.zero.native()?,
        "native zero-state identity differs from held anchor"
    );
    let zero_bytes = zero.data().clone();
    ensure!(
        zero_bytes.len() as u64 <= MANIFEST_LIMIT && sha256(&zero_bytes) == held.zero.file_hash,
        "native zero-state file hash mismatch"
    );
    let zero_root = read_single_root_boc(&zero_bytes)?;
    ensure!(
        hex::encode(zero_root.repr_hash().as_slice()) == held.zero.root_hash,
        "native zero-state root hash mismatch"
    );
    ensure!(
        ShardStateUnsplit::construct_from_cell(zero_root)?.global_id() == held.global_id,
        "native zero-state global id differs"
    );
"""

# The ancestry check before anchor proofs: a lookup by height of each fork and the init block.
ANCESTRY_PROOFS = b"""    let mut ancestors = BTreeSet::new();
    for anchor in anchor_set(held, forks)? {
        if !needs_proof(frontier, &anchor)? {
            ancestors.insert(anchor);
            continue;
        }
        let what = format!(
            "GetBlockProof from frontier {} to anchor {}",
            describe(frontier),
            describe(&anchor)
        );
        let answer = query(client, &what, &anchor_request(frontier, &anchor)?)
            .await
            .map_err(|error| anchor_read_refusal(&anchor, error))?;
        let response: tos::lite_server::PartialBlockProof = downcast(&what, answer)?;
        verify_anchor_proof(held, frontier, &frontier_state, &anchor, &response)
            .with_context(|| format!("native {what}"))?;
        ancestors.insert(anchor);
    }
"""
ANCESTRY_LOOKUP = b"""    let mut ancestors = BTreeSet::new();
    for fork in forks.iter().chain(std::iter::once(&held.init)) {
        fork.masterchain()?;
        ensure!(fork.seqno <= frontier.seqno, "held fork or init anchor is ahead of generation");
        if fork.seqno == 0 {
            ensure!(
                fork == &held.zero,
                "zero-height safety anchor differs from held network zero state"
            );
            ancestors.insert(fork.clone());
            continue;
        }
        let what = format!("LookupBlock for anchor {}", describe(fork));
        let response: tos::lite_server::BlockHeader = downcast(
            &what,
            query(
                client,
                &what,
                &tos::rpc::lite_server::LookupBlock {
                    mode: 1,
                    id: tos::tos_node::blockid::BlockId {
                        workchain: -1,
                        shard: i64::MIN,
                        seqno: i32::from_le_bytes(fork.seqno.to_le_bytes()),
                    },
                    lt: None,
                    utime: None,
                },
            )
            .await?,
        )?;
        ensure!(
            response.id() == &fork.native()?,
            "held fork or init block is not on imported native chain"
        );
        ancestors.insert(fork.clone());
    }
"""
MUTATIONS = ((ZERO_READ_ANCHOR, ZERO_READ + ZERO_READ_ANCHOR), (ANCESTRY_PROOFS, ANCESTRY_LOOKUP))

# The refusal the pre-proof path gives a source without a zero state: the worker exhausts
# its reopen deadline and names the zero-state read as the last failed check.
RED_REQUIRED = (
    "production create rejected init-block source",
    "native recovery or required shard-state read did not complete; last check: "
    "native GetState for held zero state",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> str:
    # The checkout may belong to another user (a CI container runs as root over
    # the runner's workspace); trust exactly this checkout, independent of any
    # global git configuration. Any git failure is fatal.
    result = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def mutated(original: bytes) -> bytes:
    text = original
    for before, after in MUTATIONS:
        if text.count(before) != 1:
            raise RuntimeError("mutation anchor is not unique in native_validation.rs")
        text = text.replace(before, after, 1)
    return text


def cargo(args: list[str], env: dict[str, str], log: Path) -> tuple[int, float]:
    started = time.monotonic()
    with log.open("wb") as output:
        status = subprocess.run(
            ["cargo", *args], cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT
        ).returncode
    return status, round(time.monotonic() - started, 3)


def build_worker(env: dict[str, str], target: Path, log: Path, copy: Path) -> str:
    status, _ = cargo(
        [
            "build",
            "--manifest-path",
            str(MANIFEST),
            "--locked",
            "-p",
            "node-data-sync",
            "--features",
            "native",
            "--bin",
            "node-data-sync-worker",
        ],
        env,
        log,
    )
    if status != 0:
        raise RuntimeError(f"worker build failed; see {log}")
    shutil.copy2(target / "debug/node-data-sync-worker", copy)
    return sha256(copy.read_bytes())


def lifecycle(env: dict[str, str], worker: Path, log: Path) -> dict[str, object]:
    command = [
        "test",
        "--manifest-path",
        str(MANIFEST),
        "--locked",
        "-p",
        "node-data-sync",
        "--features",
        "native-lifecycle-tests",
        "--lib",
        TEST,
        "--",
        "--exact",
        "--test-threads=1",
        "--nocapture",
    ]
    status, elapsed = cargo(command, {**env, "NODE_SYNC_NATIVE_WORKER": str(worker)}, log)
    data = log.read_bytes()
    return {
        "command": "NODE_SYNC_NATIVE_WORKER=<worker> cargo " + " ".join(command),
        "exit_status": status,
        "elapsed_seconds": elapsed,
        "worker_sha256": sha256(worker.read_bytes()),
        "output": log.name,
        "output_sha256": sha256(data),
        "output_bytes": len(data),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--init-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    target = args.target_dir.resolve()
    init_root = args.init_root.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((init_root / "init-block-receipt.json").read_text())
    if receipt.get("result") != "NATIVE_INIT_BLOCK_JOIN_OK" or receipt["init_block"]["seqno"] <= 0:
        raise RuntimeError("the init-block fixture did not join at a nonzero init block")
    # Fail closed: an unreadable status is never taken as a clean source.
    try:
        dirty = git("status", "--porcelain", "--", str(SOURCE.relative_to(ROOT)))
    except RuntimeError as error:
        raise RuntimeError(
            f"cannot confirm that native_validation.rs is unmodified: {error}"
        ) from error
    if dirty:
        raise RuntimeError("native_validation.rs has local changes; the control needs the commit")
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": str(target),
        "CARGO_BUILD_JOBS": str(args.jobs),
        "NODE_STORE_NATIVE_DIR": str(build / "third-party/rocksdb"),
        "NODE_SYNC_NATIVE_FIXTURE": str(init_root / "checked-generation"),
        "NODE_SYNC_NATIVE_SOURCE": str(init_root / "network/node5"),
        "NODE_SYNC_NATIVE_INIT_ROOT": str(init_root),
        "NODE_SYNC_NATIVE_ENGINE": str(build / "validator-engine/validator-engine"),
    }
    original = SOURCE.read_bytes()
    mutant_source = mutated(original)
    normal = output / "worker-normal"
    mutant = output / "worker-pre-anchor-proof"
    normal_sha = build_worker(env, target, output / "build-normal.log", normal)
    try:
        SOURCE.write_bytes(mutant_source)
        mutant_sha = build_worker(env, target, output / "build-pre-anchor-proof.log", mutant)
    finally:
        SOURCE.write_bytes(original)
    if sha256(SOURCE.read_bytes()) != sha256(original):
        raise RuntimeError("native_validation.rs was not restored")
    if mutant_sha == normal_sha:
        raise RuntimeError("the restored pre-proof path did not change the worker")
    # Leave the target directory holding the normal worker again.
    build_worker(env, target, output / "build-restored.log", output / "worker-restored")

    red = lifecycle(env, mutant, output / "pre-anchor-proof-red.txt")
    red_text = (output / red["output"]).read_text(errors="replace")
    red_ok = (
        red["exit_status"] != 0
        and all(text in red_text for text in RED_REQUIRED)
        and SUCCESS not in red_text
    )
    green = lifecycle(env, normal, output / "pre-anchor-proof-green.txt")
    green_text = (output / green["output"]).read_text(errors="replace")
    green_ok = (
        green["exit_status"] == 0
        and SUCCESS in green_text.splitlines()
        and "test result: ok. 1 passed; 0 failed" in green_text
    )
    result = {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": sha256(original),
        "pre_anchor_proof_source_sha256": sha256(mutant_source),
        "restored_source_sha256": sha256(SOURCE.read_bytes()),
        "mutation": "restore the held zero-state GetState read and the LookupBlock "
        "ancestry loop in place of the backward anchor proofs",
        "normal_worker_sha256": normal_sha,
        "pre_anchor_proof_worker_sha256": mutant_sha,
        "fixture_init_block_seqno": receipt["init_block"]["seqno"],
        "red_required": list(RED_REQUIRED),
        "red": red,
        "green": green,
        "result": MARKER if red_ok and green_ok else "INIT_BLOCK_PRE_ANCHOR_CONTROL_FAILED",
    }
    (output / "pre-anchor-proof-control.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    if not red_ok:
        print("the pre-proof validation path did not give the original refusal", file=sys.stderr)
        return 1
    if not green_ok:
        print("the normal worker did not pass the same lifecycle test", file=sys.stderr)
        return 1
    print(MARKER, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
