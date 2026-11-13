#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Network scenarios: a local network whose nodes may run different implementations.

Each node's implementation is a parameter:

    --node cpp:<validator-engine>      the C++ node
    --node adapter:<launcher>          any other implementation, behind a launcher that accepts the
                                       validator-engine command line (--global-config, --local-config,
                                       --db, -v..., the engine's flags) and serves the same lite-server,
                                       DHT and validator protocols

One --node applies to every node; otherwise give one per node, in node order. The runner reuses the
repository's local-network tooling (test/tostester: Genesis, PQ initial validators, DHT, lite clients),
runs a fixed scenario list on a fresh network each, and asserts hashes, not heights:

- the masterchain block ids (seqno, root hash, file hash) of blocks 1..K, as every node's lite-server
  reports them, are the same on every node;
- the state root each node applied for each of those blocks (the new-state hash of the Merkle update in
  the block proof the node stored) is the same on every node;
- every node stored a finality certificate for each block that names the same session, slot and
  candidate on every node, whose signatures verify under the validators' consensus keys and whose signers
  reach the quorum threshold. Certificates are decoded and checked through the conformance reference
  (conformance-ref-cli, consensus harness), so a node's stored proof is judged by the same code as the
  fixtures.

Scenarios: bootstrap (all nodes from Genesis), restart (one node stopped mid-run and started again),
late-join (one node started only after the others produced blocks). Node databases must be on a
non-rotational disk; the runner refuses a rotational one unless --allow-rotational is given.

    uv run python test/conformance/scenarios/run_scenarios.py --build-dir build --source-dir . \
        --work-dir build/conformance-network --node cpp:build/validator-engine/validator-engine --nodes 4
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import hashlib
import importlib
import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "migrate"))

# The package reader of the consensus context generator, which reads the same node archive format.
read_package = cast(
    Callable[[Path], dict[str, bytes]],
    getattr(importlib.import_module("consensus_contexts"), "read_package"),
)

Json = dict[str, Any]

SCENARIOS = ("bootstrap", "restart", "late-join")
MASTER_SHARD = 1 << 63
DEFAULT_BLOCKS = 12
DEFAULT_TIMEOUT_SECONDS = 300.0
POLL_SECONDS = 0.5
REFERENCE_TIMEOUT_SECONDS = 600
MAX_NODES = 16
SKIPPED = 77


class ScenarioError(Exception):
    """A scenario could not be run (as opposed to an assertion that failed)."""


@dataclass(frozen=True)
class NodeImpl:
    kind: str
    path: Path

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.path}"


def parse_node_specs(specs: Sequence[str], count: int) -> list[NodeImpl]:
    if not 1 <= count <= MAX_NODES:
        raise ScenarioError(f"--nodes must be within 1..{MAX_NODES}")
    impls: list[NodeImpl] = []
    for spec in specs:
        kind, sep, path = spec.partition(":")
        if not sep or kind not in ("cpp", "adapter") or not path:
            raise ScenarioError(f"node spec {spec!r}: cpp:<validator-engine> or adapter:<launcher>")
        resolved = Path(path).resolve()
        if not (resolved.is_file() and os.access(resolved, os.X_OK)):
            raise ScenarioError(f"node spec {spec!r}: not an executable file")
        impls.append(NodeImpl(kind, resolved))
    if len(impls) == 1:
        return impls * count
    if len(impls) != count:
        raise ScenarioError(f"give one --node for all nodes or exactly {count}")
    return impls


def is_rotational(path: Path) -> bool:
    """Whether the block device holding path is rotational (False when it cannot be told)."""
    probe = path
    while not probe.exists():
        probe = probe.parent
    dev = os.stat(probe).st_dev
    queue = Path(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}")
    for candidate in (queue / "queue" / "rotational", queue / ".." / "queue" / "rotational"):
        with contextlib.suppress(OSError, ValueError):
            return candidate.read_text().strip() == "1"
    return False


# ---------------------------------------------------------------------------------------------------------
# Observations and the comparison. Pure: the unit tests drive these with synthetic observations.


@dataclass
class Certificate:
    session_id: str
    slot: int
    candidate: str
    catchain_seqno: int
    signers: list[str]
    invalid_signers: list[str]


@dataclass
class NodeObservation:
    name: str
    implementation: str
    blocks: dict[int, tuple[str, str]] = field(default_factory=dict)
    states: dict[int, str] = field(default_factory=dict)
    certificates: dict[int, Certificate] = field(default_factory=dict)
    proof_blocks: dict[int, tuple[str, str]] = field(default_factory=dict)


@dataclass
class Expected:
    blocks: dict[int, str] = field(default_factory=dict)
    states: dict[int, str] = field(default_factory=dict)


def compare(
    observations: Sequence[NodeObservation],
    seqnos: Iterable[int],
    weights: Mapping[str, int],
    threshold: int,
    expected: Expected,
) -> list[str]:
    """Every assertion of a scenario; an empty list means it passed."""
    failures: list[str] = []
    if not observations:
        return ["no node was observed"]
    for seqno in seqnos:
        for what, table, pinned in (
            ("block id", "blocks", expected.blocks),
            ("state root", "states", expected.states),
        ):
            values: dict[str, Any] = {}
            for obs in observations:
                found = cast(Mapping[int, Any], getattr(obs, table)).get(seqno)
                if found is None:
                    failures.append(f"#{seqno}: {obs.name} has no {what}")
                else:
                    values[obs.name] = found
            if len({json.dumps(v) for v in values.values()}) > 1:
                failures.append(f"#{seqno}: nodes disagree on the {what}: {values}")
            want = pinned.get(seqno)
            if want is not None:
                for name, value in values.items():
                    got = value[0] if isinstance(value, tuple) else value
                    if got != want:
                        failures.append(f"#{seqno}: {name} {what} {got} is not the expected {want}")
        for obs in observations:
            proof_block = obs.proof_blocks.get(seqno)
            if proof_block is not None and obs.blocks.get(seqno) not in (None, proof_block):
                failures.append(
                    f"#{seqno}: {obs.name} stored a proof of {proof_block}, served {obs.blocks[seqno]}"
                )
        certs = {obs.name: obs.certificates.get(seqno) for obs in observations}
        shared = {
            (c.session_id, c.slot, c.candidate, c.catchain_seqno)
            for c in certs.values()
            if c is not None
        }
        if len(shared) > 1:
            failures.append(f"#{seqno}: certificates name different sessions/candidates: {shared}")
        for name, cert in certs.items():
            if cert is None:
                failures.append(f"#{seqno}: {name} stored no finality certificate")
                continue
            if cert.invalid_signers:
                failures.append(f"#{seqno}: {name} certificate has invalid signatures")
            unknown = [s for s in cert.signers if s not in weights]
            if unknown:
                failures.append(f"#{seqno}: {name} certificate has unknown signers {unknown}")
            if len(set(cert.signers)) != len(cert.signers):
                failures.append(f"#{seqno}: {name} certificate repeats a signer")
            weight = sum(weights.get(s, 0) for s in set(cert.signers))
            if weight < threshold:
                failures.append(f"#{seqno}: {name} certificate weight {weight} below {threshold}")
    return failures


# ---------------------------------------------------------------------------------------------------------
# Stored proofs, judged through the conformance reference.


class Reference:
    def __init__(self, path: Path) -> None:
        self.path = path

    def run(self, contexts: Sequence[Json]) -> list[Json]:
        if not contexts:
            return []
        stdin = "".join(json.dumps(ctx, sort_keys=True) + "\n" for ctx in contexts)
        result = subprocess.run(
            [str(self.path), "consensus"],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
            timeout=REFERENCE_TIMEOUT_SECONDS,
        )
        answers = [cast(Json, json.loads(line)) for line in result.stdout.splitlines()]
        if len(answers) != len(contexts):
            raise ScenarioError(f"reference answered {len(answers)} of {len(contexts)} contexts")
        for answer in answers:
            if "harness_error" in answer:
                raise ScenarioError(f"reference refused a context: {answer['harness_error']}")
        return answers


def stored_proofs(db: Path, seqnos: set[int]) -> dict[int, bytes]:
    """The masterchain block proofs a node database holds (archive and temporary packages)."""
    found: dict[int, bytes] = {}
    for pack in sorted(db.rglob("*.pack")):
        if pack.is_symlink() or not pack.is_file():
            continue
        try:
            entries = read_package(pack)
        except Exception as error:  # a package being written when the node stopped
            logging.warning("skipping unreadable package %s: %s", pack, error)
            continue
        for name, data in entries.items():
            if not name.startswith(f"proof_(-1,{MASTER_SHARD:016x},"):
                continue
            seqno = int(name.split(",")[2].split(")")[0])
            if seqno in seqnos:
                found.setdefault(seqno, data)
    return found


def judge_proofs(
    reference: Reference,
    obs: NodeObservation,
    proofs: Mapping[int, bytes],
    public_keys: Mapping[str, str],
) -> None:
    import base64

    seqnos = sorted(proofs)
    decoded = reference.run(
        [
            {"op": "decode_proof", "block_proof": base64.b64encode(proofs[s]).decode()}
            for s in seqnos
        ]
    )
    votes: list[Json] = []
    owners: list[tuple[int, str]] = []
    for seqno, answer in zip(seqnos, decoded):
        if answer.get("outcome") != "proof":
            continue
        obs.proof_blocks[seqno] = (answer["root_hash"], answer["file_hash"])
        obs.states[seqno] = answer["state_hash"]
        sig_set = answer["signature_set"]
        if sig_set is None or not sig_set["final"]:
            continue
        block = {
            "workchain": -1,
            "shard": f"{MASTER_SHARD:016x}",
            "seqno": seqno,
            "root_hash": answer["root_hash"],
            "file_hash": answer["file_hash"],
        }
        cert = Certificate(
            session_id=sig_set["session_id"],
            slot=sig_set["slot"],
            candidate=sig_set["candidate"],
            catchain_seqno=sig_set["catchain_seqno"],
            signers=[s["validator_id"] for s in sig_set["signatures"]],
            invalid_signers=[],
        )
        obs.certificates[seqno] = cert
        for sig in sig_set["signatures"]:
            key = public_keys.get(sig["validator_id"])
            if key is None:
                continue
            votes.append(
                {
                    "op": "vote",
                    "session_id": sig_set["session_id"],
                    "slot": sig_set["slot"],
                    "candidate": sig_set["candidate"],
                    "final": True,
                    "block": block,
                    "public_key": key,
                    "signature": sig["signature"],
                }
            )
            owners.append((seqno, sig["validator_id"]))
    for (seqno, signer), answer in zip(owners, reference.run(votes)):
        if answer.get("signature_check") != "valid":
            obs.certificates[seqno].invalid_signers.append(signer)


# ---------------------------------------------------------------------------------------------------------
# Running a network.


@dataclass
class Settings:
    build_dir: Path
    source_dir: Path
    work_dir: Path
    reference: Path
    impls: list[NodeImpl]
    blocks: int
    timeout: float
    base_port: int
    expected: Expected


def shim_install(base: Path, impl: NodeImpl, source_dir: Path) -> Any:
    """An Install whose validator-engine is the node's implementation (a link in a per-node tree)."""
    from tostester.install import Install

    tree = base / hashlib.sha256(impl.label.encode()).hexdigest()[:16]
    target = tree / "validator-engine" / "validator-engine"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_symlink():
        target.symlink_to(impl.path)
    return Install(tree, source_dir)


async def head_seqno(node: Any) -> int | None:
    from toslib import ToslibError

    try:
        client = await node.toslib_client()
        info = await client.get_masterchain_info()
    except (ToslibError, OSError, RuntimeError):
        return None
    return None if info.last is None else int(info.last.seqno)


async def wait_heads(nodes: Sequence[Any], seqno: int, timeout: float, what: str) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        heads = [await head_seqno(node) for node in nodes]
        if all(h is not None and h >= seqno for h in heads):
            return
        if asyncio.get_running_loop().time() >= deadline:
            names = [node.name for node in nodes]
            raise ScenarioError(f"{what}: heads {dict(zip(names, heads))} did not reach #{seqno}")
        await asyncio.sleep(POLL_SECONDS)


async def served_blocks(node: Any, seqnos: Iterable[int]) -> dict[int, tuple[str, str]]:
    client = await node.toslib_client()
    found: dict[int, tuple[str, str]] = {}
    for seqno in seqnos:
        block = await client.lookup_block(workchain=-1, shard=-MASTER_SHARD, seqno=seqno)
        found[seqno] = (block.root_hash.hex().upper(), block.file_hash.hex().upper())
    return found


async def run_scenario(name: str, settings: Settings) -> Json:
    from tostester.install import Install
    from tostester.network import FullNode, Network, StartOptions

    directory = settings.work_dir / name
    if directory.exists():
        raise ScenarioError(f"{directory} exists; give a fresh --work-dir")
    directory.mkdir(parents=True)
    install = Install(settings.build_dir, settings.source_dir)
    install.toslibjson.client_set_verbosity_level(1)
    shims = directory / "implementations"
    count = len(settings.impls)
    k = settings.blocks
    seqnos = list(range(1, k + 1))
    report: Json = {"scenario": name, "nodes": [i.label for i in settings.impls], "blocks": k}
    observations: list[NodeObservation] = []
    public_keys: dict[str, str] = {}
    weights: dict[str, int] = {}

    async with Network(install, directory / "net", base_port=settings.base_port) as network:
        dht = network.create_dht_node()
        network.config.shard_validators = count
        # Genesis of version 16 commits to an AUTH network tag; the scenarios use their own fixed one.
        network.config.auth_network_tag = hashlib.sha256(b"conformance network scenarios").digest()
        nodes: list[FullNode] = []
        for index in range(count):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"conformance-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"conformance-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            nodes.append(node)
        for node in nodes:
            held = node.pq_initial_validator
            if held is None:
                raise ScenarioError("a validator without a post-quantum key")
            vid = held.validator_id.hex().upper()
            public_keys[vid] = held.public_key.hex()
            weights[vid] = 17  # tostester's default PQ Genesis weight
        options = [
            StartOptions(install=shim_install(shims, impl, settings.source_dir))
            for impl in settings.impls
        ]

        async def start(indices: Iterable[int]) -> None:
            # One at a time: the first start generates Genesis, which concurrent starts would race.
            for i in indices:
                await nodes[i].run(options[i])

        await dht.run()
        late = count - 1 if name == "late-join" else None
        await start(i for i in range(count) if i != late)
        running = [n for i, n in enumerate(nodes) if i != late]
        half = max(2, k // 2)
        await wait_heads(running, half, settings.timeout, "first half")
        if name == "restart":
            victim = nodes[1 % count]
            await victim.stop()
            others = [n for n in nodes if n is not victim]
            await wait_heads(others, half + 3, settings.timeout, "progress while one node is down")
            await start([1 % count])
            report["restarted"] = victim.name
        if late is not None:
            await start([late])
            report["late"] = nodes[late].name
        await wait_heads(nodes, k, settings.timeout, "all nodes")
        for i, node in enumerate(nodes):
            obs = NodeObservation(node.name, settings.impls[i].label)
            obs.blocks = await served_blocks(node, seqnos)
            observations.append(obs)
        for node in nodes:
            await node.stop()
        reference = Reference(settings.reference)
        for node, obs in zip(nodes, observations):
            judge_proofs(reference, obs, stored_proofs(node.directory, set(seqnos)), public_keys)

    total = sum(weights.values())
    threshold = (2 * total + 2) // 3
    failures = compare(observations, seqnos, weights, threshold, settings.expected)
    report["failures"] = failures
    report["observations"] = {
        obs.name: {
            "implementation": obs.implementation,
            "blocks": {str(s): list(v) for s, v in sorted(obs.blocks.items())},
            "state_roots": {str(s): v for s, v in sorted(obs.states.items())},
            "certificates": {
                str(s): {"session_id": c.session_id, "slot": c.slot, "signers": len(c.signers)}
                for s, c in sorted(obs.certificates.items())
            },
        }
        for obs in observations
    }
    return report


def fresh_run_dir(root: Path) -> Path:
    """root/run-<n> for the first n not used yet: a run never reuses another run's node databases."""
    for n in range(1, 10000):
        candidate = root / f"run-{n}"
        if not candidate.exists():
            return candidate
    raise ScenarioError(f"{root}: no free run directory")


def parse_pins(values: Sequence[str], what: str) -> dict[int, str]:
    pins: dict[int, str] = {}
    for value in values:
        seqno, sep, digest = value.partition("=")
        if not sep or not seqno.isdigit() or len(digest) != 64:
            raise ScenarioError(f"{what} {value!r}: <seqno>=<64 hex digits>")
        pins[int(seqno)] = digest.upper()
    return pins


def main(argv: Sequence[str] | None = None, runner: Callable[..., Any] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--reference", type=Path, help="conformance-ref-cli (default: in --build-dir)"
    )
    parser.add_argument(
        "--node", action="append", required=True, help="cpp:<path> or adapter:<path>"
    )
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--blocks", type=int, default=DEFAULT_BLOCKS)
    parser.add_argument("--scenario", action="append", choices=SCENARIOS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--base-port", type=int, default=23000)
    parser.add_argument("--expect-block", action="append", default=[], help="<seqno>=<root hash>")
    parser.add_argument("--expect-state", action="append", default=[], help="<seqno>=<state root>")
    parser.add_argument("--allow-rotational", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--only-if-env",
        metavar="NAME",
        help="skip (exit 77) unless the environment variable NAME is 1; ctest uses it",
    )
    args = parser.parse_args(argv)
    if args.only_if_env and os.environ.get(args.only_if_env) != "1":
        print(f"skipped: set {args.only_if_env}=1 to start validator networks")
        return SKIPPED
    try:
        if args.blocks < 4:
            raise ScenarioError("--blocks must be at least 4")
        reference = args.reference or args.build_dir / "test/conformance/conformance-ref-cli"
        if not reference.is_file():
            raise ScenarioError(f"{reference}: conformance reference not built")
        work_dir = fresh_run_dir(args.work_dir.resolve())
        if is_rotational(work_dir) and not args.allow_rotational:
            raise ScenarioError(f"{work_dir} is on a rotational disk; node databases need an SSD")
        settings = Settings(
            build_dir=args.build_dir.resolve(),
            source_dir=args.source_dir.resolve(),
            work_dir=work_dir,
            reference=reference.resolve(),
            impls=parse_node_specs(args.node, args.nodes),
            blocks=args.blocks,
            timeout=args.timeout,
            base_port=args.base_port,
            expected=Expected(
                blocks=parse_pins(args.expect_block, "--expect-block"),
                states=parse_pins(args.expect_state, "--expect-state"),
            ),
        )
    except ScenarioError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(name)s] %(message)s")
    run = runner or run_scenario
    reports: list[Json] = []
    for offset, name in enumerate(args.scenario or SCENARIOS):
        # Each scenario gets its own port range, so a port still in TIME_WAIT is never reused.
        scenario_settings = dataclasses.replace(
            settings, base_port=settings.base_port + 100 * offset
        )
        try:
            report = asyncio.run(run(name, scenario_settings))
        except ScenarioError as error:
            report = {"scenario": name, "failures": [f"not completed: {error}"]}
        reports.append(report)
        verdict = "passed" if not report["failures"] else "FAILED"
        print(f"scenario {name}: {verdict}")
        for failure in report["failures"]:
            print(f"  {failure}")
    out = args.report or settings.work_dir / "report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    failed = [r["scenario"] for r in reports if r["failures"]]
    print(f"scenarios: {len(reports)} run, {len(failed)} failed; report {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
