#!/usr/bin/env python3
"""Serial Z01 live run: final-parameter four-validator network, exact Config30 proofs.

Subcommands:

* ``precommit`` (offline): binds the clean source commit, every binary the run
  will execute, the OS release, ports, window and the expected Param16/28/30
  cell hashes into a write-once JSON file. It runs the production launch-cap
  admission test and the harness 22-validator refusals. It starts no node.
* ``genesis-dry-run`` (offline): builds the exact tostester Network the live
  run builds, generates its zerostate with create-state, and checks the
  Param16/28/30 cells against the precommit. It starts no node.
* ``live``: requires ``--confirm-network-slot``. Starts one DHT and four PQ
  validators on loopback, captures every node with z01_final_capture over a
  precommitted governance window, cross-checks each height through lite-client,
  runs the proof-checker control matrix on every node's genuine quartet, checks
  every node's exact command line, stops the network and rechecks override
  absence after quiescence.

Every step retains command, exit, stdout, stderr and SHA-256 under a new output
directory, and any mismatch refuses (fail closed). The tostester genesis is not
the final signed Genesis: a receipt from this runner can bind final parameters
on the final tree but cannot by itself close Z01's signed-Genesis gate.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for entry in (REPO / "test/tostester/src", REPO):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

SCHEMA = "tos.z01.live-precommit.v1"
VALIDATORS = 4
DEFAULT_BASE_PORT = 30600
DEFAULT_RPC_BASE_PORT = 31600
# Harness DHT takes one port and every full node three (peer, lite, console).
PORT_SPAN = 1 + 3 * VALIDATORS
BINARIES = {
    "validator_engine": "validator-engine/validator-engine",
    "dht_server": "dht-server/dht-server",
    "lite_client": "lite-client/lite-client",
    "create_state": "crypto/create-state",
    "pq_consensus_key": "crypto/pq/tos-pq-consensus-key",
    "toslibjson": "toslib/libtoslibjson.so",
    "proof_checker": "z01-config-proof-check",
    "chain_checker": "z01-chain-proof-check",
    "launch_cap_test": "test-pq-launch-cap",
}
LAUNCH_CAP_OK = b"PQ_LAUNCH_CAP_OK: node admission accepts 21 and refuses every 22-validator ceiling\n"
# Decoded from the Ubuntu 24 test-input zerostate by check-z01-genesis-boc.py
# and reviewed independently; the live genesis must reproduce these cells.
EXPECTED_PARAM_CELLS = {
    "16": "5174904df97ddd38da02ed5565e6719e95729f163ce35c8f3227a80c7341c137",
    "28": "f0a98e1c3fa538583cc06d470a29dfb1a6d9407323fe8d64a8f870c838a19fea",
    "30": "a922fc0cb6bacfee2d49645da25394f069447d8c250e4a0fb5ed75ba23cdd9e5",
}


class RunError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_once(path: Path, raw: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
    return sha(raw)


def write_json(path: Path, value: Any) -> str:
    return write_once(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def run_raw(argv: list[str], out: Path, label: str, *, cwd: Path | None = None,
            env: dict[str, str] | None = None, timeout: float = 600.0) -> dict[str, Any]:
    """Run one offline command and retain its command/exit/stdout/stderr bytes."""
    at = time.time_ns()
    try:
        completed = subprocess.run(argv, capture_output=True, check=False, cwd=cwd, env=env,
                                   timeout=timeout)
        code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        code, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
    write_json(out / f"{label}.command.json", {"argv": argv, "cwd": None if cwd is None else str(cwd),
                                               "started_wall_ns": at})
    write_once(out / f"{label}.exit.raw", f"{code}\n".encode())
    write_once(out / f"{label}.stdout.raw", stdout)
    write_once(out / f"{label}.stderr.raw", stderr)
    return {"exit": code, "stdout": stdout, "stderr": stderr,
            "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}


def refuse_local_knobs(environ: dict[str, str]) -> None:
    """Nodes inherit the harness environment; no TOS_* runtime knob may be present."""
    knobs = sorted(name for name in environ if name.startswith("TOS_"))
    require(not knobs, f"harness environment carries node runtime knobs: {knobs}")


def source_identity(source: Path) -> dict[str, Any]:
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, check=False)
    require(head.returncode == 0, f"cannot read source commit: {head.stderr.decode(errors='replace').strip()}")
    status = subprocess.run(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"],
                            capture_output=True, check=False)
    require(status.returncode == 0, f"cannot read source status: {status.stderr.decode(errors='replace').strip()}")
    require(status.stdout == b"", "source tree has tracked or untracked changes")
    return {"commit": head.stdout.decode().strip(), "status_porcelain_sha256": sha(status.stdout)}


def module_origins(source: Path) -> dict[str, str]:
    """Refuse shadowing by another checkout's editable install or generated TL."""
    import tosapi.lite_api
    import tosapi.tos_api
    import toslib
    import tostester.network
    from scripts import z01_final_capture, z01_lite_quartet, z01_proof_controls, z01_fixed_inputs, z01_chain_capture, z01_development_signature, z02_pq_regenerate

    origins = {}
    for module in (tosapi.lite_api, tosapi.tos_api, toslib, tostester.network,
                   z01_final_capture, z01_lite_quartet, z01_proof_controls, z01_fixed_inputs, z01_chain_capture, z01_development_signature, z02_pq_regenerate):
        path = Path(module.__file__).resolve()
        require(path.is_relative_to(source.resolve()), f"{module.__name__} resolves outside the source tree: {path}")
        origins[module.__name__] = str(path)
    return origins


def os_release() -> dict[str, str]:
    release = platform.freedesktop_os_release()
    return {"id": release.get("ID", ""), "version_id": release.get("VERSION_ID", ""),
            "pretty_name": release.get("PRETTY_NAME", "")}


def binary_hashes(build: Path) -> dict[str, dict[str, str]]:
    result = {}
    for name, relative in BINARIES.items():
        path = build / relative
        require(path.is_file(), f"required binary is missing: {path}")
        result[name] = {"path": str(path.resolve()), "sha256": sha(path.read_bytes())}
    return result


def ports_free(base_port: int, rpc_base_port: int) -> list[int]:
    ports = [base_port + offset for offset in range(1, PORT_SPAN + 1)]
    ports += [rpc_base_port + index for index in range(VALIDATORS)]
    require(len(set(ports)) == len(ports), "peer and RPC port ranges overlap")
    for port in ports:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            probe = socket.socket(socket.AF_INET, kind)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RunError(f"loopback port {port} is not free: {exc}") from exc
            finally:
                probe.close()
    return ports


def harness_refusals() -> dict[str, str]:
    """The genesis builder must refuse a 22-validator ceiling before Fift runs."""
    from tostester.zerostate import _launch_validator_counts

    refusals = {}
    for label, call in (("22_total_validators", lambda: _launch_validator_counts(22, 4)),
                        ("22_minimum", lambda: _launch_validator_counts(4, 22))):
        try:
            call()
        except ValueError as exc:
            refusals[label] = str(exc)
            continue
        raise RunError(f"harness accepted {label}")
    accepted = _launch_validator_counts(21, 4)
    require(accepted == {"max_validators": 21, "max_main_validators": 21, "min_validators": 4},
            "harness no longer builds the 21/21/4 launch boundary")
    return refusals


def precommit(args: argparse.Namespace) -> int:
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    refuse_local_knobs(dict(os.environ))
    source = REPO
    require((args.fixed_inputs is None) == (args.fixed_inputs_sha256 is None),
            "fixed input path and SHA-256 must be supplied together")
    fixed = None
    if args.fixed_inputs is not None:
        from scripts.z01_fixed_inputs import load
        fixed, _ = load(args.fixed_inputs, args.fixed_inputs_sha256)
    identity = source_identity(source)
    origins = module_origins(source)
    binaries = binary_hashes(args.build_dir)
    release = os_release()
    final_os = release["id"] == "ubuntu" and release["version_id"] == "24.04"
    require(final_os or args.rehearsal, "Z01 final run requires Ubuntu 24.04; use --rehearsal otherwise")
    launch = run_raw([binaries["launch_cap_test"]["path"]], out, "launch-cap-test")
    require(launch["exit"] == 0 and launch["stdout"] == LAUNCH_CAP_OK,
            "production launch-cap admission test did not accept 21 and refuse 22")
    refusals = harness_refusals()
    window = args.window_heights
    require(type(window) is int and 3 <= window <= 257, "governance window must span 3..257 heights")
    manifest = {
        "schema": SCHEMA,
        "z01_eligible": final_os and not args.rehearsal,
        "source": identity, "module_origins": origins,
        "os_release": release, "image_id": args.image_id,
        "binaries": binaries,
        "ports": {"base_port": args.base_port, "rpc_base_port": args.rpc_base_port,
                  "reserved": ports_free(args.base_port, args.rpc_base_port)},
        "window_heights": window, "start_lead_heights": args.start_lead,
        "window_timeout_seconds": args.window_timeout, "capture_attempts": args.attempts,
        "expected_param_cells": EXPECTED_PARAM_CELLS,
        "fixed_inputs": fixed,
        "launch_cap_test": {"stdout_sha256": launch["stdout_sha256"],
                            "stderr_sha256": launch["stderr_sha256"]},
        "harness_22_refusals": refusals,
        "created_wall_ns": time.time_ns(),
    }
    digest = write_json(out / "precommit.json", manifest)
    print(json.dumps({"precommit": str(out / "precommit.json"), "sha256": digest}))
    return 0


def load_precommit(path: Path, digest: str, build: Path, rehearsal: bool) -> dict[str, Any]:
    raw = path.read_bytes()
    require(sha(raw) == digest, "precommit differs from its recorded SHA-256")
    manifest = json.loads(raw)
    require(manifest.get("schema") == SCHEMA, "wrong precommit schema")
    refuse_local_knobs(dict(os.environ))
    require(source_identity(REPO) == manifest["source"], "source tree differs from precommit")
    require(module_origins(REPO) == manifest["module_origins"], "module origins differ from precommit")
    require(binary_hashes(build) == manifest["binaries"], "binaries differ from precommit")
    require(os_release() == manifest["os_release"], "OS release differs from precommit")
    require(manifest["z01_eligible"] or rehearsal, "a rehearsal precommit needs --rehearsal")
    require(manifest["expected_param_cells"] == EXPECTED_PARAM_CELLS,
            "precommitted parameter cells differ from the reviewed launch cells")
    return manifest


def build_network(install: Any, directory: Path, base_port: int,
                  fixed_inputs: dict[str, Any] | None = None) -> tuple[Any, Any, list[Any]]:
    from tostester.network import Network

    network = Network(install, directory, base_port=base_port)
    config = network.config
    # Production economics: Param16 21/21/4 and Param28 250/250/1000 with a
    # 21-member shard ceiling; default Simplex v2 Param30. No Stage A timing.
    config.validator_economics_profile = True
    config.shard_validators = VALIDATORS
    if fixed_inputs is not None:
        config.genesis_time = fixed_inputs["genesis_time"]
        config.genesis_wallet_seed = fixed_inputs["wallet_seed"]
    dht = network.create_dht_node()
    nodes = []
    for index in range(VALIDATORS):
        if fixed_inputs is None:
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"z01-live-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"z01-live-validator-seed-{index}".encode()).digest(),
            )
        else:
            from nacl.signing import SigningKey
            from tostester.key import Key
            identity = fixed_inputs["validators"][index]
            node = network.create_full_node(Key(SigningKey(identity["adnl_seed"])))
            node.make_initial_pq_validator(identity["validator_id"], identity["pq_seed"])
        if fixed_inputs is not None and "signed_descriptors" in fixed_inputs:
            expected = fixed_inputs["signed_descriptors"][index]
            actual = node.pq_initial_validator
            require(all(getattr(actual, field).hex() == expected[field]
                        for field in ("validator_id", "key_id", "public_key", "adnl_id"))
                    and node.validator_key.public_key.key.hex() == expected["adnl_public_key"]
                    and type(expected["weight"]) is int and expected["weight"] == 17,
                    "signed descriptor differs from actual provisioned validator")
        node.announce_to(dht)
        nodes.append(node)
    for key_file in directory.glob("node*/keyring/*"):
        key_file.chmod(0o600)
    return network, dht, nodes


def fixed_custody(manifest: dict[str, Any]) -> dict[str, Any] | None:
    frozen = manifest.get("fixed_inputs")
    if frozen is None:
        return None
    from scripts.z01_fixed_inputs import load
    public, private = load(Path(frozen["manifest_path"]), frozen["manifest_sha256"])
    require(public == frozen, "fixed input public commitments differ from precommit")
    return private



def authenticated_custody(manifest, args):
    from scripts import z01_development_signature as signatures
    private = fixed_custody(manifest)
    require(private is not None, "development generation requires frozen private custody")
    authority, key = signatures.anchor(args.trust_anchor, args.trust_anchor_sha256)
    frozen = manifest["fixed_inputs"]
    commitments = signatures.verify_commitments(authority, key, frozen["manifest_sha256"])
    require(commitments.get("source_commit") == manifest["source"]["commit"]
            and commitments.get("generator_source_commit") == manifest["source"]["commit"],
            "signed custody differs from actual source/generator")
    require(commitments.get("genesis_time") == private["genesis_time"]
            and commitments.get("wallet_seed_commitment") == frozen["wallet_commitment"]
            and commitments.get("validators") == frozen["validators"],
            "signed custody fields differ from actual generation inputs")
    signatures.verify_profile(commitments, authority, frozen)
    from scripts.z02_pq_regenerate import authenticate_input, validate_public_input
    raw = signatures.bounded(args.signed_inputs, 2 * 1024 * 1024)
    require(sha(raw) == args.signed_inputs_sha256, "signed descriptor input hash differs")
    detached = signatures.bounded(args.input_signature, 64)
    authenticate_input(raw, key.encode(), detached, authority["public_key_sha256"])
    descriptor = json.loads(raw)
    validate_public_input(descriptor, manifest["source"]["commit"])
    require(descriptor["trust_anchor_sha256"] == args.trust_anchor_sha256
            and descriptor["input_commitments_sha256"] == authority["payload_sha256"]
            and descriptor["wallet_seed"]["sha256"] == frozen["wallet_commitment"],
            "signed descriptors do not bind pre-frozen custody/authority")
    require(len(descriptor["validators"]) == VALIDATORS, "signed descriptors require four validators")
    private["signed_descriptors"] = descriptor["validators"]
    return private


def check_genesis(network: Any, out: Path, expected: dict[str, str]) -> dict[str, Any]:
    """Generate (or reuse) the network zerostate and bind its launch cells."""
    zerostate = network._get_or_generate_zerostate()
    boc = zerostate.masterchain.file
    raw = boc.read_bytes()
    command = [sys.executable, str(REPO / "scripts/check-z01-genesis-boc.py"),
               "--zerostate", str(boc), "--expected-boc-sha256", sha(raw)]
    result = run_raw(command, out, "genesis-check")
    require(result["exit"] == 0, "zerostate does not carry the Z01 launch parameters")
    decoded = json.loads(result["stdout"])
    actual = {"16": decoded["param16_cell_hash"], "28": decoded["param28_cell_hash"],
              "30": decoded["param30_cell_hash"]}
    require(actual == expected, f"zerostate launch cells differ: {actual} != {expected}")
    require(decoded["root_hash"] == zerostate.masterchain.root_hash.hex(),
            "decoded zerostate root differs from the network's zerostate ID")
    return {"boc": str(boc), "boc_sha256": sha(raw),
            "root_hash": zerostate.masterchain.root_hash.hex(),
            "file_hash": zerostate.masterchain.file_hash.hex(), "param_cells": actual}


def genesis_dry_run(args: argparse.Namespace) -> int:
    from tostester.install import Install

    manifest = load_precommit(args.precommit, args.precommit_sha256, args.build_dir, args.rehearsal)
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    install = Install(args.build_dir, REPO)
    network, _, _ = build_network(install, out / "network", manifest["ports"]["base_port"],
                                 authenticated_custody(manifest, args))
    genesis = check_genesis(network, out, manifest["expected_param_cells"])
    write_json(out / "genesis.json", genesis)
    print(json.dumps({"passed": True, **genesis}, sort_keys=True))
    return 0


def expected_cmdline(install: Any, node: Any, rpc: str) -> list[str]:
    """The only argv a Z01 validator may carry: no consensus or override flag."""
    return [str(install.validator_engine_exe),
            "--global-config", str(node.directory / "config.global.json"),
            "--local-config", str(node.directory / "config.json"),
            "--db", ".", "-v3", "--threads", "2",
            "--initial-sync-delay", "5", "--session-logs", str(node.session_log_path),
            "--quic-flood-control", "-1", "--json-rpc-address", rpc]


class NativeTail:
    """Incrementally scan one node's raw log for native finality markers.

    Only used to decide when to start a capture; the collector re-reads and
    binds the raw log itself, so this reader carries no evidential weight.
    """

    def __init__(self, log: Path):
        self.log = log
        self.offset = 0
        self.partial = b""
        self.heights: set[int] = set()

    def poll(self) -> set[int]:
        from scripts.z01_native_marker_adapter import MARKER

        with self.log.open("rb") as handle:
            handle.seek(self.offset)
            appended = handle.read()
        self.offset += len(appended)
        complete, _, self.partial = (self.partial + appended).rpartition(b"\n")
        self.heights.update(int(match["height"]) for match in MARKER.finditer(complete))
        return self.heights

    def tip(self) -> int:
        return max(self.poll(), default=-1)


async def wait_native(tails: list[NativeTail], height: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        if all(tail.tip() >= height for tail in tails):
            return
        require(time.monotonic() < deadline, f"validators did not finalize H{height} in {timeout} s")
        await asyncio.sleep(0.5)


def proc_start_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    return int(raw.rsplit(b") ", 1)[1].split()[19])


async def capture_attempt(install: Any, network: Any, nodes: list[Any], tails: list[NativeTail],
                          rpcs: list[str], manifest: dict[str, Any], out: Path) -> list[dict[str, Any]]:
    """Pick H ahead of every tip, start each capture after its node logs H-1."""
    from scripts import z01_final_capture as capture
    from scripts import z01_lite_quartet as lite

    tips = [tail.tip() for tail in tails]
    height = max(tips) + manifest["start_lead_heights"]
    window_end = height + manifest["window_heights"] - 1
    write_json(out / "window.json", {"tips": tips, "height": height, "window_end": window_end,
                                     "chosen_wall_ns": time.time_ns()})
    checker = Path(manifest["binaries"]["proof_checker"]["path"])
    zero = network.zerostate.masterchain

    async def one(index: int, node: Any) -> dict[str, Any]:
        node_out = out / node.name
        lite_dir = out / f"{node.name}-lite"
        lite_dir.mkdir()
        lite_config = lite_dir / "lite-client.json"
        lite_config.write_text(node.liteserver_config.to_json())
        deadline = time.monotonic() + manifest["window_timeout_seconds"]
        while height - 1 not in tails[index].poll():
            require(max(tails[index].heights, default=-1) < height,
                    f"{node.name} logged H before H-1 was observed")
            require(time.monotonic() < deadline, f"{node.name} never logged H-1")
            await asyncio.sleep(0.02)
        fds = node.log_stream_fd_binding
        pid = node.process_id
        console = node.engine_console
        row = {
            "name": node.name, "db_root": str(node.directory),
            "governance_window_end_height": window_end,
            "global_config_path": str(node.directory / "config.global.json"),
            "global_config_sha256": sha((node.directory / "config.global.json").read_bytes()),
            "db_config_sha256": sha((node.directory / "config.json").read_bytes()),
            "pid": pid, "start_ticks": proc_start_ticks(pid),
            "exe_sha256": manifest["binaries"]["validator_engine"]["sha256"],
            "rpc_endpoint": rpcs[index], "stderr_pipe_inode": os.fstat(fds["input_fd"]).st_ino,
            "harness_pid": os.getpid(), "log_stream_fds": fds,
            "console_endpoint": console.public_binding()["address"],
            "zerostate_hashes": [zero.root_hash.hex(), zero.file_hash.hex()],
            "window_timeout_seconds": manifest["window_timeout_seconds"],
            "proof_checker_sha256": manifest["binaries"]["proof_checker"]["sha256"],
            "param30_cell_hash": manifest["expected_param_cells"]["30"], "block_bocs": {},
        }

        def block_source(seq: int, exact: tuple) -> dict[str, Any]:
            return lite.fetch_block(Path(manifest["binaries"]["lite_client"]["path"]), lite_config,
                                    exact, lite_dir, f"block-{seq}")

        receipt = await capture.capture_node(row, height, node_out, console, checker,
                                             block_source=block_source)
        cmdline_raw = (node_out / "before-proc-cmdline.raw").read_bytes()
        argv = [os.fsdecode(part) for part in cmdline_raw.split(b"\0") if part]
        require(argv == expected_cmdline(install, node, rpcs[index]),
                f"{node.name} command line differs from the fixed Z01 argv: {argv}")
        for seq_text, exact in receipt["full_ids"].items():
            # Off the event loop shared with the validator log streamers.
            await asyncio.to_thread(lite.fetch_proven_config,
                                    Path(manifest["binaries"]["lite_client"]["path"]), lite_config,
                                    exact, lite_dir, f"config-{seq_text}",
                                    manifest["expected_param_cells"])
            from scripts import z01_chain_capture
            await asyncio.to_thread(z01_chain_capture.capture,
                                    Path(manifest["binaries"]["lite_client"]["path"]),
                                    Path(manifest["binaries"]["chain_checker"]["path"]), lite_config,
                                    zero.root_hash.hex(), zero.file_hash.hex(), zero.file, exact,
                                    node_out / f"block-{seq_text}.boc", lite_dir / f"chain-{seq_text}",
                                    manifest["binaries"]["chain_checker"]["sha256"])
        return receipt

    # Let every node's capture finish (and close its watcher) before any
    # failure is reported, so no capture keeps writing into a failed attempt.
    rows = await asyncio.gather(*(one(index, node) for index, node in enumerate(nodes)),
                                return_exceptions=True)
    errors = [row for row in rows if isinstance(row, BaseException)]
    if errors:
        write_json(out / "attempt-errors.json", [f"{type(error).__name__}: {error}" for error in errors])
        raise errors[0]
    return list(rows)


async def other_param_boc(rpc: str, height: int, out: Path, label: str) -> Path:
    """Fetch a genuine ConfigParam28 cell of the same block as the wrong-Param30 input."""
    from scripts import z01_final_capture as capture

    request = json.dumps({"jsonrpc": "2.0", "id": label, "method": "getConfigParam",
                          "params": {"param": 28, "seqno": height}}, separators=(",", ":")).encode()
    status, response, _, _ = await asyncio.to_thread(capture.http_rpc, rpc, request)
    write_once(out / f"{label}-request.raw", request)
    write_once(out / f"{label}-response.raw", response)
    require(status == 200, f"{label}: HTTP {status}")
    parsed = json.loads(response)
    require(parsed.get("id") == label and parsed.get("error") is None, f"{label}: RPC error")
    raw = base64.b64decode(parsed["result"]["config"]["bytes"], validate=True)
    path = out / f"{label}.boc"
    write_once(path, raw)
    return path


async def proof_controls(receipts: list[dict[str, Any]], rpcs: list[str], manifest: dict[str, Any],
                         out: Path) -> list[dict[str, Any]]:
    from scripts import z01_proof_controls as controls

    verdicts = []
    checker = Path(manifest["binaries"]["proof_checker"]["path"])
    for index, receipt in enumerate(receipts):
        node_out = out / receipt["node"]
        height = receipt["height"]
        exact = receipt["full_ids"][str(height)]
        wrong = await other_param_boc(rpcs[index], height, out, f"{receipt['node']}-param28-{height}")

        def entry(path: Path) -> dict[str, str]:
            return {"path": str(path), "sha256": sha(path.read_bytes())}

        quartet = {"schema": "tos.z01.config30-quartet.v1",
                   "block_id": {"workchain": -1, "shard": 1 << 63, "seqno": height,
                                "root_hash": exact[3], "file_hash": exact[4]},
                   "expected_param30_cell_hash": manifest["expected_param_cells"]["30"],
                   "block_boc": entry(node_out / f"block-{height}.boc"),
                   "state_proof": entry(node_out / f"state-proof-{height}.boc"),
                   "config_proof": entry(node_out / f"config-proof-{height}.boc"),
                   "param30_boc": entry(node_out / f"param30-{height}.boc"),
                   "wrong_param30_boc": entry(wrong),
                   "other_block_state_proof": entry(node_out / f"state-proof-{height + 1}.boc")}
        quartet_path = out / f"{receipt['node']}-quartet.json"
        digest = write_json(quartet_path, quartet)
        verdict = await asyncio.to_thread(
            controls.run_matrix, checker, manifest["binaries"]["proof_checker"]["sha256"],
            quartet_path, digest, out / f"{receipt['node']}-controls")
        require(verdict["passed"], f"{receipt['node']} proof controls failed: {verdict['failures']}")
        verdicts.append(verdict)
    return verdicts


async def live(args: argparse.Namespace) -> int:
    from scripts import z01_final_capture as capture
    from tostester.install import Install
    from tostester.network import StartOptions

    require(args.confirm_network_slot, "live run needs --confirm-network-slot (single local-network slot)")
    manifest = load_precommit(args.precommit, args.precommit_sha256, args.build_dir, args.rehearsal)
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / "invocation.json", {"argv": sys.argv, "pid": os.getpid(), "euid": os.geteuid(),
                                         "precommit_sha256": args.precommit_sha256,
                                         "started_wall_ns": time.time_ns()})
    ports_free(manifest["ports"]["base_port"], manifest["ports"]["rpc_base_port"])
    install = Install(args.build_dir, REPO)
    rpcs = [f"127.0.0.1:{manifest['ports']['rpc_base_port'] + index}" for index in range(VALIDATORS)]
    result: dict[str, Any] = {"status": "failed", "z01_eligible": manifest["z01_eligible"],
                              "final_signed_genesis": False, "attempts": []}
    try:
        network, dht, nodes = build_network(install, out / "network", manifest["ports"]["base_port"],
                                          authenticated_custody(manifest, args))
        async with network:
            result["genesis"] = check_genesis(network, out, manifest["expected_param_cells"])
            await dht.run(StartOptions(threads=1, verbosity=3))
            for index, node in enumerate(nodes):
                await node.run(StartOptions(threads=2, verbosity=3,
                                            args=("--json-rpc-address", rpcs[index])))
            tails = [NativeTail(node.log_path) for node in nodes]
            await wait_native(tails, 3, 180.0)
            receipts = None
            for attempt in range(manifest["capture_attempts"]):
                attempt_out = out / f"attempt-{attempt}"
                attempt_out.mkdir()
                try:
                    receipts = await capture_attempt(install, network, nodes, tails, rpcs, manifest,
                                                     attempt_out)
                    result["attempts"].append({"attempt": attempt, "status": "passed"})
                    break
                except (capture.EvidenceError, RunError, OSError) as exc:
                    result["attempts"].append({"attempt": attempt, "status": "failed",
                                               "error": f"{type(exc).__name__}: {exc}"})
            require(receipts is not None, "no capture attempt produced four node receipts")
            final_out = out / f"attempt-{len(result['attempts']) - 1}"
            result["cluster"] = capture.verify_cluster(receipts)
            write_json(final_out / "cluster.json", result["cluster"])
            verdicts = await proof_controls(receipts, rpcs, manifest, final_out)
            result["controls"] = [{"node": receipt["node"], "block_id": verdict["block_id"],
                                   "passed": verdict["passed"]}
                                  for receipt, verdict in zip(receipts, verdicts)]
        # Network context exit stopped every process; recheck the DB after quiescence.
        result["post_stop"] = []
        for node in nodes:
            require(node.process_id is None, f"{node.name} is still running after network close")
            result["post_stop"].append({"node": node.name,
                                        "override": capture.override_absence(node.directory),
                                        "db_config_sha256": sha((node.directory / "config.json").read_bytes())})
        result["status"] = "passed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        write_json(out / "result.json", result)
        lines = []
        for path in sorted(out.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS":
                if "keyring" in path.parts or path.suffix in (".seed", ".pk", ".key"):
                    continue  # private key material stays out of the index
                lines.append(f"{sha(path.read_bytes())}  {path.relative_to(out)}\n")
        write_once(out / "SHA256SUMS", "".join(lines).encode())
    print(json.dumps({"status": result["status"], "error": result.get("error")}, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("precommit", "genesis-dry-run", "live"):
        sub = commands.add_parser(name)
        sub.add_argument("--build-dir", type=Path, required=True)
        sub.add_argument("--output-dir", type=Path, required=True)
        sub.add_argument("--rehearsal", action="store_true",
                         help="allow a non-Ubuntu-24 host; the receipt is then not Z01-eligible")
        if name == "precommit":
            sub.add_argument("--fixed-inputs", type=Path)
            sub.add_argument("--fixed-inputs-sha256")
            sub.add_argument("--image-id", required=True)
            sub.add_argument("--base-port", type=int, default=DEFAULT_BASE_PORT)
            sub.add_argument("--rpc-base-port", type=int, default=DEFAULT_RPC_BASE_PORT)
            sub.add_argument("--window-heights", type=int, default=5)
            sub.add_argument("--start-lead", type=int, default=8)
            sub.add_argument("--window-timeout", type=int, default=180)
            sub.add_argument("--attempts", type=int, default=3)
        else:
            sub.add_argument("--precommit", type=Path, required=True)
            sub.add_argument("--precommit-sha256", required=True)
            sub.add_argument("--trust-anchor", type=Path, required=True)
            sub.add_argument("--trust-anchor-sha256", required=True)
            sub.add_argument("--signed-inputs", type=Path, required=True)
            sub.add_argument("--signed-inputs-sha256", required=True)
            sub.add_argument("--input-signature", type=Path, required=True)
        if name == "live":
            sub.add_argument("--confirm-network-slot", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "precommit":
            return precommit(args)
        if args.command == "genesis-dry-run":
            return genesis_dry_run(args)
        return asyncio.run(live(args))
    except RunError as exc:
        print(f"Z01_LIVE_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
