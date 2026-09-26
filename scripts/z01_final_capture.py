#!/usr/bin/env python3
"""Retain Z01 final-node Config30 and local override originals.

Call capture_node from the serial Ubuntu 24 harness with its authenticated
EngineConsoleClient. It never starts a node or writes a node DB. A returned
receipt requires an externally retained native-finality manifest as well as
independent proof verification by z01-config-proof-check.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from scripts.z01_native_marker_adapter import MARKER, adapt, read_log_prefix, read_log_tail


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def save(path: Path, raw: bytes) -> str:
    path.write_bytes(raw)
    return sha(raw)


def block_id(value: Any, height: int) -> tuple[int, int, int, str, str]:
    require(isinstance(value, dict), "missing full BlockIdExt")
    try:
        wc = value["workchain"]
        shard = int(value["shard"])
        seqno = value["seqno"]
        root = base64.b64decode(value["root_hash"], validate=True)
        file = base64.b64decode(value["file_hash"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise EvidenceError("malformed full BlockIdExt") from exc
    require(type(wc) is int and wc == -1 and type(seqno) is int and seqno == height,
            "wrong masterchain block height")
    require(shard == -(1 << 63) and len(root) == len(file) == 32 and any(root) and any(file),
            "invalid masterchain shard or zero/short block digest")
    return wc, shard, seqno, root.hex(), file.hex()


def config_provenance(header: dict[str, Any], config: dict[str, Any], height: int) -> tuple[tuple, bytes, bytes, bytes]:
    """Check exact resolved ID and required raw proof shape before native verification."""
    exact = block_id(header.get("id"), height)
    require(block_id(config.get("block_id"), height) == exact,
            "Config30 proof resolved to a different full BlockIdExt")
    require(config.get("@type") == "configInfo", "getConfigParam returned another result")
    cell = config.get("config")
    require(isinstance(cell, dict) and cell.get("@type") == "tvm.cell", "missing Config30 cell")
    try:
        param = base64.b64decode(cell["bytes"], validate=True)
        state = base64.b64decode(config["state_proof"], validate=True)
        proof = base64.b64decode(config["config_proof"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise EvidenceError("missing or malformed Config30/proof bytes") from exc
    require(param and state and proof, "empty Config30 or proof bytes")
    return exact, param, state, proof


def process_snapshot(pid: int, db_root: Path, expected_exe_sha: str,
                     raw_dir: Path, label: str, endpoint: str, global_config: Path,
                     stderr_pipe_inode: int) -> dict[str, Any]:
    require(pid > 1, "invalid node PID")
    stat_raw = Path(f"/proc/{pid}/stat").read_bytes()
    cmd_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    environ_raw = Path(f"/proc/{pid}/environ").read_bytes()
    stat_sha = save(raw_dir / f"{label}-proc-stat.raw", stat_raw)
    cmd_sha = save(raw_dir / f"{label}-proc-cmdline.raw", cmd_raw)
    save(raw_dir / f"{label}-proc-environ.raw", environ_raw)
    environment = environment_policy(environ_raw)
    tail = stat_raw.rsplit(b") ", 1)
    require(len(tail) == 2, "malformed proc stat")
    ticks = int(tail[1].split()[19])  # Linux field 22; tail starts at field 3.
    cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve(strict=True)
    exe = Path(os.readlink(f"/proc/{pid}/exe")).resolve(strict=True)
    require(cwd == db_root.resolve(strict=True), "PID cwd differs from committed node DB")
    exe_sha = sha(exe.read_bytes())
    require(exe_sha == expected_exe_sha, "node executable differs from committed SHA")
    args = [os.fsdecode(part) for part in cmd_raw.split(b"\0") if part]
    def argument(*names: str) -> str:
        for name in names:
            if name in args:
                index = args.index(name)
                require(index + 1 < len(args), f"missing value for {name}")
                return args[index + 1]
        raise EvidenceError(f"node command omits {names[0]}")
    db_arg = argument("--db", "-D")
    config_arg = argument("--global-config", "-C")
    rpc_arg = argument("--json-rpc-address")
    require((cwd / db_arg).resolve(strict=True) == db_root.resolve(strict=True),
            "PID DB argument differs from committed DB")
    require((cwd / config_arg).resolve(strict=True) == global_config.resolve(strict=True),
            "PID global config argument differs from committed config")
    require(rpc_arg == endpoint, "PID RPC listener differs from committed endpoint")
    stderr_fd = os.readlink(f"/proc/{pid}/fd/2")
    require(stderr_fd == f"pipe:[{stderr_pipe_inode}]",
            "validator stderr pipe differs from harness-owned native log stream")
    save(raw_dir / f"{label}-stderr-fd.raw", (stderr_fd + "\n").encode())
    return {
        "pid": pid, "start_ticks": ticks, "proc_stat_sha256": stat_sha,
        "cmdline_sha256": cmd_sha, "environment": environment,
        "cwd": str(cwd), "cwd_dev": cwd.stat().st_dev, "cwd_ino": cwd.stat().st_ino,
        "exe": str(exe), "exe_sha256": exe_sha,
        "stderr_pipe_inode": stderr_pipe_inode,
    }


# Every TOS_* variable the node reads is a test, fault-injection, diagnostic or
# cache knob (for example TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS); none belongs
# in a Z01 final-parameter process, so the whole prefix is refused.
FORBIDDEN_ENV_PREFIX = b"TOS_"


def environment_policy(environ_raw: bytes) -> dict[str, Any]:
    """Reject any local TOS_* runtime knob in one node process environment."""
    require(environ_raw == b"" or environ_raw.endswith(b"\0"), "malformed process environment")
    names = []
    for entry in environ_raw.split(b"\0"):
        if not entry:
            continue
        name, separator, _ = entry.partition(b"=")
        require(bool(separator) and bool(name), "malformed process environment entry")
        names.append(name)
    require(len(names) == len(set(names)), "duplicate process environment name")
    forbidden = sorted(name.decode("ascii", "replace") for name in names
                       if name.startswith(FORBIDDEN_ENV_PREFIX))
    require(not forbidden, f"node environment carries local runtime knobs: {forbidden}")
    return {"names": sorted(name.decode("ascii", "replace") for name in names),
            "environ_sha256": sha(environ_raw)}


def override_absence(db_root: Path) -> dict[str, Any]:
    parent = db_root.stat()
    target = db_root / "noncritical-params-overrides.json"
    try:
        target.lstat()
    except FileNotFoundError as exc:
        require(exc.errno == 2, "unexpected override lstat error")
        return {"path": str(target), "errno": 2, "parent_dev": parent.st_dev,
                "parent_ino": parent.st_ino, "parent_mtime_ns": parent.st_mtime_ns}
    raise EvidenceError("local Simplex override file is present")


def verify_console_binding(binding: dict[str, str] | None, config_raw: bytes,
                           expected_address: str, tcp_raw: bytes,
                           process_fds: dict[str, str]) -> dict[str, Any]:
    """Join authenticated console keys and listener inode to the target node."""
    require(isinstance(binding, dict) and binding.get("address") == expected_address,
            "console address differs from target node")
    host, separator, port_text = expected_address.rpartition(":")
    require(bool(separator) and host == "127.0.0.1" and port_text.isdecimal(),
            "console endpoint is not an explicit IPv4 loopback socket")
    port = int(port_text)
    require(0 < port < 65536, "invalid console port")
    controls = json.loads(config_raw).get("control")
    require(isinstance(controls, list), "node DB lacks control configuration")
    matched = []
    for control in controls:
        if type(control.get("port")) is not int or control["port"] != port:
            continue
        try:
            server = base64.b64decode(control["id"], validate=True).hex()
            clients = [base64.b64decode(row["id"], validate=True).hex()
                       for row in control["allowed"]]
        except (KeyError, TypeError, binascii.Error) as exc:
            raise EvidenceError("malformed node control key IDs") from exc
        if (server == binding.get("server_key_id_hex")
                and binding.get("client_key_id_hex") in clients):
            matched.append(control)
    require(len(matched) == 1, "console authentication keys differ from target DB")
    listeners = set()
    for line in tcp_raw.decode("ascii").splitlines()[1:]:
        fields = line.split()
        require(len(fields) >= 10, "malformed /proc/net/tcp row")
        local, state, inode = fields[1], fields[3], fields[9]
        ip, colon, hex_port = local.partition(":")
        if (colon and ip in ("0100007F", "00000000")
                and int(hex_port, 16) == port and state == "0A"):
            listeners.add(inode)
    require(len(listeners) == 1, "console listening socket is missing or ambiguous")
    inode = next(iter(listeners))
    require(f"socket:[{inode}]" in process_fds.values(),
            "console listener is owned by another process")
    return {"address": expected_address, "server_key_id_hex": binding["server_key_id_hex"],
            "client_key_id_hex": binding["client_key_id_hex"], "socket_inode": inode}


def console_snapshot(console: Any, config_raw: bytes, node: dict[str, Any],
                     out: Path, label: str) -> dict[str, Any]:
    pid = node["pid"]
    tcp_raw = Path("/proc/net/tcp").read_bytes()
    save(out / f"{label}-proc-net-tcp.raw", tcp_raw)
    fds: dict[str, str] = {}
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            fds[fd.name] = os.readlink(fd)
        except FileNotFoundError:
            continue
    save(out / f"{label}-proc-fds.raw", (json.dumps(fds, sort_keys=True) + "\n").encode())
    return verify_console_binding(console.public_binding(), config_raw,
                                  node["console_endpoint"], tcp_raw, fds)


def log_stream_binding(node: dict[str, Any], native_source: dict[str, Any],
                       process: dict[str, Any]) -> dict[str, Any]:
    """Join child stderr pipe to this harness's reader and DB log writer FD."""
    require(node["harness_pid"] == os.getpid(), "native log streamer belongs to another harness")
    fds = node["log_stream_fds"]
    require(type(fds.get("input_fd")) is int and type(fds.get("output_fd")) is int,
            "native log streamer FDs are missing")
    reader = os.fstat(fds["input_fd"])
    writer = os.fstat(fds["output_fd"])
    require(reader.st_ino == process["stderr_pipe_inode"] and stat.S_ISFIFO(reader.st_mode),
            "native log streamer reads another PID pipe")
    require((writer.st_dev, writer.st_ino) == (native_source["dev"], native_source["ino"])
            and stat.S_ISREG(writer.st_mode), "native log streamer writes another file")
    return {"harness_pid": node["harness_pid"], "input_fd": fds["input_fd"],
            "output_fd": fds["output_fd"], "pipe_inode": reader.st_ino,
            "log_dev": writer.st_dev, "log_ino": writer.st_ino}


def require_window_start(native_initial: bytes, initial_tip: Any, height: int) -> tuple:
    """Prove the watcher spoke before H using both native and RPC originals."""
    native_heights = {int(match["height"]) for match in MARKER.finditer(native_initial)}
    require(height - 1 in native_heights, "native log lacks pre-window H-1 marker")
    require(not any(observed >= height for observed in native_heights),
            "native H marker predates override watch window")
    require(isinstance(initial_tip, dict) and type(initial_tip.get("seqno")) is int
            and initial_tip["seqno"] < height, "RPC H tip predates override watch window")
    return block_id(initial_tip, initial_tip["seqno"])


class OverrideWatcher:
    """Watch the already bound DB parent for any override create/write/delete."""

    MASK = 0x00000100 | 0x00000200 | 0x00000080 | 0x00000040 | 0x00000004 | 0x00000008 | 0x00000002 | 0x00000400 | 0x00000800
    LOST = 0x00004000 | 0x00008000 | 0x00000400 | 0x00000800

    def __init__(self, db_root: Path):
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0:
            raise EvidenceError(f"inotify_init1 failed errno={ctypes.get_errno()}")
        self.fd = fd
        self.db_root = db_root
        self.events: list[dict[str, Any]] = []
        self.watch = libc.inotify_add_watch(fd, os.fsencode(db_root), self.MASK)
        if self.watch < 0:
            os.close(fd)
            raise EvidenceError(f"inotify_add_watch failed errno={ctypes.get_errno()}")
        self.started_monotonic_ns = time.monotonic_ns()

    def drain(self) -> None:
        while True:
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            require(raw, "inotify fd closed")
            offset = 0
            while offset < len(raw):
                require(offset + 16 <= len(raw), "truncated inotify event")
                wd, mask, cookie, name_size = struct.unpack_from("iIII", raw, offset)
                end = offset + 16 + name_size
                require(end <= len(raw), "truncated inotify name")
                name = raw[offset + 16:end].split(b"\0", 1)[0]
                self.events.append({"wd": wd, "mask": mask, "cookie": cookie,
                                    "name_hex": name.hex(), "raw_hex": raw[offset:end].hex(),
                                    "read_monotonic_ns": time.monotonic_ns()})
                require(not (mask & self.LOST), "override watcher lost its DB directory")
                require(name != b"noncritical-params-overrides.json", "local override changed during capture")
                offset = end

    def close(self) -> None:
        self.drain()
        os.close(self.fd)


def http_rpc(endpoint: str, request: bytes) -> tuple[int, bytes, int, int]:
    at = time.monotonic_ns()
    req = urllib.request.Request(f"http://{endpoint}/jsonRPC", data=request,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read(), at, time.monotonic_ns()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), at, time.monotonic_ns()


async def capture_node(
    node: dict[str, Any], height: int, out: Path, console: Any, proof_checker: Path,
    rpc: Callable[[str, bytes], tuple[int, bytes, int, int]] = http_rpc,
    block_source: Callable[[int, tuple], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Capture one running node; caller owns its authenticated console client.

    block_source, when given, is called with (height, exact full ID) after that
    height is finalized and must return {"path", "sha256"} for the raw block BOC
    it fetched by that exact ID; otherwise node["block_bocs"] is used.
    """
    out.mkdir(parents=True, exist_ok=False)
    db = Path(node["db_root"]).resolve(strict=True)
    window_end = node["governance_window_end_height"]
    require(type(window_end) is int and height + 2 <= window_end <= height + 256,
            "governance observation window needs at least two later final heads and a bounded end")
    heights = range(height, window_end + 1)
    watcher = OverrideWatcher(db)
    result: dict[str, Any] = {"node": node["name"], "height": height,
                              "governance_window_end_height": window_end,
                              "watch_started_monotonic_ns": watcher.started_monotonic_ns,
                              "watch_descriptor": watcher.watch, "rpc": []}
    try:
        async def query(label: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
            request = json.dumps({"jsonrpc": "2.0", "id": label, "method": method,
                                  "params": params}, separators=(",", ":")).encode()
            status, response, at, completed = await asyncio.to_thread(rpc, node["rpc_endpoint"], request)
            row = {"label": label, "endpoint": node["rpc_endpoint"], "http_status": status,
                   "at_monotonic_ns": at, "completed_monotonic_ns": completed,
                   "request_sha256": save(out / f"{label}-request.raw", request),
                   "response_sha256": save(out / f"{label}-response.raw", response)}
            result["rpc"].append(row)
            watcher.drain()
            require(at <= completed and status == 200, f"{label}: HTTP/clock failure")
            try:
                parsed = json.loads(response)
            except ValueError as exc:
                raise EvidenceError(f"{label}: invalid JSON") from exc
            require(parsed.get("id") == label and parsed.get("error") is None
                    and isinstance(parsed.get("result"), dict), f"{label}: RPC error")
            return parsed["result"]

        # Window start first: only the watcher precedes the native H-1/RPC tip
        # originals, so a slow executable hash or console query cannot let H
        # finalize before the window is proven open. Every later snapshot is
        # still covered by the already running watcher.
        native_at = time.monotonic_ns()
        native_initial, source_initial = read_log_prefix(db / "log", db)
        native_completed = time.monotonic_ns()
        result["native_initial"] = {**source_initial, "at_monotonic_ns": native_at,
                                     "completed_monotonic_ns": native_completed}
        save(out / "native-log-initial.raw", native_initial)
        info = await query("masterchain-info", "getMasterchainInfo", {})
        initial_tip = info.get("last")
        result["initial_tip"] = require_window_start(native_initial, initial_tip, height)
        result["zerostate"] = block_id(info.get("init"), 0)
        require(result["zerostate"][3:] == tuple(node["zerostate_hashes"]),
                "node zerostate differs from committed final Genesis")
        global_config = Path(node["global_config_path"])
        global_raw = global_config.read_bytes()
        require(sha(global_raw) == node["global_config_sha256"],
                "global config differs from committed SHA")
        save(out / "global-config.raw", global_raw)
        first = process_snapshot(node["pid"], db, node["exe_sha256"], out, "before",
                                 node["rpc_endpoint"], global_config, node["stderr_pipe_inode"])
        require(first["start_ticks"] == node["start_ticks"], "wrong process generation")
        result["process_before"] = first
        result["native_stream"] = log_stream_binding(node, source_initial, first)
        result["override_before"] = override_absence(db)
        db_config_raw = (db / "config.json").read_bytes()
        result["db_config_sha256"] = save(out / "db-config.raw", db_config_raw)
        require(result["db_config_sha256"] == node["db_config_sha256"], "DB config changed")
        result["console_before"] = console_snapshot(console, db_config_raw, node, out, "before")
        memory_at = time.monotonic_ns()
        memory, query_raw, reply_raw = await console.get_consensus_noncritical_params_overrides_with_raw()
        memory_completed = time.monotonic_ns()
        require(len(memory.overrides) == 0, "in-memory Simplex override is nonempty")
        result["memory_before"] = {"request_sha256": save(out / "memory-before-request.raw", query_raw),
                                   "reply_sha256": save(out / "memory-before-reply.raw", reply_raw),
                                   "at_monotonic_ns": memory_at, "completed_monotonic_ns": memory_completed}
        timeout = node["window_timeout_seconds"]
        require(type(timeout) is int and 1 <= timeout <= 3600,
                "invalid governance observation timeout")
        deadline = time.monotonic_ns() + timeout * 1_000_000_000
        result["native_polls"] = []
        native_offset = len(native_initial)
        partial_line = native_initial.rsplit(b"\n", 1)[-1]
        while True:
            watcher.drain()
            at = time.monotonic_ns()
            appended = read_log_tail(db / "log", source_initial, native_offset)
            completed = time.monotonic_ns()
            native_offset += len(appended)
            joined = partial_line + appended
            complete, _, partial_line = joined.rpartition(b"\n")
            result["native_polls"].append({"at_monotonic_ns": at,
                                           "completed_monotonic_ns": completed,
                                           "appended_sha256": sha(appended),
                                           "end_offset": native_offset})
            if any(int(match["height"]) >= window_end for match in MARKER.finditer(complete)):
                break
            require(completed < deadline, "native governance window did not finalize before timeout")
            await asyncio.sleep(1)
        native_at = time.monotonic_ns()
        native_raw, native_source = read_log_prefix(db / "log", db)
        native_completed = time.monotonic_ns()
        require((native_source["dev"], native_source["ino"])
                == (source_initial["dev"], source_initial["ino"])
                and native_raw.startswith(native_initial),
                "native log truncated or changed during governance window")
        native = adapt(native_raw, native_source, node=node["name"],
                       pid=first["pid"], start_ticks=first["start_ticks"],
                       db_root=db, first=height, last=window_end)
        finalized_ids = native["ids"]
        result["native_log"] = {**native_source, "pid": first["pid"],
                                "start_ticks": first["start_ticks"],
                                "at_monotonic_ns": native_at,
                                "completed_monotonic_ns": native_completed}
        save(out / "native-log-prefix.raw", native_raw)
        result["native_finality_sha256"] = save(
            out / "native-finality.json", (json.dumps(native, sort_keys=True, indent=2) + "\n").encode())
        headers = {}
        result["full_ids"] = {}
        for seq in heights:
            header = await query(f"header-{seq}", "getBlockHeader",
                                 {"workchain": -1, "shard": str(-(1 << 63)), "seqno": seq})
            exact = block_id(header.get("id"), seq)
            require(exact == tuple(finalized_ids[str(seq)]),
                    "RPC header differs from native finalized full ID")
            headers[seq] = header
            result["full_ids"][str(seq)] = exact
        result["proofs"] = {}
        checker_sha = sha(proof_checker.read_bytes())
        require(checker_sha == node["proof_checker_sha256"], "proof checker binary differs from committed SHA")
        for seq in heights:
            config = await query(f"config30-{seq}", "getConfigParam",
                                 {"param": 30, "seqno": seq, "with_proof": True})
            exact, param, state, config_proof = config_provenance(headers[seq], config, seq)
            # Off the event loop: the harness's validator log streamers share it,
            # and a stalled reader would back-pressure validator stderr.
            source = (node["block_bocs"][str(seq)] if block_source is None
                      else await asyncio.to_thread(block_source, seq, exact))
            require(isinstance(source, dict) and isinstance(source.get("path"), str)
                    and isinstance(source.get("sha256"), str), "block BOC source is malformed")
            block_path = Path(source["path"]).resolve(strict=True)
            block_bytes = block_path.read_bytes()
            require(sha(block_bytes) == source["sha256"] == exact[4],
                    "raw block BOC differs from precommitted or resolved file hash")
            block_path_saved = out / f"block-{seq}.boc"
            block_sha = save(block_path_saved, block_bytes)
            param_path = out / f"param30-{seq}.boc"
            state_path = out / f"state-proof-{seq}.boc"
            config_path = out / f"config-proof-{seq}.boc"
            param_sha = save(param_path, param)
            state_sha = save(state_path, state)
            config_sha = save(config_path, config_proof)
            command = [str(proof_checker), str(exact[0]), str(exact[1] & ((1 << 64) - 1)),
                       str(exact[2]), exact[3], exact[4], str(block_path_saved),
                       str(state_path), str(config_path), str(param_path)]
            proof_at = time.monotonic_ns()
            proof = await asyncio.to_thread(subprocess.run, command, capture_output=True, check=False)
            proof_completed = time.monotonic_ns()
            result["proofs"][str(seq)] = {"command": command, "exit": proof.returncode,
                                         "block_source_path": str(block_path),
                                         "block_boc_sha256": block_sha,
                                         "param30_boc_sha256": param_sha,
                                         "state_proof_sha256": state_sha,
                                         "config_proof_sha256": config_sha,
                                         "at_monotonic_ns": proof_at, "completed_monotonic_ns": proof_completed,
                                         "stdout_sha256": save(out / f"proof-check-{seq}.stdout.raw", proof.stdout),
                                         "stderr_sha256": save(out / f"proof-check-{seq}.stderr.raw", proof.stderr),
                                         "checker_sha256": checker_sha}
            watcher.drain()
            require(proof.returncode == 0, "independent Config30 proof verification failed")
            match = re.fullmatch(rb"Z01_CONFIG_PROOF_OK seqno=(\d+) root=([0-9a-f]{64}) file=([0-9a-f]{64}) param30=([0-9a-f]{64})\n", proof.stdout)
            require(match is not None and int(match[1]) == seq and match[2].decode() == exact[3]
                    and match[3].decode() == exact[4]
                    and match[4].decode() == node["param30_cell_hash"],
                    "proof tool returned a different block or Config30 cell")

        memory_at = time.monotonic_ns()
        memory, query_raw, reply_raw = await console.get_consensus_noncritical_params_overrides_with_raw()
        memory_completed = time.monotonic_ns()
        require(len(memory.overrides) == 0, "in-memory Simplex override changed")
        result["memory_after"] = {"request_sha256": save(out / "memory-after-request.raw", query_raw),
                                  "reply_sha256": save(out / "memory-after-reply.raw", reply_raw),
                                  "at_monotonic_ns": memory_at, "completed_monotonic_ns": memory_completed}
        result["override_after"] = override_absence(db)
        result["console_after"] = console_snapshot(console, db_config_raw, node, out, "after")
        require(result["console_after"] == result["console_before"],
                "console identity or listening socket changed during capture")
        last = process_snapshot(node["pid"], db, node["exe_sha256"], out, "after",
                                node["rpc_endpoint"], global_config, node["stderr_pipe_inode"])
        result["process_after"] = last
        require(last["start_ticks"] == first["start_ticks"] and last["cwd_dev"] == first["cwd_dev"]
                and last["cwd_ino"] == first["cwd_ino"] and last["cmdline_sha256"] == first["cmdline_sha256"]
                and last["environment"] == first["environment"],
                "process generation/DB command changed during capture")
        require(result["override_after"]["parent_dev"] == result["override_before"]["parent_dev"]
                and result["override_after"]["parent_ino"] == result["override_before"]["parent_ino"],
                "override parent changed during capture")
        require(sha((db / "config.json").read_bytes()) == node["db_config_sha256"]
                and sha(global_config.read_bytes()) == node["global_config_sha256"],
                "node config changed during capture")
        watcher.drain()
    finally:
        watcher.close()
    result["watch_events"] = watcher.events
    result["passed"] = True
    save(out / "receipt.json", (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    return result


def verify_cluster(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    require(len(receipts) == 4 and all(row.get("passed") is True for row in receipts),
            "four complete node receipts are required")
    require(len({row["node"] for row in receipts}) == 4, "node name alias")
    require(len({(row["process_before"]["pid"], row["process_before"]["start_ticks"])
                 for row in receipts}) == 4, "process generation alias")
    require(len({(row["process_before"]["cwd_dev"], row["process_before"]["cwd_ino"])
                 for row in receipts}) == 4, "node DB alias")
    require(len({row["rpc"][0]["endpoint"] for row in receipts}) == 4, "RPC endpoint alias")
    require(len({row["console_before"]["socket_inode"] for row in receipts}) == 4,
            "console listening socket alias")
    require(len({row["console_before"]["address"] for row in receipts}) == 4
            and len({row["console_before"]["server_key_id_hex"] for row in receipts}) == 4,
            "console address or server key alias")
    require(len({(row["native_log"]["dev"], row["native_log"]["ino"])
                 for row in receipts}) == 4, "native log inode alias")
    require(len({row["native_log"]["sha256"] for row in receipts}) == 4,
            "native log raw byte alias")
    require(len({row["native_stream"]["pipe_inode"] for row in receipts}) == 4,
            "native stderr pipe alias")
    require(all(row["native_log"]["pid"] == row["process_before"]["pid"]
                and row["native_log"]["start_ticks"] == row["process_before"]["start_ticks"]
                for row in receipts), "native log process generation mismatch")
    require(len({tuple(row["zerostate"]) for row in receipts}) == 1, "validators have different zerostates")
    heights = receipts[0]["full_ids"].keys()
    numeric = sorted(int(height) for height in heights)
    require(len(numeric) >= 3 and numeric == list(range(numeric[0], numeric[-1] + 1))
            and all(row["full_ids"].keys() == heights for row in receipts),
            "missing common finalized heights")
    for height in heights:
        require(len({tuple(row["full_ids"][height]) for row in receipts}) == 1,
                "conflicting full BlockIdExt across validators")
    return {"passed": True, "nodes": [row["node"] for row in receipts],
            "full_ids": receipts[0]["full_ids"]}
