#!/usr/bin/env python3
"""Bind each live validator PID to the public identity the node itself runs with.

The frozen pre-fault rows are only what is compared against; they are never a source.
For each node the sources are:
- /proc: PID start ticks (before and after, so the process was not replaced), the
  executable's digest, the working directory, which must be the node's data directory,
  and that directory's (dev, ino);
- the node's own runtime config.json in that directory: its PQ validator_id, ADNL ids
  and console port;
- the kernel socket table: the console port's listening socket must be one of this
  PID's descriptors, so an authorization answered on that port came from this process;
- that authorization (retained by Stage A as the node answered it): validator_id,
  algorithm_id, key_id and public key, with key_id re-derived from the public key.

Only public data is read. The consensus seed, keyring and process environment are never
opened: every path read here is one of the named public files below.

Stdlib only, so the coordinator can run it under the fixed host interpreter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
ML_DSA_44 = 1
ML_DSA_44_PUBLIC_KEY_BYTES = 1312
CONFIG_MAX_BYTES = 1 << 20
PROC_TABLE_MAX_BYTES = 4 << 20
TCP_LISTEN = "0A"
# Files this module may open under a node data directory; anything else is refused.
PUBLIC_NODE_FILES = ("config.json",)


class IdentityRefused(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise IdentityRefused(reason)


def read_bounded(path: Path, max_bytes: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= max_bytes,
            f"{path}: not a bounded regular file",
        )
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) == info.st_size, f"{path}: size changed while read")
    return raw


def read_proc_table(path: Path) -> bytes:
    # /proc tables report size 0; read them bounded without a size precheck.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        chunks, total = [], 0
        while chunk := os.read(fd, 1 << 16):
            total += len(chunk)
            require(total <= PROC_TABLE_MAX_BYTES, f"{path}: larger than its bound")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


AUTHORIZATION_NAME = re.compile(r"pq-authorization-(\d+)-validator-([1-4])-query-(\d+)\.json")


def open_contained(root: Path, relative: str, max_bytes: int, expected_sha256: str) -> bytes:
    """Read root/relative only if every component is a real entry inside a canonical root."""
    require(
        isinstance(relative, str) and relative and not relative.startswith("/"),
        f"{relative!r}: not a plain relative path",
    )
    parts = relative.split("/")
    require(
        all(part not in ("", ".", "..") for part in parts),
        f"{relative!r}: not a plain relative path",
    )
    root = Path(root)
    require(
        root.is_absolute() and os.path.realpath(root) == str(root),
        f"{root}: artifact root is not a canonical real directory",
    )
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= max_bytes,
            f"{relative}: not a bounded regular file",
        )
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) == info.st_size, f"{relative}: size changed while read")
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, f"{relative}: digest differs")
    return raw


def authorization_record(
    artifacts_root: Path, provenance: dict, election_id: int, index: int
) -> dict:
    """One retained authorization answer, only from this election's fixed name in the artifacts root."""
    path = Path(provenance["path"])
    match = AUTHORIZATION_NAME.fullmatch(path.name)
    require(
        path.parent == Path(artifacts_root)
        and match is not None
        and int(match[1]) == election_id
        and int(match[2]) == index,
        f"validator {index} authorization path is not this election's artifact",
    )
    record = json.loads(
        open_contained(Path(artifacts_root), path.name, 64 << 10, provenance["sha256"])
    )
    require(
        record.get("validator_index") == index
        and record.get("election_id") == election_id
        and record.get("query_id") == int(match[3]),
        f"validator {index} authorization record belongs elsewhere",
    )
    return record


def derive_key_id(algorithm_id: int, public_key: bytes) -> bytes:
    """key_id = SHA-256(key_id_domain || u16_le(algorithm_id) || public_key) (crypto/pq/pq-consensus.h)."""
    require(
        algorithm_id == ML_DSA_44 and len(public_key) == ML_DSA_44_PUBLIC_KEY_BYTES,
        "only an ML-DSA-44 public key of 1312 bytes has a key_id",
    )
    return hashlib.sha256(KEY_ID_DOMAIN + algorithm_id.to_bytes(2, "little") + public_key).digest()


def start_ticks(stat_raw: bytes) -> int:
    # Field 22; the command name in parentheses may contain spaces.
    return int(stat_raw.rsplit(b") ", 1)[1].split()[19])


def listening_inodes(port: int) -> set[int]:
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            raw = read_proc_table(Path(table))
        except FileNotFoundError:
            continue
        for line in raw.decode("ascii").splitlines()[1:]:
            fields = line.split()
            local, state, inode = fields[1], fields[3], int(fields[9])
            if state == TCP_LISTEN and int(local.rsplit(":", 1)[1], 16) == port and inode > 0:
                inodes.add(inode)
    return inodes


FD_LIMIT = 4096
FD_SCAN_SECONDS = 2.0
TABLE_RECORD_MAX_BYTES = 1 << 20


def socket_inodes(pid: int, limit: int = FD_LIMIT, seconds: float = FD_SCAN_SECONDS) -> set[int]:
    """This PID's socket inodes; refuses more than `limit` descriptors or a scan past `seconds`."""
    inodes, count = set(), 0
    deadline = time.monotonic() + seconds
    with os.scandir(f"/proc/{pid}/fd") as entries:
        for entry in entries:
            count += 1
            require(count <= limit, f"PID {pid} has more than {limit} descriptors")
            require(time.monotonic() < deadline, f"PID {pid} descriptor scan exceeded {seconds}s")
            try:
                target = os.readlink(entry.path)
            except FileNotFoundError:
                continue  # closed while scanned
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(int(target[8:-1]))
    return inodes


def executable_digest(pid: int, expected_sha256: str, expected_bytes: int) -> str:
    """Hash the PID's executable through one open, bounded to the frozen validator size."""
    fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and info.st_size == expected_bytes,
            f"PID {pid} executable is not the frozen validator size",
        )
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, 1 << 20):
            total += len(chunk)
            require(total <= expected_bytes, f"PID {pid} executable grew while read")
            digest.update(chunk)
    finally:
        os.close(fd)
    require(
        total == expected_bytes and digest.hexdigest() == expected_sha256,
        f"PID {pid} executable is not the frozen validator",
    )
    return digest.hexdigest()


def table_records() -> dict:
    """The raw socket tables the listener checks read, retained for an independent audit."""
    records = {}
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            raw = read_proc_table(Path(table))
        except FileNotFoundError:
            continue
        require(len(raw) <= TABLE_RECORD_MAX_BYTES, f"{table} is larger than its record bound")
        records[table] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_b64": base64.b64encode(raw).decode(),
        }
    return records


def public_config(raw: bytes) -> dict:
    config = json.loads(raw)
    pq = config["extraconfig"]["pq_consensus"]
    controller = base64.b64decode(pq["validator_id"], validate=True)
    require(len(controller) == 32, "config.json PQ validator_id is not 256-bit")
    adnl = {base64.b64decode(item["id"], validate=True).hex() for item in config.get("adnl", [])}
    require(all(len(bytes.fromhex(a)) == 32 for a in adnl), "config.json ADNL id is not 256-bit")
    ports = [item["port"] for item in config.get("control", [])]
    require(
        len(ports) == 1 and type(ports[0]) is int and 0 < ports[0] < 65536,
        "config.json must name exactly one console port",
    )
    return {
        "controller_id_hex": controller.hex(),
        "adnl_ids_hex": sorted(adnl),
        "control_port": ports[0],
    }


def capture_node(pid: int, data_dir: Path, exe_sha256: str, exe_bytes: int, rpc_port: int) -> dict:
    """Capture one node's public identity sources; raises if any source is missing.

    The executable must be the frozen validator (size and digest); the capture keeps the
    raw config.json and socket tables so an audit can recompute every ownership claim.
    """
    require(type(pid) is int and pid > 0, "PID is not a positive integer")
    proc = Path(f"/proc/{pid}")
    stat_raw = read_proc_table(proc / "stat")
    directory = Path(data_dir).resolve(strict=True)
    require(
        (proc / "cwd").resolve(strict=True) == directory,
        "process working directory is not the node data directory",
    )
    exe_digest = executable_digest(pid, exe_sha256, exe_bytes)
    db = os.stat(directory)
    config_raw = read_bounded(directory / PUBLIC_NODE_FILES[0], CONFIG_MAX_BYTES)
    config = public_config(config_raw)
    require(type(rpc_port) is int and 0 < rpc_port < 65536, "RPC port is not a TCP port")
    tables = table_records()
    listeners = listening_inodes(config["control_port"])
    rpc_listeners = listening_inodes(rpc_port)
    owned = socket_inodes(pid)
    return {
        "pid": pid,
        "start_ticks": start_ticks(stat_raw),
        "exe_sha256": exe_digest,
        "exe_bytes": exe_bytes,
        "data_dir": str(directory),
        "db_dev": db.st_dev,
        "db_ino": db.st_ino,
        "config_sha256": hashlib.sha256(config_raw).hexdigest(),
        **config,
        "config_raw_b64": base64.b64encode(config_raw).decode(),
        "socket_tables": tables,
        "socket_inodes": sorted(owned),
        "control_listener_inodes": sorted(listeners),
        "owns_control_listener": bool(listeners) and listeners <= owned,
        "rpc_port": rpc_port,
        "rpc_listener_inodes": sorted(rpc_listeners),
        "owns_rpc_listener": bool(rpc_listeners) and rpc_listeners <= owned,
    }


def authorization_identity(record: dict) -> dict:
    """The node's own answer to a PQ stake authorization, as Stage A retained it."""
    public_key = bytes.fromhex(record["public_key_hex"])
    key_id = bytes.fromhex(record["key_id_hex"])
    require(
        key_id == derive_key_id(record["algorithm_id"], public_key),
        "authorization key_id does not derive from its public key",
    )
    return {
        "controller_id_hex": record["validator_id_hex"].lower(),
        "consensus_key_id_hex": key_id.hex(),
        "control_port": record["control_port"],
        "node_pid": record["node_pid"],
        "node_start_ticks": record["node_start_ticks"],
    }


def verify_live_identity(
    before: list[dict], after: list[dict], authorizations: list[dict], frozen_rows: list[dict]
) -> list[dict]:
    """Return the four PID-to-identity bindings, or refuse."""
    require(
        len(before) == len(after) == len(authorizations) == len(frozen_rows) == 4,
        "four captures, authorizations and frozen rows are required",
    )
    bound = []
    for first, last, record in zip(before, after, authorizations):
        auth = authorization_identity(record)
        require(
            first["pid"] == last["pid"] == auth["node_pid"]
            and first["start_ticks"] == last["start_ticks"] == auth["node_start_ticks"],
            f"PID {first['pid']} was replaced or the authorization came from another process",
        )
        require(
            first["exe_sha256"] == last["exe_sha256"]
            and first["config_sha256"] == last["config_sha256"]
            and (first["db_dev"], first["db_ino"]) == (last["db_dev"], last["db_ino"]),
            f"PID {first['pid']} executable, config or DB changed during the run",
        )
        require(
            first["owns_control_listener"]
            and last["owns_control_listener"]
            and auth["control_port"] == first["control_port"],
            f"PID {first['pid']} does not own the console port that answered its authorization",
        )
        require(
            first["owns_rpc_listener"]
            and last["owns_rpc_listener"]
            and first["rpc_port"] == last["rpc_port"],
            f"PID {first['pid']} does not own its frozen RPC endpoint",
        )
        require(
            auth["controller_id_hex"] == first["controller_id_hex"],
            f"PID {first['pid']} authorization validator_id differs from its own config",
        )
        bound.append(
            {
                "pid": first["pid"],
                "start_ticks": first["start_ticks"],
                "db": (first["db_dev"], first["db_ino"]),
                "controller_id_hex": auth["controller_id_hex"],
                "consensus_key_id_hex": auth["consensus_key_id_hex"],
                "adnl_ids_hex": set(first["adnl_ids_hex"]),
            }
        )
    require(len({row["pid"] for row in bound}) == 4, "two validators share one PID")
    require(len({row["db"] for row in bound}) == 4, "two validators share one DB directory")
    for field in ("controller_id_hex", "consensus_key_id_hex"):
        require(len({row[field] for row in bound}) == 4, f"two PIDs report the same {field}")
    result = []
    for row, frozen in zip(bound, frozen_rows):
        require(
            row["controller_id_hex"] == frozen["controller_id_hex"].lower()
            and row["consensus_key_id_hex"] == frozen["consensus_key_id_hex"].lower()
            and frozen["adnl_id_hex"].lower() in row["adnl_ids_hex"],
            f"PID {row['pid']} live identity differs from frozen row {frozen.get('validator_index')}",
        )
        result.append(
            {
                "pid": row["pid"],
                "start_ticks": row["start_ticks"],
                "db_dev": row["db"][0],
                "db_ino": row["db"][1],
                "controller_id_hex": row["controller_id_hex"],
                "consensus_key_id_hex": row["consensus_key_id_hex"],
                "adnl_id_hex": frozen["adnl_id_hex"].lower(),
            }
        )
    return result
