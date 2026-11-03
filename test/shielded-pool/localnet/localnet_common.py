"""Shared helpers for the shielded client's local end-to-end tooling.

Everything here takes its paths and ports from one `localnet.json` that the
operator of the isolated local network writes; nothing is hard-coded to a host.

Secrets never reach a receipt. A receiving descriptor, a mnemonic, a Vault
master key, a SOCKS credential or a relayer status token can appear in a
command line or in a command's output even though the client's own logs keep
them out, so every receipt is built through `Receipts`, which redacts the
values it has been told about and refuses to write a receipt that still
carries one.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = "tos.shield.localnet.config.v1"
NANOTOS = 10**9
MASTERCHAIN_SHARD = "-9223372036854775808"

JSON = dict[str, Any]


class LocalnetError(Exception):
    """The local network, a command or a receipt is not what the tooling needs."""


class LeakedSecret(LocalnetError):
    """A receipt still carried a value that must not be retained."""


def nanotos(text: str) -> int:
    """Parse a decimal TOS amount into nanotos exactly."""
    match = re.fullmatch(r"(\d+)(?:\.(\d{1,9}))?", text.strip())
    if match is None:
        raise LocalnetError(f"not a TOS amount: {text!r}")
    whole, fraction = match.group(1), (match.group(2) or "").ljust(9, "0")
    return int(whole) * NANOTOS + int(fraction)


def tos_text(amount: int) -> str:
    """Nanotos as the decimal the client prints (trailing zeros dropped)."""
    if amount < 0:
        raise LocalnetError("a negative amount")
    whole, fraction = divmod(amount, NANOTOS)
    if fraction == 0:
        return str(whole)
    return f"{whole}.{fraction:09d}".rstrip("0")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_private_json(path: Path, value: Any) -> None:
    """Write a JSON document readable by its owner only."""
    data = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def rpc(url: str, call: str, **params: Any) -> Any:
    """One JSON-RPC call to a local node, never through a proxy."""
    request = urllib.request.Request(
        url,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": call, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=30) as response:
        result = json.load(response)
    if result.get("error") or "result" not in result:
        raise LocalnetError(f"{call}: {result.get('error', result)}")
    return result["result"]


def stack_int(entry: Any) -> int:
    """An integer off a `runGetMethod` stack, in either encoding the node uses."""
    if isinstance(entry, list) and len(entry) == 2 and entry[0] == "num":
        return int(str(entry[1]), 0)
    if isinstance(entry, dict) and "value" in entry:
        return int(str(entry["value"]), 0)
    raise LocalnetError(f"not an integer stack entry: {entry!r}")


def get_method(url: str, address: str, method: str) -> int:
    result = rpc(url, "runGetMethod", address=address, method=method, stack=[])
    if result.get("exit_code", 0) != 0:
        raise LocalnetError(f"{method} on {address}: exit code {result.get('exit_code')}")
    return stack_int(result["stack"][0])


@dataclasses.dataclass(frozen=True)
class Localnet:
    """Where the isolated network and the tools under test are on this host."""

    root: Path
    rpc_url: str
    tos_root: Path
    python: Path
    tosctl: Path
    provider: Path
    br1_py: Path
    local_ceremony_pool: Path
    proof_verify: Path
    anchor_file: Path
    liteserver_config: Path
    toslib_config: Path
    toslib_library: Path
    genesis_key: Path
    network_json: Path
    ceremony_dir: Path
    phase1_dir: Path
    evidence_root: Path
    socks_port: int
    onion: str
    operator_port: int
    # Which commit and repository path each binary under test was built from,
    # keyed by the index's binary names; written by whoever built them.
    provenance: dict[str, dict[str, str]]

    @classmethod
    def load(cls, path: Path) -> Localnet:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or data.get("schema") != CONFIG_SCHEMA:
            raise LocalnetError(f"{path}: not a {CONFIG_SCHEMA} document")
        fields = {field.name for field in dataclasses.fields(cls)}
        missing = fields - set(data)
        extra = set(data) - fields - {"schema"}
        if missing or extra:
            raise LocalnetError(f"{path}: missing {sorted(missing)}, unexpected {sorted(extra)}")
        values: dict[str, Any] = {}
        for field in dataclasses.fields(cls):
            value = data[field.name]
            if field.type == "Path":
                if not isinstance(value, str) or not Path(value).is_absolute():
                    raise LocalnetError(f"{path}: {field.name} must be an absolute path")
                values[field.name] = Path(value)
            elif field.type == "int":
                if not isinstance(value, int) or not 1 <= value <= 65535:
                    raise LocalnetError(f"{path}: {field.name} must be a port number")
                values[field.name] = value
            elif field.name == "provenance":
                values[field.name] = _provenance(path, value)
            else:
                if not isinstance(value, str) or not value:
                    raise LocalnetError(f"{path}: {field.name} must be a non-empty string")
                values[field.name] = value
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", values["onion"]):
            raise LocalnetError(f"{path}: onion must be a v3 onion name")
        if not re.fullmatch(r"http://127\.0\.0\.1:\d+/.*", values["rpc_url"]):
            raise LocalnetError(f"{path}: rpc_url must be a loopback http URL")
        return cls(**values)

    def network(self) -> JSON:
        return json.loads(self.network_json.read_text())


PROVENANCE_BINARIES = ("tosctl", "br1-native-provider", "tos-proof-verify", "local_ceremony_pool")


def _provenance(path: Path, value: Any) -> dict[str, dict[str, str]]:
    """Every binary under test names the full commit and the repository path
    it was built from; nothing else, nothing missing."""
    if not isinstance(value, dict) or set(value) != set(PROVENANCE_BINARIES):
        raise LocalnetError(f"{path}: provenance must name exactly {list(PROVENANCE_BINARIES)}")
    result: dict[str, dict[str, str]] = {}
    for name, entry in value.items():
        if (
            not isinstance(entry, dict)
            or set(entry) != {"commit", "path"}
            or not isinstance(entry["commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", entry["commit"])
            or not isinstance(entry["path"], str)
            or not entry["path"]
        ):
            raise LocalnetError(f"{path}: provenance of {name} needs a full commit and a path")
        result[name] = {"commit": entry["commit"], "path": entry["path"]}
    return result


@dataclasses.dataclass
class Completed:
    """One finished command: what it was told, what it said and what it cost."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    max_rss_kib: int

    def ok(self) -> bool:
        return self.returncode == 0


# How long a timed-out command's pipes are drained before they are abandoned.
DRAIN_AFTER_TIMEOUT_SECONDS = 5.0


def run_measured(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    cwd: Path | None = None,
    timeout: float = 3600.0,
) -> Completed:
    """Run one command and measure its wall time and peak resident set.

    The child is reaped with `wait4` so that its own resource usage is read,
    not the running maximum over every child this process ever had. It leads
    its own process group, so a timeout kills every descendant that inherited
    the pipes as well; the drain of those pipes is then bounded rather than
    waited for, so a descendant that escaped the group cannot hold the gate."""
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
        start_new_session=True,
    )
    captured: dict[str, bytes] = {}

    def drain(name: str, stream: Any) -> None:
        captured[name] = stream.read()
        stream.close()

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    if stdin is not None and process.stdin is not None:
        try:
            process.stdin.write(stdin)
        except BrokenPipeError:
            pass
        process.stdin.close()

    def kill_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, kill_group)
    timer.start()
    try:
        _, status, usage = os.wait4(process.pid, 0)
    finally:
        timer.cancel()
    process.returncode = -os.WTERMSIG(status) if os.WIFSIGNALED(status) else os.WEXITSTATUS(status)
    # The deadline stays in force while the pipes drain: a command that exits
    # at once but leaves a child holding its output is still bounded by it.
    timed_out = time.monotonic() - started >= timeout
    for reader in readers:
        if not timed_out:
            reader.join(max(0.0, timeout - (time.monotonic() - started)))
            if reader.is_alive():
                timed_out = True
                kill_group()
        if timed_out:
            reader.join(DRAIN_AFTER_TIMEOUT_SECONDS)
    if timed_out:
        kill_group()
        raise LocalnetError(f"timed out after {timeout:.0f} s: {argv[0]}")
    return Completed(
        argv=list(argv),
        returncode=process.returncode,
        stdout=captured.get("stdout", b"").decode(errors="replace"),
        stderr=captured.get("stderr", b"").decode(errors="replace"),
        seconds=time.monotonic() - started,
        max_rss_kib=usage.ru_maxrss,
    )


class Receipts:
    """Builds and writes receipts with every known secret redacted.

    `add_secret(label, value)` registers a value that must not be retained;
    from then on every occurrence in an argument, an output or a parsed field
    is replaced by `<label>`. Writing checks the finished receipt again, so a
    secret that reached it by another route is caught rather than retained.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self._secrets: dict[str, str] = {}
        self._count = 0
        self.written: list[tuple[str, Path, str]] = []

    def add_secret(self, label: str, value: str) -> None:
        if len(value) < 8:
            raise LocalnetError(f"secret {label!r} is too short to redact safely")
        self._secrets[label] = value

    def redact_text(self, text: str) -> str:
        for label, value in sorted(self._secrets.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, f"<{label}>")
        return text

    def redact(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.redact(item) for key, item in value.items()}
        return value

    def check_clean(self, value: Any) -> None:
        text = json.dumps(value, sort_keys=True)
        for label, secret in self._secrets.items():
            if secret in text:
                raise LeakedSecret(f"a receipt carries the {label}")

    def build(
        self,
        name: str,
        *,
        command: Completed | None = None,
        parsed: JSON | None = None,
        facts: JSON | None = None,
        outcome: str = "observed",
    ) -> JSON:
        receipt: JSON = {
            "schema": "tos.shield.localnet.receipt.v1",
            "name": name,
            "utc": utc_now(),
            "outcome": outcome,
            "parsed": self.redact(parsed or {}),
            "facts": self.redact(facts or {}),
        }
        if command is not None:
            receipt["command"] = {
                "argv": self.redact(command.argv),
                "returncode": command.returncode,
                "seconds": round(command.seconds, 3),
                "max_rss_kib": command.max_rss_kib,
                "stdout": self.redact_text(command.stdout),
                "stderr": self.redact_text(command.stderr),
            }
        self.check_clean(receipt)
        return receipt

    def write(self, receipt: JSON) -> Path:
        self.check_clean(receipt)
        self._count += 1
        path = self.directory / f"{self._count:02d}-{receipt['name']}.json"
        write_private_json(path, receipt)
        self.written.append((str(receipt["name"]), path, sha256_file(path)))
        return path
