"""Batch ML-DSA-44 signing through the bench signer tool (same backend as the key tool)."""

import subprocess
from pathlib import Path

from contract.pq_auth import CONTEXT

PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420


class BatchSigner:
    def __init__(self, executable: Path, threads: int):
        if not executable.is_file():
            raise FileNotFoundError(f"bench signer not built: {executable}")
        if type(threads) is not int or not 1 <= threads <= 256:
            raise ValueError("signer threads must be 1..256")
        self.executable, self.threads = executable.resolve(), threads

    def _run(self, args: list[str], lines: list[str], size: int) -> list[bytes]:
        if not lines:
            return []
        result = subprocess.run(
            [str(self.executable), *args, "--threads", str(self.threads)],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("bench signer failed: " + result.stderr.strip())
        out = [bytes.fromhex(line) for line in result.stdout.splitlines()]
        if len(out) != len(lines) or any(len(item) != size for item in out):
            raise RuntimeError("bench signer returned a short or malformed batch")
        return out

    def public_keys(self, seeds: list[bytes]) -> list[bytes]:
        return self._run(["public"], [_seed(s).hex() for s in seeds], PUBLIC_KEY_BYTES)

    def sign(self, jobs: list[tuple[bytes, bytes]], context: bytes = CONTEXT) -> list[bytes]:
        lines = []
        for seed, message in jobs:
            if type(message) is not bytes or not 1 <= len(message) <= 8192:
                raise ValueError("message must be 1..8192 bytes")
            lines.append(f"{_seed(seed).hex()} {message.hex()}")
        return self._run(["sign", context.hex()], lines, SIGNATURE_BYTES)


def _seed(seed: bytes) -> bytes:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return seed
