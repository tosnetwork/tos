"""Batch ML-DSA-44 signing through the bench signer tool (same backend as the key tool)."""

import asyncio
import contextlib
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from contract.pq_auth import CONTEXT

PUBLIC_KEY_BYTES = 1312
SIGNATURE_BYTES = 2420
BATCH_TIMEOUT = 120.0


class SignerProtocol(ABC):
    """The native signer's batch wire format and result checks."""

    @abstractmethod
    def _run(self, args: list[str], lines: list[str], size: int) -> list[bytes]: ...

    @staticmethod
    def _decode(output: str, expected: int, size: int) -> list[bytes]:
        out = [bytes.fromhex(line) for line in output.splitlines()]
        if len(out) != expected or any(len(item) != size for item in out):
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


class BatchSigner(SignerProtocol):
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
            timeout=BATCH_TIMEOUT,
        )
        if result.returncode:
            raise RuntimeError("bench signer failed: " + result.stderr.strip())
        return self._decode(result.stdout, len(lines), size)

    async def run_batch(self, args: list[str], lines: bytes) -> bytes:
        """Run an owned native signer while the network and observers continue running."""
        process = await asyncio.create_subprocess_exec(
            str(self.executable),
            *args,
            "--threads",
            str(self.threads),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        io = asyncio.create_task(process.communicate(lines))
        try:
            stdout, stderr = await asyncio.wait_for(asyncio.shield(io), BATCH_TIMEOUT)
            if process.returncode:
                raise RuntimeError(
                    "bench signer failed: " + stderr.decode(errors="replace").strip()
                )
            return stdout
        finally:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                try:
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(process.wait(), 1)
                finally:
                    if process.returncode is None:
                        with contextlib.suppress(ProcessLookupError):
                            process.kill()
                    await asyncio.wait_for(io, 5)
                    await asyncio.wait_for(process.wait(), 5)


def _seed(seed: bytes) -> bytes:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return seed
