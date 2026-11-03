"""A process that inherits a node's log pipe must not hold the harness after the node exited."""

import asyncio
import os
import signal
import time
from pathlib import Path

from tostester.log_streamer import LogStreamer


async def _stream(tmp_path: Path, script: str, timeout: float) -> tuple[bool, float, bytes, int]:
    process = await asyncio.create_subprocess_exec(
        "bash", "-c", script, stderr=asyncio.subprocess.PIPE
    )
    assert process.stderr is not None
    log = tmp_path / "log"
    with open(log, "wb") as file:
        streamer = LogStreamer(file, "node", process.stderr)
        # Process.wait() would itself wait for the pipe; the child is reaped first.
        while process.returncode is None:
            await asyncio.sleep(0.05)
        code = process.returncode
        started = time.monotonic()
        drained = await streamer.aclose(timeout=timeout)
        elapsed = time.monotonic() - started
    return drained, elapsed, log.read_bytes(), code


def test_a_clean_exit_drains_the_whole_log(tmp_path: Path):
    drained, elapsed, content, code = asyncio.run(
        _stream(tmp_path, "echo first >&2; echo second >&2; exit 3", timeout=10.0)
    )
    assert code == 3
    assert drained is True
    assert elapsed < 5.0
    assert content == b"first\nsecond\n"


def test_a_descendant_holding_the_pipe_is_cut_after_the_bound(tmp_path: Path):
    pid_file = tmp_path / "pid"
    # The background sleep inherits the pipe and outlives the process that exits.
    script = f"echo first >&2; sleep 60 & echo $! > {pid_file}; exit 1"
    try:
        drained, elapsed, content, code = asyncio.run(_stream(tmp_path, script, timeout=0.5))
    finally:
        if pid_file.exists():
            os.kill(int(pid_file.read_text()), signal.SIGKILL)
    assert code == 1
    assert drained is False
    assert elapsed < 5.0
    assert content == b"first\n"
