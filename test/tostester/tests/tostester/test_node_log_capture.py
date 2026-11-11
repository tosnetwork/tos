"""Verify the child's actual stderr destination through node startup and shutdown."""

import asyncio
import os
import stat
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from tosapi import tos_api
from tostester.install import Install
from tostester.network import Network, StartOptions


@pytest.mark.parametrize(
    ("direct", "override", "expected_mode"),
    [(True, None, "unset"), (False, None, "1"), (False, "0", "0")],
    ids=["direct-file", "default-pipe", "pipe-with-async-logger"],
)
def test_node_stderr_destination_and_raw_bytes(
    tmp_path: Path, monkeypatch, direct: bool, override: str | None, expected_mode: str
):
    monkeypatch.delenv("TOS_SYNCHRONOUS_STDERR", raising=False)
    executable = tmp_path / "log-writer"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import os, stat, time\n"
        "kind = b'file' if stat.S_ISREG(os.fstat(2).st_mode) else b'pipe'\n"
        "os.write(2, kind + b'\\x00\\xff\\n')\n"
        "from pathlib import Path\n"
        "Path('written').write_text(os.environ.get('TOS_SYNCHRONOUS_STDERR', 'unset'))\n"
        "while not os.path.exists('finish'): time.sleep(0.01)\n"
    )
    executable.chmod(0o700)

    async def run():
        with patch("tostester.network.ToslibEventLoop"):
            install = Mock(spec=Install)
            network = (
                Network(install, tmp_path, direct_node_logs=True)
                if direct
                else Network(install, tmp_path)
            )
            async with network:
                node = network.create_full_node()
                options = (
                    StartOptions(env={"TOS_SYNCHRONOUS_STDERR": override})
                    if override
                    else StartOptions()
                )
                await node._run(executable, tos_api.Engine_validator_config(), None, options)
                if direct:
                    with pytest.raises(RuntimeError, match="directly"):
                        _ = node.log_stream_fd_binding
                    async with asyncio.timeout(5.0):
                        while not (node.directory / "written").exists():
                            await asyncio.sleep(0.01)
                    assert node.log_path.read_bytes() == b"file\x00\xff\n"
                else:
                    binding = node.log_stream_fd_binding
                    assert stat.S_ISFIFO(os.fstat(binding["input_fd"]).st_mode)
                    assert os.path.samestat(os.fstat(binding["output_fd"]), node.log_path.stat())
                (node.directory / "finish").touch()
                assert await node.wait(timeout=5.0) == 0
            assert node.process_id is None
            assert (node.directory / "written").read_text() == expected_mode
            return node.log_path.read_bytes()

    assert asyncio.run(run()) == (b"file" if direct else b"pipe") + b"\x00\xff\n"
