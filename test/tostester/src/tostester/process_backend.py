"""Process launch backends for multi-process integration networks.

The remote backend deliberately speaks only a command protocol. Provisioning,
host selection and transport (SSH, a scheduler, or a cloud agent) remain the
caller's concern and are not dependencies of consensus tests.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path


class ProcessBackend(ABC):
    @abstractmethod
    async def spawn(
        self,
        node_name: str,
        executable: Path | str,
        args: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        capture_stdout: bool = False,
    ) -> asyncio.subprocess.Process:
        pass

    @abstractmethod
    def manifest(self) -> dict[str, object]:
        pass


class LocalProcessBackend(ProcessBackend):
    async def spawn(
        self,
        node_name: str,
        executable: Path | str,
        args: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        capture_stdout: bool = False,
    ) -> asyncio.subprocess.Process:
        del node_name
        return await asyncio.create_subprocess_exec(
            executable,
            *args,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE if capture_stdout else None,
            stderr=asyncio.subprocess.PIPE,
        )

    def manifest(self) -> dict[str, object]:
        return {"kind": "local-process"}


class RemoteCommandBackend(ProcessBackend):
    """Launch through a caller-supplied command, without prescribing SSH.

    Each inventory value is an argv prefix that eventually invokes
    ``python -m tostester.remote_process`` on the selected host. The remote
    filesystem is expected to expose the paths in the launch specification;
    staging those files belongs to deployment tooling, not this test library.
    """

    def __init__(self, commands: Mapping[str, Sequence[str]], network_profile: str | None = None):
        self._commands = {name: tuple(command) for name, command in commands.items()}
        self._network_profile = network_profile
        if not self._commands or any(not command for command in self._commands.values()):
            raise ValueError("remote-command inventory must contain non-empty commands")

    async def spawn(
        self,
        node_name: str,
        executable: Path | str,
        args: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        capture_stdout: bool = False,
    ) -> asyncio.subprocess.Process:
        try:
            prefix = self._commands[node_name]
        except KeyError as error:
            raise ValueError(f"remote-command inventory has no entry for {node_name}") from error
        specification = {
            "executable": os.fspath(executable),
            "args": list(args),
            "cwd": os.fspath(cwd),
            "env": dict(env),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(specification, separators=(",", ":")).encode()
        ).decode()
        return await asyncio.create_subprocess_exec(
            *prefix,
            "--spec-base64",
            encoded,
            stdout=asyncio.subprocess.PIPE if capture_stdout else None,
            stderr=asyncio.subprocess.PIPE,
        )

    def manifest(self) -> dict[str, object]:
        result: dict[str, object] = {
            "kind": "remote-command",
            "nodes": sorted(self._commands),
            "provisioning": "external",
        }
        if self._network_profile is not None:
            result["network_profile"] = self._network_profile
        return result
