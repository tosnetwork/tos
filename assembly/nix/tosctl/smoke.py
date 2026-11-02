#!/usr/bin/env python3
"""Exercise an installed tosctl as an ordinary user, without a chain or funds."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


def main():
    binary = shutil.which("tosctl")
    if binary is None:
        raise RuntimeError("tosctl is not installed")
    assert os.geteuid() != 0, "acceptance must run as an ordinary user"
    environment = dict(os.environ)
    for name in ("CONFIG_PATH", "VAULT_URL"):
        environment.pop(name, None)
    environment["TOKIO_WORKER_THREADS"] = "2"

    with tempfile.TemporaryDirectory(prefix="tosctl-nixos-", dir=Path.home()) as directory:
        work = Path(directory)

        def run(*args, error=None):
            result = subprocess.run(
                [binary, *map(str, args)], cwd=work, env=environment,
                text=True, capture_output=True, timeout=30,
            )
            output = result.stdout + result.stderr
            if error is None:
                assert result.returncode == 0, output
            else:
                assert result.returncode != 0 and error in output, output
            return output

        assert "tosctl" in run("--version")
        assert "config" in run("--help")
        run("not-a-command", error="unrecognized subcommand")
        config = work / "config.json"
        run("config", "generate", "--output", config)
        assert isinstance(json.loads(config.read_text())["nodes"], dict)
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert config.stat().st_uid == os.geteuid()
        before = config.read_bytes()
        run("config", "generate", "--output", config, error="already exists")
        assert config.read_bytes() == before

        primary = "http://127.0.0.1:3301/"
        backup = "http://127.0.0.1:3302/"
        run("config", "--config", config, "chain-rpc", "set", "--url", primary)
        run("config", "--config", config, "chain-rpc", "add", "--url", primary)
        run("config", "--config", config, "chain-rpc", "add", "--url", backup)
        assert json.loads(config.read_text())["chain_rpc"]["urls"] == [primary, backup]
        assert stat.S_IMODE(config.stat().st_mode) == 0o600

        before = config.read_bytes()
        link = work / "linked.json"
        link.symlink_to(config)
        run("config", "generate", "--output", link, "--force",
            error="persistence target must be a regular file")
        assert config.read_bytes() == before
        unsafe = work / "shared"
        unsafe.mkdir()
        unsafe.chmod(0o777)
        run("config", "generate", "--output", unsafe / "config.json",
            error="writable by other users")
        assert not (unsafe / "config.json").exists()
        unsafe.chmod(0o700)
        run("config", "generate", "--output", unsafe / "config.json")
        assert stat.S_IMODE((unsafe / "config.json").stat().st_mode) == 0o600
    print("PASS: installed CLI, configuration persistence, permissions and refusal controls")


if __name__ == "__main__":
    main()
