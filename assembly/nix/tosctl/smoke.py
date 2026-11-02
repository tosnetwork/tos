#!/usr/bin/env python3
"""Exercise an installed tosctl as an ordinary user, without a chain or funds."""

import datetime
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

# Checks are explicit raises, never `assert`, so `python3 -O` or PYTHONOPTIMIZE cannot strip
# them; the VM test also runs this file under -O and rejects any assert statement in it.
MODE_MESSAGE = "configuration mode is not 0600"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def expected_version():
    """The commit and source date the package was built from, passed by the VM test."""
    commit = os.environ.get("TOSCTL_EXPECTED_COMMIT")
    epoch = os.environ.get("TOSCTL_EXPECTED_EPOCH")
    require(commit and epoch and epoch.isdigit(), "expected commit and source epoch are required")
    date = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
    return commit, date.strftime("%Y-%m-%d %H:%M:%S +0000")


def main():
    binary = shutil.which("tosctl")
    if binary is None:
        raise RuntimeError("tosctl is not installed")
    require(os.geteuid() != 0, "acceptance must run as an ordinary user")
    commit, commit_date = expected_version()
    environment = dict(os.environ)
    for name in ("CONFIG_PATH", "VAULT_URL"):
        environment.pop(name, None)
    environment["TOKIO_WORKER_THREADS"] = "2"

    with tempfile.TemporaryDirectory(prefix="tosctl-nixos-", dir=Path.home()) as directory:
        work = Path(directory)

        def run(*args, error=None):
            result = subprocess.run(
                [binary, *map(str, args)],
                cwd=work,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            output = result.stdout + result.stderr
            if error is None:
                require(result.returncode == 0, output)
            else:
                require(result.returncode != 0 and error in output, output)
            return output

        def mode_is_private(path):
            require(stat.S_IMODE(path.stat().st_mode) == 0o600, f"{MODE_MESSAGE}: {path}")

        version = dict(
            line.split(": ", 1) for line in run("--version").splitlines() if ": " in line
        )
        require(version.get("COMMIT_ID") == commit, f"COMMIT_ID {version.get('COMMIT_ID')!r}")
        for field in ("COMMIT_DATE", "BUILD_DATE"):
            require(version.get(field) == commit_date, f"{field} {version.get(field)!r}")
        require(version.get("GIT_BRANCH") == "Unknown", f"GIT_BRANCH {version.get('GIT_BRANCH')!r}")
        require("config" in run("--help"), "help lists the config command")
        run("not-a-command", error="unrecognized subcommand")
        config = work / "config.json"
        run("config", "generate", "--output", config)
        require(isinstance(json.loads(config.read_text())["nodes"], dict), "generated nodes")
        mode_is_private(config)
        require(config.stat().st_uid == os.geteuid(), "configuration owner")
        before = config.read_bytes()
        run("config", "generate", "--output", config, error="already exists")
        require(config.read_bytes() == before, "refused overwrite left the file unchanged")

        primary = "http://127.0.0.1:3301/"
        backup = "http://127.0.0.1:3302/"
        run("config", "--config", config, "chain-rpc", "set", "--url", primary)
        run("config", "--config", config, "chain-rpc", "add", "--url", primary)
        run("config", "--config", config, "chain-rpc", "add", "--url", backup)
        urls = json.loads(config.read_text())["chain_rpc"]["urls"]
        require(urls == [primary, backup], f"chain RPC endpoints {urls!r}")
        mode_is_private(config)

        before = config.read_bytes()
        link = work / "linked.json"
        link.symlink_to(config)
        run(
            "config",
            "generate",
            "--output",
            link,
            "--force",
            error="persistence target must be a regular file",
        )
        require(config.read_bytes() == before, "symlink refusal left the target unchanged")
        unsafe = work / "shared"
        unsafe.mkdir()
        unsafe.chmod(0o777)
        run(
            "config",
            "generate",
            "--output",
            unsafe / "config.json",
            error="writable by other users",
        )
        require(not (unsafe / "config.json").exists(), "nothing written to an unsafe directory")
        unsafe.chmod(0o700)
        run("config", "generate", "--output", unsafe / "config.json")
        mode_is_private(unsafe / "config.json")
    print("PASS: installed CLI, configuration persistence, permissions and refusal controls")


if __name__ == "__main__":
    main()
