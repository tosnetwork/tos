import os
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import final

from toslib import ToslibCDLL


@final
class Install:
    def __init__(self, build_dir: Path, source_dir: Path):
        self._build_dir = build_dir.absolute()
        self._source_dir = source_dir.absolute()
        self._toslibjson = None

    @property
    def build_dir(self):
        return self._build_dir

    @property
    def source_dir(self):
        return self._source_dir

    @property
    def fift_exe(self):
        return self.build_dir / "crypto/create-state"

    @property
    def fift_include_dirs(self):
        return [
            self.source_dir / "crypto/fift/lib",
            self.build_dir / "crypto/smartcont",
            self.source_dir / "crypto/smartcont",
        ]

    @property
    def key_helper_exe(self):
        return self.build_dir / "utils/generate-random-id"

    @property
    def validator_engine_exe(self):
        return self.build_dir / "validator-engine/validator-engine"

    @property
    def pq_consensus_key_exe(self):
        return self.build_dir / "crypto/pq/tos-pq-consensus-key"

    @property
    def dht_server_exe(self):
        return self.build_dir / "dht-server/dht-server"

    @property
    def validator_engine_console_exe(self):
        return self.build_dir / "validator-engine-console/validator-engine-console"

    @property
    def lite_client_exe(self):
        return self.build_dir / "lite-client/lite-client"

    @property
    def blockchain_explorer_exe(self):
        return self.build_dir / "blockchain-explorer/blockchain-explorer"

    @property
    def toslibjson(self):
        if self._toslibjson is None:
            if sys.platform.startswith("linux"):
                name = "toslib/libtoslibjson.so"
            elif sys.platform == "darwin":
                name = "toslib/libtoslibjson.dylib"
            else:
                raise RuntimeError(f"Unsupported platform: {sys.platform}")
            self._toslibjson = ToslibCDLL(self.build_dir / name)

        return self._toslibjson


def run_fift(install: Install, code: str, working_dir: Path, *,
             env: dict[str, str] | None = None, retain_script: bool = False):
    script_file = working_dir / "script.fif"
    _ = script_file.write_text(code)

    args = [install.fift_exe]
    for include_dir in install.fift_include_dirs:
        args += ["-I", include_dir]
    args += ["-s", "script.fif"]

    if retain_script:
        (working_dir / "generation.command.json").write_text(json.dumps({
            "argv": [str(arg) for arg in args], "cwd": str(working_dir.resolve()),
            "source_date_epoch": None if env is None else env.get("SOURCE_DATE_EPOCH"),
            "started_wall_ns": time.time_ns(),
        }, sort_keys=True, indent=2) + "\n")
        result = subprocess.run(args, cwd=working_dir, check=False, env=env,
                                capture_output=True)
        (working_dir / "generation.stdout.raw").write_bytes(result.stdout)
        (working_dir / "generation.stderr.raw").write_bytes(result.stderr)
        (working_dir / "generation.exit.raw").write_text(f"{result.returncode}\n")
        result.check_returncode()
    else:
        _ = subprocess.run(args, cwd=working_dir, check=True, env=env)

    if not retain_script:
        os.remove(script_file)
