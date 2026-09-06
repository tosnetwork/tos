import os
import subprocess
import sys
from pathlib import Path
from typing import final

from toslib import ToslibCDLL


@final
class Install:
    def __init__(self, build_dir: Path, source_dir: Path, *, validator_engine: Path | None = None):
        self._build_dir = build_dir.absolute()
        self._source_dir = source_dir.absolute()
        self._toslibjson = None
        self._validator_engine = validator_engine

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
        return self._validator_engine or self.build_dir / "validator-engine/validator-engine"

    @property
    def dht_server_exe(self):
        return self.build_dir / "dht-server/dht-server"

    @property
    def validator_engine_console_exe(self):
        return self.build_dir / "validator-engine-console/validator-engine-console"

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


def run_fift(install: Install, code: str, working_dir: Path):
    script_file = working_dir / "script.fif"
    _ = script_file.write_text(code)

    args = [install.fift_exe]
    for include_dir in install.fift_include_dirs:
        args += ["-I", include_dir]
    args += ["-s", "script.fif"]

    _ = subprocess.run(args, cwd=working_dir, check=True)

    os.remove(script_file)
