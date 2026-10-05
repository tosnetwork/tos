"""Prepare an object-only cache without changing the caller's build flags."""

import hashlib
import json
import os
import platform
import re
import shutil
from pathlib import Path

CPU_FIELDS = {
    "vendor_id",
    "cpu family",
    "model",
    "model name",
    "stepping",
    "microcode",
    "flags",
    "Features",
    "CPU implementer",
    "CPU architecture",
    "CPU variant",
    "CPU part",
    "CPU revision",
}


def cpu_signature(cpuinfo: str) -> list[tuple[str, str]]:
    """Ignore clock/core numbering, not instruction sets or processor models."""
    rows = set()
    for line in cpuinfo.splitlines():
        key, separator, value = line.partition(":")
        key = key.strip()
        if separator and key in CPU_FIELDS:
            value = " ".join(value.split())
            if key in {"flags", "Features"}:
                value = " ".join(sorted(set(value.split())))
            rows.add((key, value))
    if not any(key in {"flags", "Features"} and value for key, value in rows):
        raise ValueError("CPU instruction-set identity is unavailable")
    return sorted(rows)


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def cache_settings(
    workspace: Path, temporary: Path, identity: str, profile: str, max_size: str
) -> tuple[dict[str, str], str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", profile):
        raise ValueError("Invalid cache profile")
    if not re.fullmatch(r"[1-9][0-9]*[KMG]?", max_size):
        raise ValueError("Invalid cache size")
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("Invalid host fingerprint")
    prefix = f"tos-native-v1-{profile}-{identity}"
    settings = {
        "CCACHE_DIR": str(temporary / "tos-native-ccache"),
        "CCACHE_CONFIGPATH": str(temporary / "tos-native-ccache.conf"),
        "CCACHE_BASEDIR": str(workspace),
        "CCACHE_COMPILERCHECK": "content",
        "CCACHE_NAMESPACE": prefix,
        "CCACHE_MAXSIZE": max_size,
        "CCACHE_SLOPPINESS": "",
        # Environment initialization happens before early third-party targets
        # and also reaches separately configured signer projects.
        "CMAKE_C_COMPILER_LAUNCHER": "ccache",
        "CMAKE_CXX_COMPILER_LAUNCHER": "ccache",
    }
    if any("\n" in value or "\r" in value for value in settings.values()):
        raise ValueError("Multiline environment value")
    return settings, prefix


def main() -> None:
    if platform.system() != "Linux":
        raise SystemExit("The native cache action supports Linux runners only")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    compilers = {}
    for name in ("cc", "c++", "gcc", "g++", "clang", "clang++", "clang-21", "clang++-21"):
        executable = shutil.which(name)
        if executable:
            resolved = str(Path(executable).resolve())
            if resolved not in compilers:
                compilers[resolved] = file_digest(Path(resolved))
    if not compilers:
        raise SystemExit("No compiler found before cache setup")
    identity = digest(
        {
            "arch": platform.machine(),
            "cpu": cpu_signature(Path("/proc/cpuinfo").read_text()),
            "os": Path("/etc/os-release").read_text(),
            "image": os.environ.get("ImageVersion", "unknown"),
            "compilers": compilers,
        }
    )
    settings, prefix = cache_settings(
        workspace, temporary, identity, os.environ["CACHE_PROFILE"], os.environ["CACHE_MAX_SIZE"]
    )
    # Do not restore ccache configuration from a previous build. In particular,
    # no cached config may introduce sloppy header or time-macro handling.
    Path(settings["CCACHE_CONFIGPATH"]).write_text("sloppiness =\n")
    Path(settings["CCACHE_DIR"]).mkdir(parents=True, exist_ok=True)
    with open(os.environ["GITHUB_ENV"], "a") as stream:
        for key, value in settings.items():
            stream.write(f"{key}={value}\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write(f"prefix={prefix}\n")
        stream.write(f"host-key={identity}\n")
        stream.write(f"directory={settings['CCACHE_DIR']}\n")
    print(f"Object cache: {prefix}; limit: {settings['CCACHE_MAXSIZE']}")
    print("Compiler, optimization, architecture and test flags are unchanged.")


if __name__ == "__main__":
    main()
