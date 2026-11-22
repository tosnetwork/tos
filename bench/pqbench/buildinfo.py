"""How the node under test was built: its allocator, as linked and as configured.

Release node binaries are built with jemalloc, and a validator's speed and memory behaviour
depend on it, so a node without it is not the product. The binary is the evidence; the CMake
cache only says what the last configure asked for.
"""

import logging
import subprocess
from pathlib import Path

ENGINE = "validator-engine/validator-engine"
_TRUE = frozenset(("ON", "1", "TRUE", "YES", "Y"))


def needed_libraries(binary: Path) -> list[str] | None:
    """Shared libraries the binary names as NEEDED, or None when that cannot be read."""
    try:
        out = subprocess.run(
            ["readelf", "-d", str(binary)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    names: list[str] = []
    for line in out.stdout.splitlines():
        if "(NEEDED)" in line and "[" in line and "]" in line:
            names.append(line[line.index("[") + 1 : line.rindex("]")])
    return names


def cmake_cache(build: Path) -> dict[str, str] | None:
    """NAME -> value of the build directory's CMake cache, or None when it cannot be read."""
    try:
        text = (build / "CMakeCache.txt").read_text(errors="replace")
    except OSError:
        return None
    cache: dict[str, str] = {}
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep and ":" in name and not name.startswith(("#", "//")):
            cache[name.split(":", 1)[0]] = value
    return cache


def node_build(build: Path) -> dict[str, object]:
    """The report's `node_build` record.

    `links_jemalloc` is read from the node binary and `configured_jemalloc` from the CMake
    cache; either is None when it could not be determined. `product_allocator` is true only
    when the binary is known to link jemalloc.
    """
    needed = needed_libraries(build / ENGINE)
    links = None if needed is None else any(name.startswith("libjemalloc.so") for name in needed)
    cache = cmake_cache(build)
    setting = None if cache is None else cache.get("TOS_USE_JEMALLOC")
    return {
        "build_type": (cache or {}).get("CMAKE_BUILD_TYPE") or None,
        "configured_jemalloc": None if setting is None else setting.upper() in _TRUE,
        "links_jemalloc": links,
        "product_allocator": links is True,
    }


def warn_unless_product(log: logging.Logger, build: Path, info: dict[str, object]) -> None:
    """Say once, before a run, when the node is not known to be the product build."""
    if info["product_allocator"]:
        return
    if info["links_jemalloc"] is None:
        log.warning(
            "could not tell whether the node in %s links jemalloc (readelf on %s failed); release "
            "binaries do, and a node without it understates the product",
            build,
            ENGINE,
        )
    else:
        log.warning(
            "the node in %s does not link jemalloc; release binaries do, so these results understate "
            "the product: configure with -DTOS_USE_JEMALLOC=ON and rebuild",
            build,
        )
