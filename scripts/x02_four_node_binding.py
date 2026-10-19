#!/usr/bin/env python3
"""Full StageA frozen runtime closure contract, checked only inside a ticket."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

BINARY_PATHS = (
    "crypto/create-state",
    "crypto/pq/tos-pq-consensus-key",
    "utils/generate-random-id",
    "lite-client/lite-client",
    # Authenticates the elected Config34 block from the network's zerostate.
    "lite-client/proof-verify/tos-proof-verify",
    "validator-engine/validator-engine",
    "dht-server/dht-server",
    "validator-engine-console/validator-engine-console",
    "blockchain-explorer/blockchain-explorer",
    "crypto/func",
    "crypto/fift",
    "toslib/libtoslibjson.so",
    "tosctl/pq_pool_stake_order",
)
# One committed binding per run selects its fault scenario and Stage A window:
# P = deterministic partial loss, D = 100% directed isolation. D's fixed fault sequence
# lasts up to about 405 s, so it gets a 900 s primary window; both keep the 600 s tail.
SCENARIO_WINDOWS = {
    "P": {"duration": 420, "settlement_tail": 600},
    "D": {"duration": 900, "settlement_tail": 600},
}
TC_PATH = "/usr/sbin/tc"


def repository_git_common_root():
    """Bind to this checkout's actual Git metadata, including linked worktrees."""
    repo = Path(__file__).resolve().parents[1]
    output = subprocess.check_output(
        [
            "/usr/bin/git",
            "-C",
            str(repo),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        text=True,
        timeout=10,
    )
    return str(Path(output.strip()).resolve(strict=True))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def scenario_windows(binding):
    require(binding.get("scenario") in SCENARIO_WINDOWS, "binding names no known fault scenario")
    return SCENARIO_WINDOWS[binding["scenario"]]


def expected_stage_argv(binding):
    windows = scenario_windows(binding)
    return [
        "--mode",
        "experiment",
        "--stage",
        "a",
        "--build-dir",
        binding["build_root"],
        "--base-port",
        "32600",
        "--rpc-base-port",
        "34600",
        "--duration-seconds",
        str(windows["duration"]),
        "--settlement-tail-seconds",
        str(windows["settlement_tail"]),
        "--sample-interval",
        "5",
        "--output-root",
        binding["stage_output"],
        "--pq-pool-stake-order-binary",
        str(Path(binding["build_root"]) / "tosctl/pq_pool_stake_order"),
    ]


def expected_host_files(binding):
    """Host executables pinned by digest: bwrap always; tc only for the directed scenario."""
    scenario_windows(binding)
    return {
        binding["bwrap_path"],
        *((TC_PATH,) if binding["scenario"] == "D" else ()),
        *(("/usr/sbin/nft",) if binding["scenario"] == "P" else ()),
    }


def verify_binding(binding, host=False):
    require(binding["schema"] == "tos.x02.four-node-binding.v2", "binding schema differs")
    scenario_windows(binding)
    require(
        binding.get("partial_engine") == ("nft-ordinal-v1" if binding["scenario"] == "P" else None),
        "partial fault engine differs from the frozen scenario",
    )
    require(
        re.fullmatch("[0-9a-f]{40}", binding["native_source_sha"]) is not None,
        "native source provenance absent",
    )
    require(
        binding["stage_argv"] == expected_stage_argv(binding),
        "full StageA argv differs from fixed preset",
    )
    require(
        isinstance(binding["host_files"], dict)
        and set(binding["host_files"]) == expected_host_files(binding),
        "pinned host executables differ from the scenario",
    )
    require(binding["python_version"][:2] >= [3, 14], "StageA requires Python at least3.14")
    require(
        Path(binding["interpreter"]).is_absolute()
        and Path(binding["build_root"]).is_absolute()
        and Path(binding["source_root"]).is_absolute(),
        "binding path is not absolute",
    )
    require(
        binding["rootfs_root"] == "/datax/n6-unit-agents/Z02/u24-rootfs"
        and binding["git_common_root"] == repository_git_common_root()
        and binding["bwrap_path"] == "/usr/bin/bwrap",
        "sandbox paths differ from fixed interface",
    )
    require(
        binding["native_source_sha"] == "a075bc51c4e5f949e3c79f36a2cbce8eccb34fce"
        and binding["native_binary_sha256"]
        == "8e370be745db7ee406746ffed6e1bd1cfe57bb104ff1827abde6e2992e838236",
        "native snapshot differs from the frozen a075bc51c source/binary",
    )
    if host:
        for name, receipt in sorted(binding["host_files"].items()):
            require(
                hashlib.sha256(Path(name).read_bytes()).hexdigest() == receipt["sha256"],
                "pinned host executable differs: " + name,
            )
    os_release = Path(binding["rootfs_root"]) / "etc/os-release"
    require('VERSION_ID="24.04"' in os_release.read_text(), "StageA rootfs is not U24")
    files = binding["files"]
    require(isinstance(files, dict) and 0 < len(files) <= 100000, "missing/boundless file closure")
    for relative in BINARY_PATHS:
        require(
            str(Path(binding["build_root"]) / relative) in files,
            "missing StageA binary " + relative,
        )
    require(binding["interpreter"] in files, "interpreter bytes not indexed")
    for relative in (
        "scripts/validator-election-stage-a.py",
        "scripts/x02_stage_a_child.py",
        "scripts/x02_four_node_binding.py",
        "scripts/x01_window_evidence.py",
    ):
        require(
            str(Path(binding["source_root"]) / relative) in files,
            "StageA source/bootstrap bytes not indexed",
        )
    require(
        binding["interpreter_stdlib_root"] in binding["runtime_roots"],
        "interpreter standard library closure absent",
    )
    roots = [
        Path(binding["source_root"]) / "test/tostester/src",
        Path(binding["source_root"]) / "crypto/fift/lib",
        Path(binding["source_root"]) / "crypto/smartcont",
        Path(binding["build_root"]) / "crypto/smartcont",
        *map(Path, binding["dependency_roots"]),
        *map(Path, binding["runtime_roots"]),
    ]
    require(len(binding["dependency_roots"]) > 0, "StageA dependency closure absent")
    for root in roots:
        require(root.is_dir(), "runtime source/package/generated directory absent")
        actual = {str(path) for path in root.rglob("*") if path.is_file()}
        expected = {name for name in files if Path(name).is_relative_to(root)}
        require(actual == expected, "unindexed or absent runtime file")
    for name, receipt in files.items():
        path = Path(name)
        require(
            path.is_absolute() and re.fullmatch("[0-9a-f]{64}", receipt["sha256"]) is not None,
            "invalid frozen file binding",
        )
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode) and info.st_size == receipt["bytes"],
            "frozen runtime path/type/size changed",
        )
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        require(digest.hexdigest() == receipt["sha256"], "frozen runtime SHA differs: " + name)
    require(
        binding["native_binary_sha256"]
        == files[str(Path(binding["build_root"]) / "validator-engine/validator-engine")]["sha256"],
        "native validator binding differs",
    )
    return binding
