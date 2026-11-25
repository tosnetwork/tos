#!/usr/bin/env python3
"""Rebuild Service Actor; check or explicitly update the SDK's frozen bytecode.

Every build profile is checked: the native and token rails' release builds and
their test-only builds (see scripts/tos_service_actor_profile.py). Each has two
frozen copies: an SDK constant (named by the profile, in its rail's SDK module,
checked by root cell hash) and the artifact named by its manifest (checked byte
for byte). --write refreshes all of them; the manifests are refreshed by hand,
and scripts/test-tos-service-actor-v1.sh refuses any drift between them.
"""

import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import tos_service_actor_profile as profiles  # noqa: E402

FUNC = Path(os.environ.get("FUNC_PATH", ROOT / "build/crypto/func"))
FIFT = Path(os.environ.get("FIFT_PATH", ROOT / "build/crypto/fift"))
STDLIB = ROOT / "crypto/smartcont/stdlib.fc"
LABELS = {
    profiles.RELEASE: "release",
    profiles.TEST: "test-profile",
    profiles.TOKEN: "token release",
    profiles.TOKEN_TEST: "token test-profile",
}


def encode_artifact(boc: bytes) -> str:
    """The artifact's line format: base64 wrapped at 76 columns, newline-terminated."""
    text = base64.b64encode(boc).decode("ascii")
    return "".join(text[i : i + 76] + "\n" for i in range(0, len(text), 76))


def constant_pattern(name: str) -> re.Pattern:
    return re.compile(rf'pub const {name}: &str = "([A-Za-z0-9+/=]+)";')


def build(name: str, tmp: Path, env: dict) -> tuple[bytes, Path]:
    work = tmp / name
    work.mkdir()
    source = profiles.source_for(name, work / "source", ROOT)
    fift_source = work / "service-actor.fif"
    boc = work / "service-actor.boc"
    subprocess.run(
        [str(FUNC), "-APS", "-W", str(boc), "-o", str(fift_source), str(STDLIB), str(source)],
        cwd=ROOT,
        check=True,
    )
    subprocess.run([str(FIFT), str(fift_source)], cwd=ROOT, env=env, check=True)
    return boc.read_bytes(), boc


def root_hashes(paths: list[Path], tmp: Path, env: dict) -> list[str]:
    hash_script = tmp / "hashes.fif"
    hash_script.write_text("".join(f'"{path}" file>B B>boc hashu . cr ' for path in paths) + "\n")
    return subprocess.run(
        [str(FIFT), str(hash_script)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="replace the embedded SDK bytecode")
    args = parser.parse_args()
    for tool in (FUNC, FIFT):
        if not tool.is_file():
            raise SystemExit(f"missing compiler tool: {tool} (set FUNC_PATH/FIFT_PATH to override)")
    sources = {
        selected["sdk"]: (ROOT / selected["sdk"]).read_text()
        for selected in profiles.PROFILES.values()
    }
    env = os.environ.copy()
    env["FIFTPATH"] = str(ROOT / "crypto/fift/lib")

    generated: dict[str, bytes] = {}
    hashes: dict[str, list[str]] = {}
    embedded: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="service-actor-bytecode-") as raw_tmp:
        tmp = Path(raw_tmp)
        for name, selected in profiles.PROFILES.items():
            match = constant_pattern(selected["sdk_constant"]).search(sources[selected["sdk"]])
            if not match:
                raise SystemExit(f"{selected['sdk_constant']} was not found in Rust source")
            embedded[name] = base64.b64decode(match.group(1), validate=True)
            generated[name], boc = build(name, tmp, env)
            if args.write:
                # The embedded copy is about to be replaced and need not parse.
                hashes[name] = root_hashes([boc], tmp, env)
                continue
            if not embedded[name]:
                raise SystemExit(f"Service Actor {LABELS[name]} bytecode is not embedded")
            embedded_boc = tmp / f"{name}-embedded.boc"
            embedded_boc.write_bytes(embedded[name])
            hashes[name] = root_hashes([boc, embedded_boc], tmp, env)

    if args.write:
        for name, selected in profiles.PROFILES.items():
            text = sources[selected["sdk"]]
            match = constant_pattern(selected["sdk_constant"]).search(text)
            encoded = base64.b64encode(generated[name]).decode("ascii")
            sources[selected["sdk"]] = text[: match.start(1)] + encoded + text[match.end(1) :]
            (ROOT / selected["artifact_base64"]).write_text(encode_artifact(generated[name]))
        for path, text in sources.items():
            (ROOT / path).write_text(text)
        print(
            f"Service Actor bytecode updated (repr_hash={hashes[profiles.RELEASE][0]}, "
            f"test_profile_repr_hash={hashes[profiles.TEST][0]}, "
            f"token_repr_hash={hashes[profiles.TOKEN][0]}, "
            f"token_test_profile_repr_hash={hashes[profiles.TOKEN_TEST][0]})"
        )
        return

    for name, selected in profiles.PROFILES.items():
        label = LABELS[name]
        # BOC containers may legitimately differ in index/CRC flags; the root
        # cell representation hash is the bytecode identity used on chain.
        if len(hashes[name]) != 2 or hashes[name][0] != hashes[name][1]:
            raise SystemExit(
                f"Service Actor {label} bytecode is stale: rebuild {selected['sdk_constant']} "
                f"(generated {len(generated[name])} bytes, embedded {len(embedded[name])} bytes)"
            )
        # The artifact is what the manifest pins, so its exact bytes count.
        artifact = ROOT / selected["artifact_base64"]
        if not artifact.is_file():
            raise SystemExit(f"Service Actor {label} artifact is missing: {artifact}")
        frozen = base64.b64decode(b"".join(artifact.read_bytes().split()), validate=True)
        if frozen != generated[name]:
            raise SystemExit(
                f"Service Actor {label} artifact is stale: the frozen artifact differs from the "
                f"rebuild (generated {len(generated[name])} bytes, frozen {len(frozen)} bytes)"
            )
    for release_name, test_name in profiles.TEST_PAIRS:
        if hashes[release_name][0] == hashes[test_name][0]:
            raise SystemExit(
                f"Service Actor {LABELS[test_name]} bytecode equals the {LABELS[release_name]} "
                "bytecode"
            )
    print(
        f"Service Actor token test-profile bytecode synchronized "
        f"(repr_hash={hashes[profiles.TOKEN_TEST][0]})"
    )
    print(f"Service Actor token bytecode synchronized (repr_hash={hashes[profiles.TOKEN][0]})")
    # The release line comes last and keeps its format: callers read it.
    print(
        f"Service Actor test-profile bytecode synchronized (repr_hash={hashes[profiles.TEST][0]})"
    )
    print(f"Service Actor bytecode synchronized (repr_hash={hashes[profiles.RELEASE][0]})")


if __name__ == "__main__":
    main()
