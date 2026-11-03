#!/usr/bin/env python3
"""Build the existing shielded wallet C ABI for supported mobile platforms."""

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TARGETS = {
    "arm64-v8a": ("aarch64-linux-android", "aarch64-linux-android"),
    "armeabi-v7a": ("armv7-linux-androideabi", "armv7a-linux-androideabi"),
    "x86": ("i686-linux-android", "i686-linux-android"),
    "x86_64": ("x86_64-linux-android", "x86_64-linux-android"),
}
TOOLCHAIN = "1.97.1"


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def source_identity(root):
    """Include the builder itself: its flags and packaging affect the artifact."""
    paths = [
        "tools/shielded-pool-mobile",
        "tools/shielded-pool-wallet",
        "tools/shielded-pool-circuit",
        "crypto/poseidon2",
        "tosctl/src/block/src/poseidon2_kat.rs",
        "scripts/build-shielded-mobile.py",
    ]
    return {
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "source_dirty": bool(
            subprocess.check_output(
                ["git", "status", "--porcelain", "--", *paths], cwd=root, text=True
            )
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["ios", "android"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--abi", choices=TARGETS)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    package = root / "tools/shielded-pool-mobile"
    target_dir = args.target_dir.resolve()
    output = args.output.resolve()
    env = dict(os.environ)
    env.setdefault("CARGO_BUILD_JOBS", "2")
    env["IPHONEOS_DEPLOYMENT_TARGET"] = "15.0"
    targets = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"]
    if args.platform == "android":
        if args.abi is None or args.ndk is None:
            parser.error("Android requires --abi and --ndk")
        host = "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
        tools = args.ndk.resolve() / "toolchains/llvm/prebuilt" / host / "bin"
        target, clang = TARGETS[args.abi]
        linker = tools / f"{clang}24-clang"
        if not linker.is_file():
            parser.error(f"NDK API-24 compiler is missing: {linker}")
        env[f"CARGO_TARGET_{target.upper().replace('-', '_')}_LINKER"] = str(linker)
        env[f"CC_{target.replace('-', '_')}"] = str(linker)
        env[f"AR_{target.replace('-', '_')}"] = str(tools / "llvm-ar")
        env[f"CARGO_TARGET_{target.upper().replace('-', '_')}_RUSTFLAGS"] = (
            "-C link-arg=-Wl,-z,max-page-size=16384"
        )
        targets = [target]
    for target in targets:
        run(
            [
                "cargo",
                f"+{TOOLCHAIN}",
                "build",
                "--release",
                "--locked",
                "--manifest-path",
                package / "Cargo.toml",
                "--target",
                target,
                "--target-dir",
                target_dir,
            ],
            cwd=root,
            env=env,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shielded-build-", dir=output.parent) as tmp:
        staging = Path(tmp)
        if args.platform == "android":
            product = staging / "product"
            product.mkdir()
            for name in ["libshielded_pool_mobile.a", "libshielded_pool_mobile.so"]:
                shutil.copyfile(target_dir / targets[0] / "release" / name, product / name)
            shutil.copyfile(
                package / "include/tos_shielded_mobile.h", product / "tos_shielded_mobile.h"
            )
        else:
            combined = staging / "libshielded_sim.a"
            run(
                [
                    "xcrun",
                    "lipo",
                    "-create",
                    target_dir / targets[1] / "release/libshielded_pool_mobile.a",
                    target_dir / targets[2] / "release/libshielded_pool_mobile.a",
                    "-output",
                    combined,
                ]
            )
            frameworks = []
            for name, archive in [
                ("device", target_dir / targets[0] / "release/libshielded_pool_mobile.a"),
                ("simulator", combined),
            ]:
                framework = staging / name / "TOSShielded.framework"
                (framework / "Headers").mkdir(parents=True)
                (framework / "Modules").mkdir()
                shutil.copyfile(archive, framework / "TOSShielded")
                shutil.copyfile(
                    package / "include/tos_shielded_mobile.h",
                    framework / "Headers/tos_shielded_mobile.h",
                )
                (framework / "Modules/module.modulemap").write_text(
                    'framework module TOSShielded { umbrella header "tos_shielded_mobile.h" export * }\n'
                )
                with (framework / "Info.plist").open("wb") as file:
                    plistlib.dump(
                        {
                            "CFBundleIdentifier": "network.tos.shielded",
                            "CFBundleName": "TOSShielded",
                            "CFBundleExecutable": "TOSShielded",
                            "CFBundlePackageType": "FMWK",
                            "CFBundleVersion": "1",
                            "CFBundleShortVersionString": "1.0",
                        },
                        file,
                    )
                frameworks.append(framework)
            product = staging / "TOSShielded.xcframework"
            run(
                [
                    "xcodebuild",
                    "-create-xcframework",
                    "-framework",
                    frameworks[0],
                    "-framework",
                    frameworks[1],
                    "-output",
                    product,
                ]
            )
        provenance = {
            **source_identity(root),
            "rust_toolchain": TOOLCHAIN,
            "targets": targets,
            "files": {
                str(p.relative_to(product)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(product.rglob("*"))
                if p.is_file()
            },
        }
        (product / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
        if output.exists():
            # Replacing build output is allowed only at the explicitly supplied path.
            shutil.rmtree(output)
        shutil.move(product, output)


if __name__ == "__main__":
    main()
