#!/usr/bin/env python3
"""Enforce one repository schema input for both Rust generation entry points."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

INPUT = "tosctl/src/tl/codegen/src/input.rs"
BUILD = "tosctl/src/tl/api/build.rs"
MANUAL = "tosctl/src/tl/codegen/src/bin/codegen_test.rs"
POLICY = "tosctl/src/tl/api/tl/codegen.json"


def require(value: bool, detail: str) -> None:
    if not value:
        raise RuntimeError(f"TL_SINGLE_SOURCE_FAILURE: {detail}")


def check(root: Path) -> None:
    fixture_manifest = json.loads((root / "test/tl-cli/binary-fixtures.json").read_text())
    for path in (root / "tosctl").rglob("*"):
        if "target" in path.relative_to(root).parts:
            continue
        if path.suffix == ".tl":
            relative = path.relative_to(root).as_posix()
            require(not path.is_symlink(), "private schema symlink returned")
            require(relative in fixture_manifest, f"private schema returned: {relative}")
            try:
                path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                raise RuntimeError("TL_SINGLE_SOURCE_FAILURE: text replaced a binary TL fixture")
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == fixture_manifest[relative],
                f"pinned binary TL fixture changed: {relative}",
            )
        if path.is_symlink():
            require(
                not path.is_dir() and path.resolve().suffix != ".tl",
                "private schema symlink returned",
            )
    loader = (root / INPUT).read_text()
    require(
        'pub const SCHEMA_DIRECTORY: &str = "tl/generate/scheme";' in loader,
        "authoritative directory changed",
    )
    require(
        'pub const CONFIG_FILE: &str = "tosctl/src/tl/api/tl/codegen.json";' in loader,
        "policy input changed",
    )
    for name in ("lite_api.tl", "tos_api.tl", "toslib_api.tl"):
        require(f'"{name}"' in loader, f"missing input {name}")
        require((root / "tl/generate/scheme" / name).is_file(), f"missing authoritative {name}")
    require("api.ancestors().nth(4)" in loader, "API root resolution changed")
    require("env::" not in loader.split("#[cfg(test)]")[0], "environment-selected schema input")
    require("file.canonicalize()? != file" in loader, "input redirect check missing")
    build = (root / BUILD).read_text()
    require(
        "input::repository_from_api(" in build and "input::load(&root)?" in build,
        "Cargo bypasses fixed loader",
    )
    require("input::generate(source," in build, "Cargo bypasses generation reconciliation")
    require(
        "for file in &source.files" in build and "cargo:rerun-if-changed={}" in build,
        "schema rebuild inputs missing",
    )
    require("source.config_file.display()" in build, "policy rebuild input missing")
    require(
        "read_to_string" not in build and "TL_DIR" not in build, "Cargo has a second input path"
    )
    manual = (root / MANUAL).read_text()
    require(
        "input::generate(tl_codegen::input::load(&root)?," in manual,
        "manual generator bypasses fixed loader",
    )
    require(
        "read_to_string" not in manual and "TL_DIR" not in manual,
        "manual generator has a second input path",
    )
    require(
        json.loads((root / POLICY).read_text())["exclude_types"] == [],
        "schema declarations are excluded",
    )


def self_test(root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="tl-single-source-") as directory:
        fixture = Path(directory)
        for name in (INPUT, BUILD, MANUAL, POLICY, "test/tl-cli/binary-fixtures.json"):
            target = fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, target)
        for name in ("lite_api.tl", "tos_api.tl", "toslib_api.tl"):
            path = fixture / "tl/generate/scheme" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("probe value:int = Probe;\n")
        check(fixture)
        mutations = [
            (
                INPUT,
                '"tosctl/src/tl/api/tl/codegen.json"',
                '"alternate-policy.json"',
                "policy input",
            ),
            (INPUT, '"tl/generate/scheme"', '"private/scheme"', "authoritative directory"),
            (INPUT, "api.ancestors().nth(4)", "api.ancestors().nth(3)", "API root"),
            (INPUT, "file.canonicalize()? != file", "false", "redirect check"),
            (BUILD, "input::load(&root)?", "private_load(&root)?", "Cargo bypasses"),
            (BUILD, "for file in &source.files", "for file in &[]", "schema rebuild"),
            (BUILD, "source.config_file.display()", '"other"', "policy rebuild"),
            (MANUAL, "input::load(&root)?", "private_load(&root)?", "manual generator bypasses"),
        ]
        for name, old, new, expected in mutations:
            path = fixture / name
            before = path.read_text()
            require(old in before, f"stale control anchor: {old}")
            path.write_text(before.replace(old, new, 1))
            try:
                check(fixture)
            except RuntimeError as error:
                require(expected in str(error), f"wrong control failure: {error}")
            else:
                raise RuntimeError(f"TL_CONTROL_SURVIVED: {name} {old}")
            finally:
                path.write_text(before)
        returned = fixture / "tosctl/private.tl"
        for symlink in (False, True):
            if symlink:
                returned.symlink_to(fixture / "tl/generate/scheme/tos_api.tl")
            else:
                returned.write_text("probe value:int = Probe;\n")
            try:
                check(fixture)
            except RuntimeError as error:
                require("private schema" in str(error), "wrong private-copy refusal")
            else:
                raise RuntimeError("TL_COPY_CONTROL_SURVIVED")
            finally:
                returned.unlink()
        directory_link = fixture / "tosctl/schema-link"
        directory_link.symlink_to(fixture / "tl/generate/scheme", target_is_directory=True)
        try:
            check(fixture)
        except RuntimeError as error:
            require("private schema symlink" in str(error), "wrong directory-link refusal")
        else:
            raise RuntimeError("TL_DIRECTORY_COPY_CONTROL_SURVIVED")
        finally:
            directory_link.unlink()
        manifest_path = fixture / "test/tl-cli/binary-fixtures.json"
        entries = json.loads(manifest_path.read_text())
        name = next(iter(entries))
        binary = fixture / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        original = (root / name).read_bytes()
        binary.write_bytes(original + b"damage")
        try:
            check(fixture)
        except RuntimeError as error:
            require(
                "pinned binary TL fixture changed" in str(error), "wrong binary fixture refusal"
            )
        else:
            raise RuntimeError("TL_BINARY_CONTROL_SURVIVED")
        text = b"shadow value:int = Shadow;\n"
        binary.write_bytes(text)
        entries[name] = hashlib.sha256(text).hexdigest()
        manifest_path.write_text(json.dumps(entries))
        try:
            check(fixture)
        except RuntimeError as error:
            require("text replaced a binary" in str(error), "wrong disguised schema refusal")
        else:
            raise RuntimeError("TL_DISGUISED_COPY_CONTROL_SURVIVED")
        binary.write_bytes(original)
        shutil.copyfile(root / "test/tl-cli/binary-fixtures.json", manifest_path)
        check(fixture)
    print("TL_SINGLE_SOURCE_CONTROLS_OK: 13 intended refusals; restored green")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    check(args.root)
    if args.self_test:
        self_test(args.root)
    print("TL_SINGLE_SOURCE_OK: fixed main schema inputs; no Rust schema copies")


if __name__ == "__main__":
    main()
