#!/usr/bin/env python3
"""Require that building the tosctl Nix package imports only its fileset, not the repository.

Nix 2.35 evaluates the repository-root flake without copying its tracked tree into the store;
older releases copy all of it (about 800 MB). After a build this checks:

- the running Nix is at least 2.35;
- the package source (a store path) is within SIZE_LIMIT and contains none of the
  repository's excluded paths or sentinels that only a whole-repository import would bring;
- among everything the VM check's derivation needs, the only store path holding this
  repository's sources is that package source.

With --red-control it instead imports the whole repository (builtins.fetchGit of the local
checkout) and requires the same source checks to refuse it.

With --compare-variants it reads the standard and the shielded package derivations and
requires them to be one recipe: the same source, builder, toolchain and metadata, differing
only in the attributes the shielded feature, its wrapper and its material add; the standard
derivation depends on neither the wrapper nor the material.

usage: check-store.py SOURCE_STORE_PATH VM_CHECK_DRV
       check-store.py --red-control
       check-store.py --compare-variants STANDARD_DRV SHIELDED_DRV
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INPUTS = json.loads((ROOT / "assembly/nix/tosctl/inputs.json").read_text())
SIZE_LIMIT = 160 * 1024 * 1024
MINIMUM_NIX = (2, 35)
# Present in the repository, never in the package source.
SENTINELS = ["validator-engine/validator-engine.cpp", "third-party/rocksdb"] + INPUTS["exclude"]
REPOSITORY_MARKER = "tosctl/src/Cargo.toml"
# The derivation attributes the shielded variant may set differently from the standard one.
VARIANT_ATTRIBUTES = {
    "name",
    "pname",
    "cargoBuildFlags",
    "cargoTestFlags",
    "checkFlags",
    "nativeBuildInputs",
    "installCheckPhase",
    "preCheck",
    "postFixup",
    "out",
}
# The build inputs the shielded variant adds, by derivation name.
VARIANT_INPUTS = {"make-shell-wrapper-hook", "tosctl-shield-material"}
MATERIAL_NAME = "tosctl-shield-material"


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def nix(*args):
    return subprocess.run(["nix", *args], check=True, capture_output=True, text=True).stdout


def check_nix_version():
    text = nix("--version")
    match = re.search(r"(\d+)\.(\d+)", text)
    require(match, f"cannot read the Nix version from {text!r}")
    version = (int(match.group(1)), int(match.group(2)))
    require(version >= MINIMUM_NIX, f"Nix {text.strip()} is older than 2.35")
    return text.strip()


def size(path):
    return sum(p.lstat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def check_source(source):
    require(source.is_dir(), f"{source} is not a directory")
    total = size(source)
    require(total <= SIZE_LIMIT, f"package source is {total} bytes, over {SIZE_LIMIT}")
    present = [s for s in SENTINELS if (source / s).exists()]
    require(not present, f"package source contains excluded or repository paths: {present}")
    suffixes = [
        p.relative_to(source).as_posix()
        for suffix in INPUTS["exclude_suffixes"]
        for p in source.rglob("*" + suffix)
    ]
    require(not suffixes, f"package source contains excluded files: {suffixes[:5]}")
    return total


def check_closure(source, drv):
    requisites = nix("path-info", "--recursive", drv).split()
    repository = [p for p in requisites if (Path(p) / REPOSITORY_MARKER).exists()]
    require(
        repository == [str(source)],
        f"repository sources among the VM check's inputs: {repository}, expected [{source}]",
    )
    whole = [p for p in requisites if (Path(p) / SENTINELS[0]).exists()]
    require(not whole, f"a whole-repository import is an input: {whole}")
    return len(requisites)


def red_control():
    imported = nix(
        "eval", "--impure", "--raw", "--expr", f'(builtins.fetchGit "{ROOT}").outPath'
    ).strip()
    try:
        check_source(Path(imported))
    except Failure as error:
        print(f"TOSCTL_NIX_STORE_RED_CONTROL_OK: a whole-repository import is refused ({error})")
        return 0
    print("TOSCTL_NIX_STORE_FAILED: a whole-repository import passed the source checks")
    return 1


def derivation(path):
    """One derivation as `nix derivation show` prints it: the version-4 document of Nix
    2.35 (`derivations` keyed by basename, inputs under `inputs.drvs`) or the older flat one."""
    shown = json.loads(nix("derivation", "show", path))
    shown = shown.get("derivations", shown)
    require(len(shown) == 1, f"{path} is one derivation, found {len(shown)}")
    drv = next(iter(shown.values()))
    drv["input_drvs"] = drv.get("inputs", {}).get("drvs", drv.get("inputDrvs", {}))
    return drv


def drv_name(path):
    return Path(path).name.split("-", 1)[1].removesuffix(".drv")


def compare_variants(standard_path, shielded_path):
    standard, shielded = derivation(standard_path), derivation(shielded_path)
    for key in ("system", "builder", "args"):
        require(standard[key] == shielded[key], f"{key} differs between the variants")
    s_env, v_env = standard["env"], shielded["env"]
    require(set(s_env) <= set(v_env), f"the shielded variant drops {sorted(set(s_env) - set(v_env))}")
    differing = sorted(k for k in s_env if s_env[k] != v_env[k]) + sorted(set(v_env) - set(s_env))
    unexpected = [k for k in differing if k not in VARIANT_ATTRIBUTES]
    require(not unexpected, f"the variants differ in {unexpected}, beyond {sorted(VARIANT_ATTRIBUTES)}")
    for key in ("src", "cargoDeps", "version", "GIT_COMMIT", "SOURCE_DATE_EPOCH", "buildInputs"):
        require(key in s_env, f"the derivation has no {key}")
        require(s_env[key] == v_env[key], f"{key} differs between the variants")
    require("shielded" in v_env["cargoBuildFlags"], "the shielded variant builds the feature")
    require("shielded" not in s_env["cargoBuildFlags"], "the standard variant builds without it")
    standard_inputs = {drv_name(p) for p in standard["input_drvs"]}
    shielded_inputs = {drv_name(p) for p in shielded["input_drvs"]}
    require(standard_inputs <= shielded_inputs, f"the shielded variant drops {standard_inputs - shielded_inputs}")
    added = shielded_inputs - standard_inputs
    require(added == VARIANT_INPUTS, f"the shielded variant adds {sorted(added)}, expected {sorted(VARIANT_INPUTS)}")
    leaked = [k for k, v in s_env.items() if MATERIAL_NAME in str(v) or "wrapProgram" in str(v)]
    require(not leaked, f"the standard variant references the material or wrapper in {leaked}")
    return len(differing), sorted(added)


def main():
    if sys.argv[1:] == ["--red-control"]:
        return red_control()
    if len(sys.argv) == 4 and sys.argv[1] == "--compare-variants":
        try:
            count, added = compare_variants(sys.argv[2], sys.argv[3])
        except (Failure, subprocess.CalledProcessError) as error:
            print(f"TOSCTL_NIX_STORE_FAILED: {error}", file=sys.stderr)
            return 1
        print(
            f"TOSCTL_NIX_VARIANTS_OK: one recipe; {count} attributes differ as the shielded "
            f"feature requires; the shielded variant alone adds {added}"
        )
        return 0
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    source, drv = Path(sys.argv[1]), sys.argv[2]
    try:
        version = check_nix_version()
        total = check_source(source)
        count = check_closure(source, drv)
    except (Failure, subprocess.CalledProcessError) as error:
        print(f"TOSCTL_NIX_STORE_FAILED: {error}", file=sys.stderr)
        return 1
    print(
        f"TOSCTL_NIX_STORE_OK: {version}; package source {total} bytes; {count} build inputs; "
        "no whole-repository import"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
