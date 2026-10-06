"""Export the shared state sources with exact dependency pins for mobile builds."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_source_lock(output):
    source = (ROOT / "tosctl/src/Cargo.lock").read_text()
    blocks = source.split("[[package]]")[1:]
    entries = [(tomllib.loads("[[package]]" + block)["package"][0], block) for block in blocks]
    roots = [i for i, (p, _) in enumerate(entries) if p["name"] == "lms-fee-state"]
    if len(roots) != 1:
        raise ValueError("source lock has no unique fee-state package")
    selected = set()
    pending = roots.copy()
    while pending:
        index = pending.pop()
        if index in selected:
            continue
        selected.add(index)
        package = entries[index][0]
        for dependency in package.get("dependencies", []):
            parts = dependency.split()
            version = parts[1] if len(parts) > 1 and parts[1][0].isdigit() else None
            matches = [
                i
                for i, (p, _) in enumerate(entries)
                if p["name"] == parts[0] and (version is None or p["version"] == version)
            ]
            if len(matches) != 1:
                raise ValueError(f"ambiguous source dependency: {dependency}")
            pending.extend(matches)
    text = "# Derived mechanically from the TOS source lock.\nversion = 4\n\n"
    text += "".join("[[package]]" + entries[i][1] for i in sorted(selected))
    (output / "Cargo.lock").write_text(text)
    subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(output / "Cargo.toml"),
            "--offline",
            "--filter-platform",
            "aarch64-linux-android",
            "--format-version",
            "1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    resolved = tomllib.loads((output / "Cargo.lock").read_text())["package"]
    allowed = {(p["name"], p["version"], p.get("checksum")) for p, _ in entries}
    for p in resolved:
        if "source" in p and (p["name"], p["version"], p.get("checksum")) not in allowed:
            raise ValueError(f"resolver selected an unreviewed dependency: {p['name']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = [
        "tosctl/src/lms-fee-state/Cargo.toml",
        "tosctl/src/lms-fee-state/build.rs",
        "tosctl/src/lms-fee-state/src/lib.rs",
        "tosctl/src/lms-fee-state/src/ffi.rs",
        "tosctl/src/lms-fee-state/README.md",
        *[
            f"tosctl/src/node-control/contracts/src/{name}.rs"
            for name in ("lms_fee_schedule", "lms_fee_journal", "lms_fee_cache")
        ],
    ]
    identities = {}
    for name in sources:
        source = ROOT / name
        dest = output / name.removeprefix("tosctl/src/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        identities[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(ROOT / "LICENSE", output / "LICENSE")
    shutil.copyfile(ROOT / "rust-toolchain.toml", output / "rust-toolchain.toml")
    identities["rust-toolchain.toml"] = hashlib.sha256(
        (ROOT / "rust-toolchain.toml").read_bytes()
    ).hexdigest()
    (output / "Cargo.toml").write_text('[workspace]\nmembers = ["lms-fee-state"]\nresolver = "2"\n')
    packages = tomllib.loads((ROOT / "tosctl/src/Cargo.lock").read_text())["package"]
    manifest = output / "lms-fee-state/Cargo.toml"
    text = manifest.read_text()
    for name, prefix, original in [
        ("anyhow", "1.", "1.0"),
        ("fs2", "0.4.", "0.4"),
        ("libc", "0.2.", "0.2"),
        ("sha2", "0.10.", "0.10"),
        ("tempfile", "3.", "3"),
    ]:
        versions = [
            p["version"] for p in packages if p["name"] == name and p["version"].startswith(prefix)
        ]
        if len(versions) != 1:
            raise ValueError(f"ambiguous locked dependency: {name}")
        anchor = f'{name} = "{original}"'
        if text.count(anchor) != 1:
            raise ValueError(f"manifest dependency changed: {name}")
        text = text.replace(anchor, f'{name} = "={versions[0]}"')
    manifest.write_text(text)
    write_source_lock(output)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    (output / "SOURCE-MANIFEST.json").write_text(
        json.dumps(
            {
                "repository": "tosnetwork/tos",
                "starting_head": head,
                "source_sha256": identities,
                "status": "implementation source snapshot, not release approval",
                "manifest_transform": "workspace-local dependencies pinned to the source Cargo.lock",
            },
            indent=2,
        )
        + "\n"
    )
    print(output)


if __name__ == "__main__":
    main()
