"""Compile the self-pay Quantum wallet the bench deploys, with the PQ instruction set."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

from pytosiq_core import Cell

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {"quantum": "wallet-quantum-self-pay.fc"}


def build(build_dir: Path, out: Path) -> dict[str, Cell]:
    out.mkdir(parents=True, exist_ok=True)
    func, fift = build_dir / "crypto/func", build_dir / "crypto/fift"
    for tool in (func, fift):
        if not tool.is_file():
            raise FileNotFoundError(f"required compiler not built: {tool}")
    env = dict(os.environ, TOL_STDLIB=str(ROOT / "crypto/smartcont/tol-stdlib"))
    code: dict[str, Cell] = {}
    manifest = {}
    for name, source_name in SOURCES.items():
        source = ROOT / "crypto/smartcont" / source_name
        asm, boc = out / f"{name}.fif", out / f"{name}.boc"
        subprocess.run(
            [str(func), "-SPA", "-o", str(asm), str(ROOT / "crypto/smartcont/stdlib.fc"), str(source)],
            env=env, check=True,
        )
        script = out / f"{name}.run.fif"
        script.write_text(f'"PQ.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n')
        subprocess.run(
            [str(fift), "-I", str(ROOT / "crypto/fift/lib"), "-s", str(script)], check=True
        )
        raw = boc.read_bytes()
        code[name] = Cell.one_from_boc(raw)
        manifest[name] = {
            "source": str(source.relative_to(ROOT)),
            "code_hash": code[name].hash.hex(),
            "boc_sha256": hashlib.sha256(raw).hexdigest(),
        }
    (out / "contracts.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return code
