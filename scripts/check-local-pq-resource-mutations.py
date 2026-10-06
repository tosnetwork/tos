#!/usr/bin/env python3
"""Compile the production resource reader; require source changes to move it."""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = "tools/shielded-pool-circuit/crosscheck/src/runtime_resources.rs"
CONTRACT = "crypto/smartcont/tos-shielded-pool-v1.fc"
FIXTURE = "tools/shielded-pool-circuit/fixtures/groth16-development.json"


def main():
    with tempfile.TemporaryDirectory(prefix="pq-resources-") as temp:
        root = Path(temp) / "checkout"
        for name in (MODULE, CONTRACT, FIXTURE):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, path)
        harness = Path(temp) / "probe.rs"
        harness.write_text('#[path = ' + json.dumps(str(root / MODULE)) + '] mod resources;\n'
                           'fn main() { println!("{}:{}", resources::gas_ceiling("deposit_gas_ceiling").unwrap(), '
                           'resources::DEVELOPMENT_FIXTURE.len()); }\n')
        binary = Path(temp) / "probe"
        def build():
            subprocess.run(["rustc", "--edition=2021", str(harness), "-o", str(binary)], check=True)
        def output():
            return subprocess.check_output([str(binary)], cwd=temp, text=True).strip()
        build()
        baseline = output()
        hidden = root.with_name("hidden")
        root.rename(hidden)
        try:
            if output() != baseline: raise AssertionError("resource access depends on checkout")
        finally:
            hidden.rename(root)
        source = (root / CONTRACT).read_text()
        altered, count = re.subn(r'(int deposit_gas_ceiling\(\) asm ")(\d+)',
                                 lambda m: m[1] + str(int(m[2]) - 1), source)
        if count != 1: raise AssertionError("gas mutation did not match exactly once")
        (root / CONTRACT).write_text(altered)
        build()
        if output() == baseline: raise AssertionError("contract mutation survived")
        changed = output()
        with (root / FIXTURE).open("a") as handle: handle.write("\n")
        build()
        if output() == changed: raise AssertionError("fixture mutation survived")
        print("PASS: isolated compiled reader; contract mutation; fixture mutation")


if __name__ == "__main__":
    main()
