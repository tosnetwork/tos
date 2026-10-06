#!/usr/bin/env python3
"""Real systemd positive/negative controls for the installer's admission check.

Run as root on the disposable CI VM. Only temporary files below /var/tmp change;
no live TOS unit, wallet, database or published snapshot is touched.
"""
import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--generator", type=Path, required=True)
    args = parser.parse_args()
    repo = args.checkout.resolve()
    spec = importlib.util.spec_from_file_location("admission", repo / "scripts/check-local-pq-resources.py")
    admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admission)
    with tempfile.TemporaryDirectory(prefix="tos-pq-protected-", dir="/var/tmp") as temporary:
        stage = Path(temporary)
        binary = stage / "src" / admission.GENERATOR
        binary.parent.mkdir(parents=True)
        shutil.copy2(args.generator.resolve(), binary)
        build = args.generator.resolve().parent
        admission.check(stage, repo, build)
        print("PASS: compiled generator admitted with ProtectHome and both roots inaccessible", flush=True)
        # This control obeys the resource protocol but deliberately reads the
        # original checkout at runtime. It passes outside the protected unit.
        bad = '''#!/usr/bin/python3
import json, re
from pathlib import Path
repo = Path(REPO_LITERAL)
source = (repo / "crypto/smartcont/tos-shielded-pool-v1.fc").read_text()
fixture = (repo / "tools/shielded-pool-circuit/fixtures/groth16-development.json").read_text()
result = dict(schema="tos.local-pq-runtime-resources.v1", pool_source=source,
              development_fixture=fixture, verifying_key_hex=json.loads(fixture)["verifying_key"]["hex"])
for name in ("deposit_gas_ceiling", "transact_gas_ceiling"):
    result[name] = int(re.findall(r'int '+name+r'\\(\\) asm "(\\d+) PUSHINT', source)[0])
print(json.dumps(dict(ok=True, result=result)))
'''.replace("REPO_LITERAL", repr(str(repo)))
        binary.write_text(bad)
        binary.chmod(0o755)
        unprotected = subprocess.check_output([str(binary)], text=True, timeout=10)
        admission.validate(unprotected, (repo / admission.CONTRACT).read_text(),
                           (repo / admission.FIXTURE).read_text())
        try:
            admission.check(stage, repo, build)
        except ValueError:
            print("PASS: protocol-valid runtime checkout reader refused under identical protection", flush=True)
        else:
            raise AssertionError("a runtime checkout reader was admitted; isolation is ineffective")


if __name__ == "__main__":
    main()
