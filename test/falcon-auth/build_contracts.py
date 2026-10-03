#!/usr/bin/env python3
"""Build deployable module BOCs with the public PQ bindings (no SDK code edits)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'test/auth-extensions'))
from cells import from_boc

SOURCES = {
    'mldsa-module-func': 'mldsa44-auth-module.fc',
    'mldsa-module-tol': 'mldsa44-auth-module.tol',
    'module-func': 'falcon512-auth-module.fc',
    'module-tol': 'falcon512-auth-module.tol',
    'wallet-func': 'wallet-v5-code.fc',
    'wallet-tol': 'wallet-v5.tol',
    'agent': 'agent-account-code.fc',
}


def build_contracts(build, out):
    build, out = Path(build).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TOL_STDLIB=str(ROOT / 'crypto/smartcont/tol-stdlib'))
    manifest = {}
    for name, source_name in SOURCES.items():
        source = ROOT / 'crypto/smartcont' / source_name
        asm, boc = out / f'{name}.fif', out / f'{name}.boc'
        if source.suffix == '.fc':
            cmd = [str(build / 'crypto/func'), '-SPA', '-o', str(asm),
                   str(ROOT / 'crypto/smartcont/stdlib.fc'), str(source)]
        else:
            cmd = [str(build / 'tol/tol'), '-o', str(asm), str(source)]
        subprocess.run(cmd, env=env, check=True)
        script = out / f'{name}.run.fif'
        script.write_text(f'"PQ.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n')
        subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'),
                        '-s', str(script)], check=True)
        raw = boc.read_bytes()
        manifest[name] = {'source': str(source.relative_to(ROOT)),
                          'code_hash': from_boc(raw).hash.hex(),
                          'boc_sha256': hashlib.sha256(raw).hexdigest(),
                          'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                          'compiler_sha256': hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest(),
                          'profile': 'TOS-AUTH-ML-DSA-44-v1' if name.startswith('mldsa-') else 'TOS-FALCON512-PADDED-v1',
                          'state_init': ('global_id:int32 public_key:^canonical1312' if name.startswith('mldsa-') else 'global_id:int32 profile_version:uint16=1 public_key:^canonical897') if 'module' in name else ('AgentAccountState.serialize' if name == 'agent' else 'WalletV5State.serialize')}
    (out / 'contracts.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build_contracts(args.build, args.out)
