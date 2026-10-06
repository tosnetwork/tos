#!/usr/bin/env python3
"""Check generated candidate config loading and a Rust default-fallback mutation."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / 'tosctl/src/executor/src/blockchain_config.rs'
    original = source.read_bytes()
    anchor = b'gas_prices_wc: config.gas_prices(false)?,'
    assert original.count(anchor) == 1
    results = {}

    def run(name, filtered=False):
        command = ['cargo', 'test', '--manifest-path', str(root / 'tosctl/src/Cargo.toml'),
                   '--locked', '-p', 'contracts', '--test', 'chain_gas_envelope_sandbox', '-j', '1']
        if filtered:
            command.append('admission_candidate_executor_loads_the_generated_chain_configuration')
        command += ['--', '--nocapture']
        env = dict(os.environ, TOS_ROOT=str(root), V5R2_ADMISSION_CONFIG_OUT=str(output / (name + '-config.boc')))
        with (output / (name + '.log')).open('wb') as log:
            result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        results[name] = {'command': command, 'returncode': result.returncode}
        return result.returncode

    if run('baseline'):
        raise RuntimeError('baseline failed; no mutation applied')
    try:
        source.write_bytes(original.replace(anchor, b'gas_prices_wc: GasLimitsPrices::default_wc(),'))
        if run('fallback-default', filtered=True) == 0:
            raise RuntimeError('default fallback unexpectedly passed')
        failure = (output / 'fallback-default.log').read_text(errors='replace')
        if 'candidate basechain gas_credit' not in failure or '20000' not in failure or '10000' not in failure:
            raise RuntimeError('mutation failed outside candidate gas loading')
    finally:
        source.write_bytes(original)
        restored = run('restored')
        artifacts = {}
        for path in sorted(output.iterdir()):
            if path.suffix in ('.log', '.boc'):
                data = path.read_bytes()
                artifacts[path.name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        (output / 'results.json').write_text(json.dumps({
            'source': str(source.relative_to(root)), 'source_sha256': hashlib.sha256(original).hexdigest(),
            'runs': results, 'artifacts': artifacts,
            'scope': 'Generated canonical candidate passed directly into Rust BlockchainConfig::with_config; no transaction execution',
        }, indent=2) + '\n')
        if restored:
            raise RuntimeError('restored test failed')


if __name__ == '__main__':
    main()
