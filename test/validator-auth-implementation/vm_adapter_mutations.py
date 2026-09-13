"""Remove native configuration propagation at each actual execution boundary."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from mutation_support import replace_once

ROOT = Path(__file__).resolve().parents[2]


def main(build, fixtures, driver, out):
    build, fixtures, driver = (p.resolve() for p in (build, fixtures, driver))
    folder = build / 'test/validator-auth-implementation'
    report = []
    modules = [
        ('vm', 'test-p0-vm-state-mutant', [
            ('constructor-capability', ', global_capabilities(global_capabilities)', '', 'valid-long-message'),
            ('child-capability', 'new_state.global_capabilities = global_capabilities;', '', 'child-capability'),
        ]),
        ('SmartContract', 'test-p0-vm-adapter-mutant', [
            ('getter-capability', 'config ? static_cast<td::uint64>(config->get_capabilities()) : 0', '0', 'native-getter-capability'),
        ]),
        ('transaction', 'test-p0-transaction-mutant', [
            ('config-capability', 'compute_phase_cfg->global_capabilities = config.get_capabilities();', '', '1024-accept-relay'),
            ('compute-capability', '{}, cfg.global_capabilities', '{}, 0', '1024-accept-relay'),
        ]),
    ]
    with tempfile.TemporaryDirectory(prefix='p0-adapter-') as tmp:
        counter = 0
        for module, target, mutations in modules:
            source = folder / f'mutated-{module}.cpp'
            original = source.read_text()

            def run(text):
                nonlocal counter
                source.write_text(text)
                result = subprocess.run(['cmake', '--build', str(build), '--target', target, '-j2'],
                                        capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError('Native adapter build failed: ' + result.stdout + result.stderr)
                if module == 'transaction':
                    library = folder / ('lib' + target + ('.dylib' if sys.platform == 'darwin' else '.so'))
                    counter += 1
                    command = [sys.executable, str(ROOT / 'test/validator-auth-implementation/check_vm_transactions.py'),
                               '--build', str(build), '--vectors', str(fixtures), '--driver', str(driver),
                               '--emulator', str(library), '--out', str(Path(tmp) / str(counter))]
                else:
                    command = [str(folder / target)]
                    if module == 'SmartContract':
                        command.append(str(fixtures))
                return subprocess.run(command, capture_output=True, text=True)

            try:
                baseline = run(original)
                assert baseline.returncode == 0, baseline.stdout + baseline.stderr
                for name, before, after, label in mutations:
                    result = run(replace_once(original, before, after))
                    if module == 'transaction':
                        assert result.returncode == 1 and "AssertionError: ('" + label + "', {'exit': 6" in result.stderr, (name, result.stderr)
                    else:
                        assert result.returncode == 1 and result.stderr.strip() == 'ASSERTION: ' + label, (name, result.stderr)
                    report.append({'guard': name, 'compiled': True, 'assertion_failed': True})
                    print('KILLED:', name, flush=True)
            finally:
                restored = run(original)
                assert restored.returncode == 0, restored.stdout + restored.stderr
    out.write_text(json.dumps({'native_adapter_mutations': report, 'restored_baselines': True}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'fixtures', 'driver', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    main(args.build, args.fixtures, args.driver, args.out)
