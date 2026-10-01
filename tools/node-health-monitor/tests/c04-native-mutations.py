import hashlib, json, pathlib, subprocess

import argparse
parser = argparse.ArgumentParser(description='Compile narrow native C04 mutants, require intended red, restore and require green.')
parser.add_argument('--build-dir', required=True, type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
build = args.build_dir.resolve()
out = root / 'tools/node-health-monitor/evidence/c04-native-actions/raw/mutants'
out.mkdir(parents=True, exist_ok=True)
cases = [
 ('nested-allowance', 'metrics/metrics-collectors.cpp',
  'child_budget.max_resident_bytes -= parent;', 'child_budget.max_resident_bytes -= 0;',
  'test-health-c04-publisher', ['nested'], 'nested second child gets reduced parent allowance'),
 ('refusal-stops-starts', 'metrics/metrics-collectors.cpp',
  'if (error.is_error()) {', 'if (!budget.bounded && error.is_error()) {',
  'test-health-c04-publisher', ['oversize'], 'oversized or too-many-family child refuses before subsequent starts'),
 ('v2-body-refusal', 'metrics/native-core-snapshot.h',
  '(v2 && openmetrics.size() > 1048576)', '(false && openmetrics.size() > 1048576)',
  'test-health-c04-publisher', [], 'v2 oversized refusal'),
 ('lease-retirement', 'metrics/consensus-health.h',
  'entry.closed && entry.holders == 0 &&', 'entry.closed &&',
  'test-health-actions', ['lease'], 'paused duplicate lease prevents retirement and new-key reuse'),
]
receipts = []
for name, relative, before, after, target, args, needle in cases:
    path = root / relative
    original = path.read_bytes()
    source = original.decode()
    assert before in source, name
    mutant = source.replace(before, after, 1 if name == 'nested-allowance' else -1)
    receipt = dict(name=name, source=relative, baseline_sha256=hashlib.sha256(original).hexdigest(),
                   mutant_sha256=hashlib.sha256(mutant.encode()).hexdigest(), expected_assertion=needle)
    try:
        path.write_text(mutant)
        with (out / (name + '-build.log')).open('w') as log:
            receipt['build_exit'] = subprocess.run(['cmake', '--build', str(build), '--target', target, '-j8'], stdout=log, stderr=subprocess.STDOUT).returncode
        assert receipt['build_exit'] == 0, 'mutant must compile: ' + name
        binary = build / 'test/validator/consensus' / target
        result = subprocess.run([str(binary), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        output = result.stdout.decode(errors='replace')
        (out / (name + '-red.log')).write_text(output)
        receipt['test_exit'] = result.returncode
        receipt['intended_assertion_seen'] = needle in output
        assert result.returncode != 0 and needle in output, 'mutant must fail intended assertion: ' + name
    finally:
        path.write_bytes(original)
        with (out / (name + '-restore-build.log')).open('w') as log:
            receipt['restore_build_exit'] = subprocess.run(['cmake', '--build', str(build), '--target', target, '-j8'], stdout=log, stderr=subprocess.STDOUT).returncode
        receipt['restored_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert receipt['restore_build_exit'] == 0 and path.read_bytes() == original
    result = subprocess.run([str(binary), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    (out / (name + '-green.log')).write_bytes(result.stdout)
    receipt['restored_test_exit'] = result.returncode
    assert result.returncode == 0
    receipts.append(receipt)
    (out / 'receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
    print(name + ': compiled mutant red; restored control green', flush=True)
