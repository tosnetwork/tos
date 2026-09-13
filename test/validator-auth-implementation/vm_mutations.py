"""Compile real VM instruction guard removals; require their named assertions."""
import argparse
import json
from pathlib import Path
import subprocess
from mutation_support import replace_once

MUTATIONS = [
    ('disabled-instruction-gas', 'st->consume_gas(gas_per_instr);', ''),
    ('version-gate', 'st->get_global_version() < p0_chksign_min_version ||', ''),
    ('capability-gate', '!(st->get_global_capabilities() & p0_capability)', 'false'),
    ('base-and-byte-gas', 'st->consume_gas_chk(p0_chksign_base_gas);', ''),
    ('byte-gas', 'st->consume_gas_chk(static_cast<long long>(length));', ''),
    ('message-upper-bound', 'length > p0_chksign_max_message', 'false'),
    ('root-tag', 'cs.fetch_ulong(32) != 0x76616231', '(cs.fetch_ulong(32), false)'),
    ('root-version', 'cs.fetch_ulong(16) != 1', '(cs.fetch_ulong(16), false)'),
    ('root-hash', 'actual != expected', 'false'),
    ('leaf-kind', 'branch != 0 ||', ''),
    ('leaf-bit-tail', 'cs.size() != length * 8 ||', ''),
    ('leaf-ref-tail', 'cs.size_refs() != 0', 'false'),
    ('branch-length', 'length != expected || count', 'false || count'),
    ('branch-count', 'count != (expected + cap - 1) / cap ||', ''),
    ('signature-bit-boundary', 'signature->size() != 512 ||', ''),
    ('signature-reference', 'signature->size_refs() != 0 ||', ''),
    ('operand-1', '!key->export_bytes(public_key.data(), public_key.size(), false)', '(key->export_bytes(public_key.data(), public_key.size(), false), false)'),
    ('operand-6', 'stack.check_underflow(3);', ''),
]


def main(build, out):
    build = build.resolve()
    folder = build / 'test/validator-auth-implementation'
    source = folder / 'mutated-authops.cpp'
    original = source.read_text()
    report = []

    def run(text):
        source.write_text(text)
        subprocess.run(['cmake', '--build', str(build), '--target', 'test-p0-vm-mutant', '-j2'],
                       check=True, capture_output=True, text=True)
        return subprocess.run([str(folder / 'test-p0-vm-mutant')], capture_output=True, text=True)

    try:
        baseline = run(original)
        assert baseline.returncode == 0, baseline.stderr
        for label, before, after in MUTATIONS:
            result = run(replace_once(original, before, after))
            assert result.returncode == 1 and result.stderr.strip() == 'ASSERTION: ' + label, (label, result.stderr)
            report.append({'guard': label, 'compiled': True, 'assertion_failed': True})
            print('KILLED:', label, flush=True)
    finally:
        restored = run(original)
        assert restored.returncode == 0, restored.stderr
    out.write_text(json.dumps({'native_vm_mutations': report, 'restored_baseline': True}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    main(args.build, args.out)
