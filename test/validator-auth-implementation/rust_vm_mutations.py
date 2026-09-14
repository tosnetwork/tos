"""Falsify Rust VM guards against the independently generated native transcript."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OPCODE_START = 'pub(super) fn execute_p0_chksign('
OPCODE_END = 'fn native_gate('
MUTATIONS = [
    ('disabled-gas', 'engine.try_use_gas(Gas::basic_gas_price(0, 0))?;', ''),
    ('version', 'engine.block_version() < 16 ||', ''),
    ('capability', '!engine.check_capabilities(CAPABILITY)', 'false'),
    ('base-gas', 'engine.try_use_gas(BASE_GAS)?;', ''),
    ('byte-gas', 'engine.try_use_gas(size as i64)?;', ''),
    ('message-bound', 'size > MAX_MESSAGE', 'false'),
    ('root-tag', 'slice.get_next_u32()? != 0x76616231', '{ slice.get_next_u32()?; false }'),
    ('root-version', 'slice.get_next_u16()? != 1', '{ slice.get_next_u16()?; false }'),
    ('root-hash', 'sha256_digest(&output).as_slice() != hash', 'false'),
    ('leaf-kind', 'if branch {', 'if false {'),
    ('leaf-length', 'size != expected ||', ''),
    ('leaf-bits', 'slice.remaining_bits() != size * 8 ||', ''),
    ('branch-length', 'length != expected ||', ''),
    ('branch-count', 'count != expected.div_ceil(cap) ||', ''),
    ('signature-bits', 'signature.remaining_bits() != 512 ||', ''),
    ('signature-refs', 'signature.remaining_references() != 0', 'false'),
    ('key-range', '.as_vec(256, false, true)?', '.as_vec(256, false, true).unwrap_or_else(|_| vec![0; 32])'),
    ('stack-admission', 'engine.cc.stack.depth() < 3', 'false'),
]


def main(fixtures, out):
    report = []
    with tempfile.TemporaryDirectory(prefix='p0-rust-vm-') as tmp:
        root = Path(tmp)
        parent = root / 'tosctl/src'
        parent.mkdir(parents=True)
        crate = parent / 'vm'
        shutil.copytree(ROOT / 'tosctl/src/vm', crate)
        for name in ('common', 'validator-auth-crypto'):
            shutil.copytree(ROOT / 'tosctl/src' / name, parent / name)
        for dependency in (ROOT / 'tosctl/src').iterdir():
            if dependency.is_dir() and dependency.name != 'target' and not (parent / dependency.name).exists():
                (parent / dependency.name).symlink_to(dependency, target_is_directory=True)
        (root / 'third-party').mkdir()
        (root / 'third-party/mldsa-native').symlink_to(ROOT / 'third-party/mldsa-native', target_is_directory=True)
        (root / 'crypto').mkdir()
        (root / 'crypto/pq').symlink_to(ROOT / 'crypto/pq', target_is_directory=True)
        manifest = crate / 'Cargo.toml'
        manifest.write_text(manifest.read_text() + '\n[workspace]\n')
        shutil.copy2(ROOT / 'tosctl/src/Cargo.lock', crate / 'Cargo.lock')
        source = crate / 'src/executor/validator_auth.rs'
        original = source.read_text()

        def run(text):
            source.write_text(text)
            built = subprocess.run(['cargo', 'build', '--offline', '--manifest-path', str(manifest), '--example', 'p0-parity'],
                                   capture_output=True, text=True)
            if built.returncode:
                raise RuntimeError('native Rust mutation build failed: ' + built.stderr)
            return subprocess.run([str(crate / 'target/debug/examples/p0-parity'), str(fixtures.resolve())],
                                  capture_output=True, text=True)

        try:
            baseline = run(original)
            assert baseline.returncode == 0, baseline.stderr
            for name, before, after in MUTATIONS:
                # Formatting can wrap a boolean clause without changing it.
                pattern = r'\s*'.join(re.escape(token) for token in before.split())
                # Guards that also appear on the native-host path are matched
                # inside this opcode only. The host copy is exercised by
                # different fixtures and is mutated by native_host_mutations.py;
                # disabling it from here would report a survivor for a path this
                # transcript never runs.
                region = original[original.index(OPCODE_START):original.index(OPCODE_END)]
                scope = region if len(list(re.finditer(pattern, original))) > 1 else original
                offset = original.index(scope) if scope is region else 0
                matches = list(re.finditer(pattern, scope))
                assert len(matches) == 1, name
                match = matches[0]
                start, end = match.start() + offset, match.end() + offset
                modified = original[:start] + after + original[end:]
                result = run(modified)
                assert result.returncode == 1 and re.search(r'Error: .*/\d+: \[.*\] != \[.*\]', result.stderr), (name, result.stderr)
                report.append({'guard': name, 'compiled': True, 'assertion_failed': True})
                print('KILLED:', name, flush=True)
        finally:
            restored = run(original)
            assert restored.returncode == 0, restored.stderr
    out.write_text(json.dumps({'rust_vm_mutations': report, 'restored_baseline': True}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    main(args.fixtures, args.out)
