"""Compile removed native Keyring barriers and require exact assertion failures."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from mutation_support import replace_once

MUTATIONS = [
    (label, 'keyring', method, 'if (isolation.is_error())', 'if (false)')
    for method, label in (
        ('add_key', 'keyring-reimport'), ('del_key', 'keyring-delete'),
        ('export_private_key', 'keyring-export'), ('sign_message', 'keyring-sign'),
        ('sign_add_get_public_key', 'keyring-sign-public'), ('sign_messages', 'keyring-sign-batch'),
        ('decrypt_message', 'keyring-decrypt'), ('export_all_private_keys', 'keyring-export-all'))
] + [
    ('keyring-drain-barrier', 'keyring-isolation', 'protect_validator_auth_key', 'if (raw_inflight_.empty())', 'if (true)'),
    ('keyring-private-barrier', 'keyring-isolation', 'admit_generic', 'if (!protection_waiters_.empty())', 'if (false)'),
    ('keyring-bulk-barrier', 'keyring-isolation', 'admit_bulk_export', 'if (!protection_waiters_.empty())', 'if (false)'),
    ('keyring-restart', 'key-isolation', 'replay', '!denied_.insert(key).second', 'false'),
    ('keyring-restart', 'key-isolation', 'protect', 'auto written = log_->append(record);', 'Result<LogFrontier> written = LogFrontier{};'),
    ('keyring-sign', 'key-isolation', 'protect', 'denied_.insert(key);', ''),
    ('keyring-ledger-replacement', 'key-isolation', 'refresh', 'if (!log_->linked_at(path))', 'if (false)'),
    ('keyring-upgrade-stopped', 'key-isolation', 'refresh', 'if (stopped_)', 'if (false)'),
    ('keyring-concurrent-writer', 'key-isolation', 'protect', '::flock(directory_fd_, LOCK_EX | LOCK_NB) != 0', 'false'),
    ('keyring-concurrent-writer', 'key-isolation', 'refresh', '::flock(directory_fd_, LOCK_SH | LOCK_NB) != 0', 'false'),
    ('keyring-storage-closed', 'key-isolation', 'admit', 'if (!ready.ok())', 'if (false)'),
    ('keyring-storage-closed', 'key-isolation', 'refresh', '(st.st_mode & 0777) != 0700', 'false'),
    ('record-tag', 'key-isolation', 'replay', '!std::equal(tag.begin(), tag.end(), raw.begin())', 'false'),
    ('record-length', 'key-isolation', 'replay', 'raw.size() != 36', 'false'),
    # Keep insertion's side effect while dropping duplicate rejection.
    ('record-duplicate', 'key-isolation', 'replay', '!denied_.insert(key).second', '(denied_.insert(key), false)'),
    ('keyring-storage-closed', 'key-isolation', 'refresh', 'if (!secure_parent())', 'if (false)'),
    ('keyring-parent-writable', 'key-isolation', 'protect', 'if (!secure_parent())', 'if (false)'),
]


def mutate(source, method, before, after):
    # Bodies have a unique qualified method name and close at column zero.
    start = source.index('::'+method+'(')
    end = source.index('\n}', start) + 2
    return source[:start] + replace_once(source[start:end], before, after) + source[end:]


def main(build, out):
    folder = build.resolve()/'test/validator-auth-implementation'
    report = []
    modules = dict.fromkeys(row[1] for row in MUTATIONS)
    for module in modules:
        source = folder/f'mutated-{module}.cpp'
        original = source.read_text()
        target = f'test-p0-{module}-mutant'
        def run(text):
            source.write_text(text)
            subprocess.run(['cmake', '--build', str(build), '--target', target, '-j2'],
                           check=True, capture_output=True, text=True)
            with tempfile.TemporaryDirectory(prefix='p0-keyring-mut-', dir='/tmp') as temp:
                return subprocess.run([str(folder/target), str(Path(temp)/'data')],
                                      capture_output=True, text=True, timeout=45)
        try:
            baseline = run(original)
            assert baseline.returncode == 0, (module, baseline.stderr)
            for index, (label, owner, method, before, after) in enumerate(MUTATIONS):
                if owner != module:
                    continue
                result = run(mutate(original, method, before, after))
                assert result.returncode == 1 and result.stderr.strip() == 'ASSERTION: '+label, (
                    index, module, method, 'invalid kill', result.returncode, result.stderr)
                report.append(dict(guard=f'{module}:{method}:{index}', assertion=label, compiled=True, assertion_failed=True))
                print('KILLED:', module, method, label, flush=True)
        finally:
            restored = run(original)
            assert restored.returncode == 0, ('restored', module, restored.stderr)
    out.write_text(json.dumps(dict(keyring_mutations=report, restored_baselines=True), indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    main(args.build, args.out)
