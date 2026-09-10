#!/usr/bin/env python3
"""Seal source-bound C3 host controls and independently read back all raw files."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    work = args.work.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    controls = work / 'controls-final'
    records = json.loads((controls / 'report.json').read_text())
    audit = json.loads((controls / 'restore-audit.json').read_text())
    baseline = json.loads((controls / 'baseline.json').read_text())
    if len(records) != 24 or len(audit) != 24 or not all(r.get('expected_failure_observed') for r in records):
        raise RuntimeError('incomplete control matrix')
    for row in records:
        if row['original_sha256'] != row['restored_sha256'] or row['restored_binary_sha256'] != baseline['binary']:
            raise RuntimeError('failed source/binary restoration')
    for path, expected in baseline['source_hashes'].items():
        if sha((source / path).read_bytes()) != expected:
            raise RuntimeError('final source differs from measured source: ' + path)
    if sha((work / 'build/test-workchain-preflight-budget').read_bytes()) != baseline['binary']:
        raise RuntimeError('final native binary changed')
    refusal_counts = {}
    for name, expected in (('collator', 1), ('validate-query', 3)):
        path = 'validator/impl/' + name + '.cpp'
        original = subprocess.check_output(['git', 'show', baseline['base_commit'] + ':' + path], cwd=source)
        current = (source / path).read_bytes()
        count = current.count(b'multi-account admission and replay are not connected')
        if current != original or count != expected:
            raise RuntimeError('production refusal source changed: ' + path)
        refusal_counts[name] = count
    if (work / 'domain-scan-final.log').read_bytes() != (work / 'domain-scan.log').read_bytes():
        raise RuntimeError('final staged-file guard findings changed')
    files = {str(p.relative_to(work)): p for p in work.rglob('*')
             if p.is_file() and 'build' not in p.relative_to(work).parts}
    for name in ('CMakeCache.txt', 'CTestTestfile.cmake'):
        files['build-provenance/' + name] = work / 'build' / name
    for relative in (*baseline['source_hashes'], 'crypto/test/workchain-preflight-controls.py',
                     'crypto/test/workchain-preflight-archive.py', 'crypto/test/workchain-preflight-budget.md',
                     'doc/uno-v2-implementation-plan.md'):
        files['final-source/' + relative] = source / relative
    # Compare every reported guard-hit file with the committed baseline. This
    # does not exempt it or turn a failed full scan into a passed scan.
    hits = sorted({line.split(':', 1)[0] for line in (work / 'domain-scan.log').read_text().splitlines()
                   if ':' in line})
    guard_files = []
    for path in hits:
        original = subprocess.check_output(['git', 'show', baseline['base_commit'] + ':' + path], cwd=source)
        current = (source / path).read_bytes()
        if current != original:
            raise RuntimeError('guard hit is not byte-identical to baseline: ' + path)
        guard_files.append({'path': path, 'sha256': sha(current), 'baseline_identical': True})
    hashes = {name: sha(path.read_bytes()) for name, path in files.items()}
    archive = out / 'raw-controls.tar.gz'
    if archive.exists():
        raise RuntimeError('refusing to overwrite existing evidence')
    with tarfile.open(archive, 'w:gz') as tar:
        for name, path in sorted(files.items()):
            tar.add(path, arcname=name, recursive=False)
    with tarfile.open(archive, 'r:gz') as tar:
        if set(tar.getnames()) != set(hashes):
            raise RuntimeError('archive member mismatch')
        for member in tar:
            if sha(tar.extractfile(member).read()) != hashes[member.name]:
                raise RuntimeError('archive readback mismatch: ' + member.name)
    report = {
        'scope': 'host preflight contract plus private controls; not C2 or C3 closure',
        'base_commit': baseline['base_commit'],
        'source_binding': 'base commit plus archived full source overlay and SHA256; new files are not claimed present at base commit',
        'source_hashes': baseline['source_hashes'], 'native_binary_sha256': baseline['binary'],
        'native_cases': 9, 'single_site_controls': records, 'restore_audit': audit,
        'final_registered_test': 'controls-final/final.xml',
        'refusal_counts': refusal_counts,
        'whole_repository_scan': {'passed': False, 'baseline_identical_hit_files': guard_files},
        'not_run': ['full default build', 'ordinary full regression', 'private I13 harnesses', 'production preflight'],
        'raw_archive_sha256': sha(archive.read_bytes()), 'readback_verified_files': len(hashes),
        'files': hashes,
    }
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(records)} controls; {len(hashes)} archived files verified; {report["raw_archive_sha256"]}')


if __name__ == '__main__':
    main()
