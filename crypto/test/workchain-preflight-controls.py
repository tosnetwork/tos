#!/usr/bin/env python3
"""Single-site host-contract controls with explicit target rebuild and restore audit."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

HEADER = 'crypto/block/workchain-preflight-budget.h'
TEST = 'crypto/test/test-workchain-preflight-budget.cpp'
DRIVER = 'crypto/test/workchain-preflight-budget.py'
MODULE = 'crypto/test/workchain-preflight-budget.cmake'
TARGET = 'test-workchain-preflight-budget'
TEST_NAME = TARGET + '-gates'

# (path, original, replacement, native case or 'ctest', exact failed assertion)
CASES = {
    'zero-allowance': (HEADER,
        'if (!allowance.units) return {Reason::InvalidAllowance, 0, std::nullopt, {}};',
        '(void)allowance;', 'allowance', 'allowance.zero_rejected'),
    'zero-allowance-order': (HEADER,
        'if (!allowance.units) return {Reason::InvalidAllowance, 0, std::nullopt, {}};\n'
        '    try {\n      switch (reservations.reserve_preflight(allowance.units)) {',
        'try {\n      auto outcome = reservations.reserve_preflight(allowance.units);\n'
        '      if (!allowance.units) return {Reason::InvalidAllowance, 0, std::nullopt, {}};\n'
        '      switch (outcome) {', 'allowance', 'allowance.before_reservation_and_body'),
    'reservation-amount': (HEADER, 'reserve_preflight(allowance.units)', 'reserve_preflight(0)',
                           'positive', 'reserve.before_body'),
    'block-refusal': (HEADER, 'return {Reason::BlockLimitExceeded, 0, std::nullopt, {}};', 'break;',
                      'block-bound', 'block.no_grace'),
    'charge-order': (HEADER, 'consumed_ += units;\n    std::forward<Operation>(operation)();',
                     'std::forward<Operation>(operation)();\n    consumed_ += units;',
                     'positive', 'charge.before_operation'),
    'charge-omitted': (HEADER, 'consumed_ += units;', 'consumed_ += 0;',
                       'positive', 'charge.before_operation'),
    'operation-bound': (HEADER, 'if (units > limit_ - consumed_)', 'if (false)',
                        'sticky', 'sticky.over_limit'),
    'sticky-omitted': (HEADER, 'if (state_ != WorkchainPreflightMeterState::Ready) return false;',
                       'if (false) return false;', 'sticky', 'sticky.no_resume'),
    'host-meter-result': (HEADER, 'if (meter.state() == WorkchainPreflightMeterState::Exhausted)',
                          'if (false)', 'sticky', 'sticky.host_overrides_success'),
    'body-error-result': (HEADER, 'reason = Reason::InspectionFailure;', 'reason = Reason::Complete;',
                          'failure', 'failure.retains_status'),
    'body-exception-result': (HEADER, 'reason = Reason::InspectionException;', 'reason = Reason::Complete;',
                              'exception', 'exception.original_present'),
    'body-exception-payload': (HEADER, 'exception = std::current_exception();',
                               'exception = std::make_exception_ptr(0);',
                               'exception', 'exception.type_and_charge_retained'),
    'primary-reason': (HEADER, 'if (meter.state() == WorkchainPreflightMeterState::Exhausted)',
                       'if (meter.state() == WorkchainPreflightMeterState::Exhausted && !exception)',
                       'exception', 'exception.meter_reason_first'),
    'zero-charge': (HEADER, 'if (!units)', 'if (false)', 'zero', 'zero.not_free'),
    'invalid-charge-exception-priority': (HEADER,
        'meter.state() == WorkchainPreflightMeterState::InvalidCharge)',
        'meter.state() == WorkchainPreflightMeterState::InvalidCharge && !exception)',
        'zero', 'zero.precedes_exception'),
    'invalid-charge-status-priority': (HEADER,
        'meter.state() == WorkchainPreflightMeterState::InvalidCharge)',
        'meter.state() == WorkchainPreflightMeterState::InvalidCharge && (!result || result->is_ok()))',
        'zero', 'zero.precedes_status_error'),
    'addition-overflow': (HEADER, 'if (units > limit_ - consumed_)',
                          'if (units + consumed_ > limit_)', 'overflow', 'overflow.no_wrap'),
    'reservation-local': (HEADER, 'return {Reason::ReservationUnavailable, 0, std::nullopt, {}};',
                           'break;', 'reservation-failure', 'reservation.local_no_body'),
    'reservation-unknown': (HEADER, 'return {Reason::InvalidReservation, 0, std::nullopt, {}};',
                             'break;', 'reservation-failure', 'reservation.unknown_no_default'),
    'reservation-payload': (HEADER,
        'return {Reason::ReservationException, 0, std::nullopt, std::current_exception()};',
        'return {Reason::ReservationException, 0, std::nullopt, std::make_exception_ptr(0)};',
        'reservation-failure', 'reservation.original_allocation_exception'),
    'completion-omitted': (TEST,
        'std::cout << "completed preflight host case: " << name << \'\\n\';', '(void)name;',
        'ctest', 'positive: incomplete/failed contract check, exit=0'),
    'registered-driver-fails': (DRIVER, 'def main():',
        'def main():\n    raise RuntimeError("preflight registered-driver control")',
        'ctest', 'preflight registered-driver control'),
    'empty-selection': (DRIVER, 'EXPECTED_COUNT = 9', 'CASES = ()\nEXPECTED_COUNT = 9',
        'ctest', 'preflight selection count changed'),
    'missing-native-case': (TEST,
        'Case{"overflow", overflow}, Case{"zero", zero}, Case{"allowance", allowance}',
        'Case{"overflow", overflow}, Case{"zero", zero}',
        'ctest', 'preflight native dispatch/driver selection mismatch'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patch(path, before, after, patch_tool):
    # Use apply_patch for source edits, including restoration. Never overwrite
    # a possibly concurrently changed file with a saved whole-file snapshot.
    if path.read_bytes() != before:
        raise RuntimeError(f'unexpected concurrent source change: {path}')
    old, new = before.decode().splitlines(), after.decode().splitlines()
    prefix = 0
    while prefix < min(len(old), len(new)) and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while suffix < min(len(old), len(new)) - prefix and old[-suffix - 1] == new[-suffix - 1]:
        suffix += 1
    old_end = len(old) - suffix
    new_end = len(new) - suffix
    lines = ['*** Begin Patch', f'*** Update File: {path}', '@@']
    lines += [' ' + line for line in old[max(0, prefix - 2):prefix]]
    lines += ['-' + line for line in old[prefix:old_end]]
    lines += ['+' + line for line in new[prefix:new_end]]
    lines += [' ' + line for line in old[old_end:old_end + 2]]
    lines += ['*** End Patch', '']
    result = subprocess.run([patch_tool], input='\n'.join(lines), text=True, capture_output=True)
    if result.returncode or path.read_bytes() != after:
        raise RuntimeError(f'patch failed or changed unintended bytes: {result.stdout}\n{result.stderr}')


def audit_disk(out):
    audit = []
    for row in json.loads((out / 'report.json').read_text()):
        original = (out / 'baseline-source' / row['path']).read_bytes()
        if sha(original) != row['original_sha256']:
            raise RuntimeError('archived original hash mismatch')
        before = row['before'].encode()
        if original.count(before) != 1:
            raise RuntimeError('archived mutation anchor is not unique')
        left, _, right = original.partition(before)
        reconstructed = left + row['after'].encode() + right
        mutant = (out / row['identity'] / 'mutant-source').read_bytes()
        if sha(reconstructed) != row['mutant_sha256'] or mutant != reconstructed:
            raise RuntimeError('archived mutant reconstruction mismatch')
        if row['original_sha256'] != row['restored_sha256']:
            raise RuntimeError('recorded restoration differs')
        audit.append({'identity': row['identity'], 'reconstructed_sha256': sha(reconstructed),
                      'byte_exact_restore': True})
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source, build = args.source.resolve(strict=True), args.build.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    patch_tool = shutil.which('apply_patch')
    if not patch_tool:
        raise RuntimeError('apply_patch unavailable')
    # This deliberately in-place control method is restricted to this private
    # single-consumer unit. Fail before editing if a new literal C++ consumer
    # lands; do not assume its targets would be restored by our target rebuild.
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=source)
    consumers = set()
    for raw in set(paths.split(b'\0')):
        if not raw:
            continue
        relative = raw.decode()
        path = source / relative
        if relative.startswith('third-party/') or path.suffix not in ('.h', '.hpp', '.cpp', '.cc', '.cxx', '.inc', '.ipp', '.c'):
            continue
        includes = re.findall(r'^\s*#\s*include\s*[<"]([^">]+)[">]', path.read_text(errors='strict'), re.M)
        if any(Path(item).name == 'workchain-preflight-budget.h' for item in includes):
            consumers.add(relative)
    if consumers != {TEST}:
        raise RuntimeError(f'private control consumer boundary changed: {sorted(consumers)}')
    (out / 'literal-consumers.json').write_text(json.dumps(sorted(consumers), indent=2) + '\n')
    binary = build / TARGET
    baseline = {path: (source / path).read_bytes() for path in (HEADER, TEST, DRIVER, MODULE)}
    records = []

    def run(folder, name, argv, expected):
        (folder / (name + '.argv.json')).write_text(json.dumps(argv, indent=2) + '\n')
        result = subprocess.run(argv, cwd=source, capture_output=True, timeout=180)
        (folder / (name + '.stdout.log')).write_bytes(result.stdout)
        (folder / (name + '.stderr.log')).write_bytes(result.stderr)
        if result.returncode != expected:
            raise RuntimeError(f'{name}: exit {result.returncode}, expected {expected}')
        return result

    rebuild = ['cmake', '--build', str(build), '--target', TARGET, '-j32']
    run(out, 'baseline-build', rebuild, 0)
    baseline_binary = sha(binary.read_bytes())
    run(out, 'baseline-run', ['python3', str(source / DRIVER), '--binary', str(binary)], 0)
    # Establish that this build actually compiled these paths, not another
    # uncommitted worktree or override. The full commands/deps are retained.
    commands = json.loads((build / 'compile_commands.json').read_text())
    rows = [row for row in commands if Path(row['file']).resolve() == source / TEST]
    if len(rows) != 1:
        raise RuntimeError('expected exactly one compiled fixture source')
    (out / 'compile_commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    deps = run(out, 'dependencies', ['ninja', '-C', str(build), '-t', 'deps'], 0).stdout.decode()
    if str(source / HEADER) not in deps:
        raise RuntimeError('compiled dependency graph lacks the measured header')
    (out / 'baseline.json').write_text(json.dumps({
        'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
        'source_hashes': {p: sha(b) for p, b in baseline.items()}, 'binary': baseline_binary,
        'actual_executables': [str(binary), shutil.which('python3'), shutil.which('ctest')],
        'explicit_native_rebuild_targets': [TARGET],
        'scope': 'C3 host contract/private C2 consumer only; no production call site or engine closure',
    }, indent=2) + '\n')
    for path, content in baseline.items():
        target = out / 'baseline-source' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)  # Evidence copy, not a source edit.
    for identity, (relative, before, after, case, expected_assertion) in CASES.items():
        path = source / relative
        original = baseline[relative]
        if original.count(before.encode()) != 1:
            raise RuntimeError(f'{identity}: nonunique mutation anchor')
        for item, content in baseline.items():
            if (source / item).read_bytes() != content:
                raise RuntimeError('baseline changed before control: ' + item)
        mutated = original.replace(before.encode(), after.encode(), 1)
        folder = out / identity
        folder.mkdir()
        (folder / 'mutant-source').write_bytes(mutated)
        record = {'identity': identity, 'path': relative, 'case': case,
                  'before': before, 'after': after, 'original_sha256': sha(original),
                  'mutant_sha256': sha(mutated), 'expected_assertion': expected_assertion}
        try:
            patch(path, original, mutated, patch_tool)
            run(folder, 'mutant-build', rebuild, 0)
            record['mutant_binary_sha256'] = sha(binary.read_bytes())
            if case == 'ctest':
                result = run(folder, 'mutant-test', ['ctest', '--test-dir', str(build),
                    '-R', '^' + TEST_NAME + '$', '--output-on-failure', '--output-junit',
                    str(folder / 'mutant.xml')], 8)
                cases = ET.parse(folder / 'mutant.xml').getroot().findall('.//testcase')
                if len(cases) != 1 or cases[0].get('name') != TEST_NAME or cases[0].get('status') != 'fail' or cases[0].find('failure') is None:
                    raise RuntimeError('registered driver did not produce exactly one Failed test')
                text = result.stdout.decode() + result.stderr.decode()
                if expected_assertion not in text:
                    raise RuntimeError('CTest failed for a different cause')
            else:
                result = run(folder, 'mutant-test', [str(binary), case], 1)
                if result.stderr.decode() != expected_assertion + '\n':
                    raise RuntimeError('control failed at a different assertion')
            record['expected_failure_observed'] = True
        finally:
            current = path.read_bytes()
            if current == mutated:
                patch(path, mutated, original, patch_tool)
            elif current != original:
                raise RuntimeError('unexpected partial/concurrent edit; refusing blind restoration')
            # The actual native executable, not all-tests or just ctest/python.
            run(folder, 'restored-build', rebuild, 0)
            if sha(binary.read_bytes()) != baseline_binary:
                raise RuntimeError('restored binary differs from baseline')
            record['restored_sha256'] = sha(path.read_bytes())
            record['restored_binary_sha256'] = sha(binary.read_bytes())
            run(folder, 'restored-run', ['python3', str(source / DRIVER), '--binary', str(binary)], 0)
            records.append(record)
            (out / 'report.json').write_text(json.dumps(records, indent=2) + '\n')
        print(identity + ': intended failure and exact restoration confirmed', flush=True)
    # Reload report and original/mutant evidence from disk, independently of
    # the controller's in-memory replacement. Do not self-check the same bytes
    # used to populate mutant_sha256 without reading the archived inputs.
    audit = audit_disk(out)
    (out / 'restore-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    # Negative controls for the artifact reader, not additional native tests.
    # Retain the altered evidence copies; never edit the real measured source.
    for kind, expected in (('original', 'archived original hash mismatch'),
                           ('mutant', 'archived mutant reconstruction mismatch')):
        calibration = out / 'audit-calibration' / kind
        calibration.mkdir(parents=True)
        shutil.copyfile(out / 'report.json', calibration / 'report.json')
        shutil.copytree(out / 'baseline-source', calibration / 'baseline-source')
        for row in records:
            (calibration / row['identity']).mkdir()
            shutil.copyfile(out / row['identity'] / 'mutant-source', calibration / row['identity'] / 'mutant-source')
        row = records[0]
        target = (calibration / 'baseline-source' / row['path'] if kind == 'original'
                  else calibration / row['identity'] / 'mutant-source')
        target.write_bytes(target.read_bytes() + b'\n')
        try:
            audit_disk(calibration)
        except RuntimeError as error:
            if str(error) != expected:
                raise
            (calibration / 'observed.json').write_text(json.dumps({
                'expected_failure': expected, 'observed_failure': str(error),
                'altered_artifact_sha256': sha(target.read_bytes())}, indent=2) + '\n')
        else:
            raise RuntimeError('artifact audit accepted changed evidence')
    run(out, 'final-ctest', ['ctest', '--test-dir', str(build), '-R', '^' + TEST_NAME + '$',
        '--output-on-failure', '--output-junit', str(out / 'final.xml')], 0)
    final = ET.parse(out / 'final.xml').getroot().findall('.//testcase')
    if len(final) != 1 or final[0].get('status') != 'run' or final[0].find('failure') is not None:
        raise RuntimeError('final registration/run incomplete')
    print(f'{len(records)} single-site controls, native restores and final registered run complete')


if __name__ == '__main__':
    main()
