"""Compile narrow mutants of the shared action ledger, require the intended red, restore and require green.

Each mutant edits one source in place, rebuilds the named targets, runs every listed probe and
requires that each run fails for the stated reason: one of the exact assertion texts, or for the
lock mutant a thread sanitizer race report whose first report names the ledger's own accesses. A
compile failure, a watchdog expiry or an unrelated sanitizer failure is never accepted as the red.
The source is restored byte for byte, rebuilt, and every probe must pass again. Commit before running:
the source is rewritten while a mutant is built.
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument('--build-dir', required=True, type=pathlib.Path, help='Release build directory')
parser.add_argument('--tsan-build-dir', required=True, type=pathlib.Path, help='ThreadSanitizer build directory')
parser.add_argument('--out', required=True, type=pathlib.Path, help='evidence directory (outside the tree)')
parser.add_argument('--jobs', type=int, default=64)
parser.add_argument('--only', action='append', default=[], help='run only the named mutants')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
HEADER = 'metrics/consensus-health.h'
PRODUCER = 'validator/consensus/block-producer.cpp'
args.out.mkdir(parents=True, exist_ok=True)

LOCK_BEFORE = 'using Guard = std::lock_guard<std::mutex>;'
LOCK_AFTER = 'struct Guard { explicit Guard(std::mutex &) noexcept {} };'
# The lifetime pin bypassed: the session is closed, and its banks released, while the stopped
# producer frame is still outstanding.
STOP_BEFORE = '    cancellation_source_.cancel();\n    stop();\n'
STOP_EARLY_CLOSE = '    cancellation_source_.cancel();\n    owning_bus()->health_session.close();\n    stop();\n'
DTOR_BEFORE = '  ~ActionObservation() {\n    finish(Phase::Cancelled);\n  }\n'
DTOR_OMITTED = '  ~ActionObservation() {\n  }\n'
# The rejected design: skip accounting once a session stop has been requested.
DTOR_STOP_SKIPPED = ('  ~ActionObservation() {\n    if (consensus_stats.sessions_stop_started.load() == 0)\n'
                     '      finish(Phase::Cancelled);\n  }\n')

LEDGER = 'test-health-ledger'
ACTIONS = 'test-health-actions'
RACE = 'race'


def probe(binary, mode, expect, runs=1, timeout=180):
    return dict(binary=binary, mode=mode, expect=[expect] if isinstance(expect, str) else expect, runs=runs,
                timeout=timeout)


cases = [
    dict(name='no-bank-lock', source=HEADER, before=LOCK_BEFORE, after=LOCK_AFTER, tsan=True,
         probes=[probe(LEDGER, 'concurrent', RACE, runs=10), probe(ACTIONS, 'pool-stopped-duplicate', RACE, runs=10)]),
    dict(name='omitted-destructor-finish', source=HEADER, before=DTOR_BEFORE, after=DTOR_OMITTED, tsan=False,
         probes=[probe(LEDGER, 'concurrent', 'no request remains pending after concurrent cleanup')]),
    dict(name='stop-skipped-finish', source=HEADER, before=DTOR_BEFORE, after=DTOR_STOP_SKIPPED, tsan=False,
         probes=[probe(ACTIONS, 'pool-stopped-duplicate', 'stopped duplicate cleanup clears the pending request and row'),
                 probe(ACTIONS, 'producer-stop-ordering',
                       'the stopped producer frame records its cancellation and clears its pending request and row')]),
    # The red may be seen before the drain or after it, depending on when the producer handles
    # its stop; both assertions are ordering failures of the same mutant.
    dict(name='early-session-close', source=PRODUCER, before=STOP_BEFORE, after=STOP_EARLY_CLOSE, tsan=False,
         probes=[probe(ACTIONS, 'producer-stop-ordering',
                       ['the observation is released before its session closes and its bank is released',
                        'the lease stays unavailable while the observation is outstanding'], runs=5)]),
]


def build(directory, targets, log):
    with log.open('w') as stream:
        return subprocess.run(['cmake', '--build', str(directory), '--target', *targets, f'-j{args.jobs}'],
                              stdout=stream, stderr=subprocess.STDOUT).returncode


def first_tsan_report(output):
    start = output.find('WARNING: ThreadSanitizer: data race')
    if start < 0:
        return ''
    end = output.find('SUMMARY: ThreadSanitizer', start)
    return output[start:end if end >= 0 else len(output)]


def run(directory, item, log, expect_red):
    binary = directory / 'test/validator/consensus' / item['binary']
    env = dict(os.environ)
    env['TSAN_OPTIONS'] = 'halt_on_error=1 second_deadlock_stack=1'
    try:
        result = subprocess.run([str(binary), item['mode']], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=item['timeout'], env=env)
        output, code = result.stdout.decode(errors='replace'), result.returncode
    except subprocess.TimeoutExpired as expired:
        output, code = (expired.stdout or b'').decode(errors='replace') + '\nPROBE_TIMEOUT\n', None
    log.write_text(output)
    unrelated = ('PROBE_TIMEOUT' in output or 'WATCHDOG' in output or 'ThreadSanitizer: CHECK failed' in output
                 or 'FATAL: ThreadSanitizer' in output)
    if not expect_red:
        return dict(exit=code, green=code == 0 and not unrelated and 'ThreadSanitizer' not in output)
    if item['expect'] == [RACE]:
        # The racing address must lie in the static ledger banks, and both accesses in ledger code
        # (the entry operations, which the compiler may inline into the observation's methods).
        report = first_tsan_report(output)
        frames = [line.strip() for line in report.splitlines() if '#0 ' in line]
        intended = (code not in (0, None) and not unrelated
                    and "Location is global 'tos::health::ActionLedger::banks_" in report and len(frames) >= 2
                    and all('tos::health::ActionLedger::' in frame or 'tos::health::ActionObservation::' in frame
                            for frame in frames[:2]))
        return dict(exit=code, intended=intended, report_frames=frames[:2])
    seen = [needle for needle in item['expect'] if ('ASSERTION: ' + needle) in output]
    intended = code not in (0, None) and not unrelated and len(seen) > 0
    return dict(exit=code, intended=intended, assertion_seen=seen)


receipts = []
for case in cases:
    if args.only and case['name'] not in args.only:
        continue
    name = case['name']
    header = root / case['source']
    directory = (args.tsan_build_dir if case['tsan'] else args.build_dir).resolve()
    targets = sorted({item['binary'] for item in case['probes']})
    original = header.read_bytes()
    source = original.decode()
    assert source.count(case['before']) == 1, 'mutation anchor must occur exactly once: ' + name
    mutant = source.replace(case['before'], case['after'], 1)
    receipt = dict(name=name, source=case['source'], build_dir=str(directory),
                   baseline_sha256=hashlib.sha256(original).hexdigest(),
                   mutant_sha256=hashlib.sha256(mutant.encode()).hexdigest(), red=[], green=[])
    try:
        header.write_text(mutant)
        receipt['build_exit'] = build(directory, targets, args.out / f'{name}-build.log')
        assert receipt['build_exit'] == 0, 'mutant must compile: ' + name
        for item in case['probes']:
            for attempt in range(item['runs']):
                log = args.out / f"{name}-red-{item['mode']}-{attempt}.log"
                outcome = run(directory, item, log, expect_red=True)
                receipt['red'].append(dict(mode=item['mode'], attempt=attempt, expect=item['expect'], **outcome))
                assert outcome['intended'], f"mutant must fail for the intended reason: {name} {item['mode']} {attempt}"
    finally:
        header.write_bytes(original)
        receipt['restore_build_exit'] = build(directory, targets, args.out / f'{name}-restore-build.log')
        receipt['restored_sha256'] = hashlib.sha256(header.read_bytes()).hexdigest()
        (args.out / 'receipts.json').write_text(json.dumps(receipts + [receipt], indent=2) + '\n')
        assert receipt['restore_build_exit'] == 0 and header.read_bytes() == original
    for item in case['probes']:
        outcome = run(directory, item, args.out / f"{name}-green-{item['mode']}.log", expect_red=False)
        receipt['green'].append(dict(mode=item['mode'], **outcome))
        assert outcome['green'], f"restored control must pass: {name} {item['mode']}"
    receipts.append(receipt)
    (args.out / 'receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
    print(name + ': compiled mutant red for the intended reason; restored control green', flush=True)
