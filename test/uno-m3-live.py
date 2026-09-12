#!/usr/bin/env python3
"""Test-owned node fixture. No deployment configuration or permission flag."""
import argparse
import atexit
import ast
import base64
import hashlib
import json
import importlib.util
import os
import shlex
import sys
import shutil
from pathlib import Path
import subprocess
import tempfile
import time
from uno_wallet_freshness import pin

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', required=True, type=Path)
p.add_argument('--m4', action='store_true', help='use explicit M4 test parameters and real Native Deposit')
p.add_argument('--m4-rejections', action='store_true', help='run separate rejection cases after two real Deposits')
p.add_argument('--m5-debit', action='store_true', help='stop after authenticated Withdrawal debit checkpoint')
p.add_argument('--m5-return-route', action='store_true', help='deliver a funded payout to wc0 and observe the actual return')
p.add_argument('--m5-failed', action='store_true', help='publish the funded phase-0 return atomically at custody')
p.add_argument('--m5-bucket-small', action='store_true', help='real bounce below local issuance fees')
p.add_argument('--phase-delay-transit', action='store_true',
               help='keep the original payout queued through the first owner operation for D73')
p.add_argument('--phase-replay-cuts', action='store_true',
               help='retain per-operation DB predecessors inside this run for D73 producer controls')
p.add_argument('--m5-completion-late', action='store_true',
               help='establish Q through real owner operations before importing the return')
p.add_argument('--completion-close-before-return', action='store_true',
               help='expire the original obligation through an owner operation before late delivery')
p.add_argument('--completion-close-account-before-return', action='store_true',
               help='use real SENDs and closure before delivering the original late return')
p.add_argument('--completion-window-pair', action='store_true',
               help='fork one authenticated predecessor into deadline and deadline+1 real returns')
p.add_argument('--completion-no-slot', action='store_true',
               help='fill the explicit test system-pending capacity with real Deposits before prepare')
p.add_argument('--completion-free-one-slot', action='store_true',
               help='after filling the real system map, COLLECT exactly one entry before prepare')
p.add_argument('--completion-sweep', action='store_true',
               help='after actual full-slot bucket publication, COLLECT one Deposit and execute the authorized round')
p.add_argument('--m5-completion-paid', action='store_true',
               help='real no-bounce payout, untouched expiry, then an owner trigger')
p.add_argument('--completion-full-cap', action='store_true',
               help='explicit Paid test cap of three: expiry must precede admission')
p.add_argument('--m5-return-principal', type=int, help='explicit real-payout fixture principal')
p.add_argument('--completion-expect-offset', type=int, choices=(-1, 0, 1),
               help='assert observed y is h plus this exact boundary offset')
p.add_argument('--remaining-contract', choices=('phase-transition',),
               help='execute the existing remaining-work contract; incomplete controls fail closed')
p.add_argument('--completion-contract', choices=('bucket-small', 'bucket-full', 'bucket-closed', 'row4', 'row5', 'row6', 'sweep-atomic', 'oracle-control'),
               help='run the existing frozen real-host completion contract')
p.add_argument('--failed-routing-probe', action='store_true',
               help='run the real fee-routing producer mutation before normal Failed publication')
p.add_argument('--failed-routing-binary', type=Path,
               help='isolated test binary for oracle-removal control only')
p.add_argument('--retain-fixture', metavar='REASON',
               help="deliberately retain this run's fixtures for evidence; requires a nonempty reason")
p.add_argument('--fixture-parent', type=Path, help=argparse.SUPPRESS)
a = p.parse_args()
if a.retain_fixture is not None and not a.retain_fixture.strip():
    p.error('retaining a fixture requires a reason')
if a.fixture_parent is not None and not a.fixture_parent.is_dir():
    p.error('fixture parent must be an existing parent-owned directory')

# Read the filesystem, not our footprint: unrelated processes share this volume.
# Children needed by an oracle live below its work directory; only the parent
# removes that directory, after observations, mutations and restoration finish.
live_paths = []
live_volume = a.fixture_parent or Path(tempfile.gettempdir())
def live_capacity(stage):
    usage = shutil.disk_usage(live_volume)
    print('LIVE_CAPACITY_' + stage + ':' + json.dumps(dict(
        pid=os.getpid(), volume=str(live_volume), device=live_volume.stat().st_dev,
        total_bytes=usage.total, free_bytes=usage.free)), flush=True)

def live_fixture(prefix):
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=a.fixture_parent))
    live_paths.append((os.getpid(), path))
    return path

def finish_live():
    try:
        live_capacity('END')  # Before cleanup, so reclaimed space cannot mask pressure.
        for owner, path in reversed(live_paths):
            if owner != os.getpid():
                continue  # A fork must never delete its parent's observations.
            if a.fixture_parent is not None:
                print(f'LIVE_FIXTURE_PARENT_OWNED:{path}: retained until parent oracle finishes', flush=True)
            elif a.retain_fixture:
                print(f'LIVE_FIXTURE_RETAINED:{path}: {a.retain_fixture}', flush=True)
            else:
                # Keep child capacity observations in this run's result log before
                # removing the temporary logs that the oracle has already read.
                for log in sorted(path.rglob('*.log')):
                    with log.open('rb') as stream:
                        for line in stream:
                            if line.startswith(b'LIVE_CAPACITY_'):
                                print('CHILD_' + line.decode('utf-8').rstrip(), flush=True)
                shutil.rmtree(path)
                print(f'LIVE_FIXTURE_REMOVED:{path}', flush=True)
    except Exception as error:
        # atexit normally swallows callback failures. Cleanup/measurement failure
        # must instead fail the run, even after a business observation marker.
        print(f'LIVE_FINALIZATION_FAILED:{error!r}', file=sys.stderr, flush=True)
        sys.stdout.flush()
        os._exit(1)

live_capacity('START')
atexit.register(finish_live)
if a.phase_delay_transit and (not a.m5_completion_late or a.m5_completion_paid or
                             a.completion_close_account_before_return):
    p.error('delayed transit requires the ordinary late-return owner sequence')
if a.phase_replay_cuts and not a.m5_completion_late:
    p.error('phase replay cuts require the actual late-return owner sequence')
split_return_route = a.m5_completion_late and not a.m5_completion_paid
if a.completion_close_before_return and not split_return_route:
    p.error('close-before-return requires the real split late-return route')
if a.completion_close_account_before_return and (not split_return_route or a.completion_close_before_return or
                                                a.completion_window_pair or a.completion_no_slot):
    p.error('account closure requires the unfilled split late route without other closure/window variants')
if a.completion_window_pair and (not split_return_route or a.completion_close_before_return):
    p.error('window-pair requires the split late route without close-before-return')
if a.m5_completion_paid:
    a.m5_completion_late = True
if a.completion_full_cap and not a.m5_completion_paid:
    p.error('full-cap fixture requires Paid completion')
if a.m5_bucket_small or a.m5_completion_late:
    a.m5_failed = True
if a.completion_sweep:
    if a.completion_free_one_slot or a.completion_close_account_before_return:
        p.error('sweep needs the real full-slot bucket, not a pre-return slot removal or closed owner')
    a.completion_no_slot = True
if a.completion_no_slot:
    a.m5_failed = True
if a.completion_free_one_slot and not a.completion_no_slot:
    p.error('free-one-slot requires the real full-system-map fixture')
if a.failed_routing_probe:
    a.m5_failed = True
if a.m5_failed:
    a.m5_return_route = True
if a.m5_return_route:
    a.m5_debit = True
repo = Path(__file__).resolve().parents[1]
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
if f'CMAKE_HOME_DIRECTORY:INTERNAL={repo}' not in cache:
    p.error('build belongs to another tree')
if 'TOS_UNO_CRYPTO_NODE_LINK:BOOL=ON' not in cache:
    p.error('real node verification requires TOS_UNO_CRYPTO_NODE_LINK=ON')
if a.m5_return_principal is not None and not (a.m5_return_route and 0 < a.m5_return_principal < 2**64):
    p.error('explicit principal requires a real return and must fit uint64')
if a.completion_expect_offset is not None and not a.m5_bucket_small:
    p.error('boundary observation requires the bucket fixture')

if a.completion_contract and a.remaining_contract:
    p.error('select exactly one contract')
if a.completion_contract or a.remaining_contract:
    # Complete the existing carrier here; do not introduce a parallel runner.
    work = live_fixture('uno-completion-bucket-')
    print(f'COMPLETION_RUN:{work}', flush=True)
    spec = importlib.util.spec_from_file_location('completion_oracle',
        repo / 'crypto/test/workchain_withdrawal_completion_oracle.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)

    if a.completion_contract == 'oracle-control':
        # Real-host observations retained by the seven closing slots. This slot
        # tests the oracle/driver layer; it does not re-execute those host paths.
        evidence = repo / 'doc/measurements/uno-m5-withdrawal-completion'
        cases = (
            ('row4', 'row4-real/positive/completion-observation.json',
             'row4-real/skip-expiry-run/completion-observation.json', 'ROW4_TRIGGERED'),
            ('row6', 'row6-real/late/completion-observation.json',
             'row6-real/misroute/completion-observation.json', 'LATE_NOT_ROW3'),
            ('row5', 'row5-controls/default-row5-restored.json',
             'row5-controls/default-retarget-p-run.json', 'DELTA_P'),
            ('bucket-small', 'bucket-small-real/equal.json',
             'bucket-small-real/attribution.json', 'BUCKET_FIXED_ATTRIBUTION'),
            ('bucket-full', 'bucket-full-real/full.json',
             'bucket-full-real/full-attribution-run.json', 'BUCKET_FIXED_ATTRIBUTION'),
            ('bucket-closed', 'bucket-closed-real/closed.json',
             'bucket-closed-real/closed-attribution-run.json', 'BUCKET_FIXED_ATTRIBUTION'),
            ('sweep-atomic', 'sweep-atomic-real/positive.json',
             'sweep-atomic-real/fees.json', 'D63_3_FEE_DESTINATIONS'))
        def paired_meta(module, case, data, assertion):
            module.expect_red(case, data, assertion)
            try:
                module.expect_red(case, data, assertion, observer=lambda case, observation: None)
            except module.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
            else:
                raise module.Violation('ORACLE_CONTROL_DRIVER_MISSING')
        for case, positive, negative, assertion in cases:
            oracle.check(case, json.loads((evidence / positive).read_text()))
            data = json.loads((evidence / negative).read_text())
            paired_meta(oracle, case, data, assertion)
            print('COMPLETION_META_REAL_OBSERVATION:' + case + ':' + assertion, flush=True)
            print('ORACLE_MISSING:' + assertion, flush=True)
        # Prove this meta driver can reject. Semantically remove the final
        # no-rejection failure from expect_red, without matching an error string.
        source = repo / 'crypto/test/workchain_withdrawal_completion_oracle.py'
        tree = ast.parse(source.read_text())
        targets = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'expect_red']
        if len(targets) != 1 or not isinstance(targets[0].body[-1], ast.Raise):
            raise RuntimeError('negative-driver semantic mutation shape changed')
        targets[0].body[-1] = ast.copy_location(ast.Return(value=None), targets[0].body[-1])
        ast.fix_missing_locations(tree)
        namespace = {'__name__': 'isolated_completion_oracle'}
        exec(compile(tree, str(source), 'exec'), namespace)
        from types import SimpleNamespace
        disabled = SimpleNamespace(**namespace)
        case, _, negative, assertion = cases[-1]
        try:
            paired_meta(disabled, case, json.loads((evidence / negative).read_text()), assertion)
        except disabled.Violation as error:
            if str(error) != 'ORACLE_CONTROL_DRIVER_MISSING':
                raise
            print(str(error), flush=True)
        else:
            raise RuntimeError('meta driver failed to detect removed negative-driver rejection')
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-oracle-control')
        raise SystemExit(0)

    def shadow_binary(label, old, replacement, relative="crypto/block/workchain-failed-funded.h",
                      native_units=(), extra_mutations=()):
        root = work / label
        header = root / relative
        header.parent.mkdir(parents=True)
        text = (repo / relative).read_text()
        if text.count(old) != 1:
            raise RuntimeError('semantic mutation target changed: ' + label)
        header.write_text(text.replace(old, replacement))
        if relative == 'crypto/test/workchain-m5-sweep.h':
            # A quoted include searches the caller's directory first. Shadow
            # that caller too, so the mutated callee is actually compiled.
            parent = root / 'crypto/test/workchain-m3-node-engine.h'
            parent.write_text((repo / 'crypto/test/workchain-m3-node-engine.h').read_text())
        for extra_relative, extra_old, extra_new in extra_mutations:
            extra = root / extra_relative
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra_text = (repo / extra_relative).read_text()
            if extra_text.count(extra_old) != 1:
                raise RuntimeError('semantic secondary mutation target changed: ' + label)
            extra.write_text(extra_text.replace(extra_old, extra_new))
        source = repo / 'test/test-m3-live.cpp'
        entries = [e for e in json.loads((build / 'compile_commands.json').read_text())
                   if Path(e['file']).as_posix().endswith('/test/test-m3-live.cpp')]
        if len(entries) != 1:
            raise RuntimeError('missing unique live compile command')
        command = shlex.split(entries[0]['command'])
        # Copy the caller: its quoted observer include must resolve the isolated
        # mutation, not the original caller directory. Other headers stay at the
        # configured Native source, avoiding a second copy of core types.
        compiled_source = root / 'test-m3-live.cpp'
        compiled_source.write_text(source.read_text())
        command[command.index(entries[0]['file'])] = str(compiled_source)
        command[1:1] = ['-I' + str(root), '-I' + str(root / 'test'), '-I' + str(root / 'crypto'), '-I' + str(repo / 'test'), '-I' + str(Path(entries[0]['file']).parent.parent / 'crypto/test')]
        obj = root / 'live.o'
        command[command.index('-o') + 1] = str(obj)
        with (root / 'build.log').open('w') as log:
            subprocess.run(command, cwd=build, stdout=log, stderr=log, check=True)
            native_objects = []
            for unit in native_units:
                # Some inline settlement code runs in the Native callers, not
                # the registered engine TU. Rebuild those exact consumers.
                matches = [e for e in json.loads((build / 'compile_commands.json').read_text())
                           if Path(e['file']).as_posix().endswith('/' + unit)]
                if len(matches) != 1:
                    raise RuntimeError('missing unique Native compile command: ' + unit)
                native_command = shlex.split(matches[0]['command'])
                native_command[1:1] = ['-I' + str(root), '-I' + str(root / 'crypto')]
                native_object = root / (Path(unit).stem + '.o')
                native_command[native_command.index('-o') + 1] = str(native_object)
                subprocess.run(native_command, cwd=build, stdout=log, stderr=log, check=True)
                native_objects.append(str(native_object))
            link = shlex.split(subprocess.check_output(['ninja', '-t', 'commands', 'test-m3-live'],
                                                       cwd=build, text=True).splitlines()[-1])
            if link[:2] != [':', '&&'] or link[-2:] != ['&&', ':']:
                raise RuntimeError('unrecognized live link command')
            link = link[2:-2]
            link[1:1] = native_objects
            original = 'CMakeFiles/test-m3-live.dir/test/test-m3-live.cpp.o'
            if link.count(original) != 1:
                raise RuntimeError('missing live object in link')
            link[link.index(original)] = str(obj)
            binary = root / 'test-m3-live'
            link[link.index('-o') + 1] = str(binary)
            subprocess.run(link, cwd=build, stdout=log, stderr=log, check=True)
        return binary

    def replay_paid(label, binary, source, case="row4", reader=None):
        target = work / label
        target.mkdir()
        for file in source.iterdir():
            if file.is_file() and not file.name.startswith(('enabled.', 'closed.', 'completion-observation')):
                shutil.copy2(file, target / file.name)
        shutil.copytree(source / 'db', target / 'db')
        shutil.copytree(source / 'm4-blocks', target / 'm4-blocks')
        before_id = (source / 'completion-before-block.id').read_text()
        (target / 'accepted-block.id').write_text(before_id)
        # Remove only post-predecessor observations, never authenticated inputs.
        height = int(before_id.split(')')[0].rsplit(',', 1)[1])
        for file in (target / 'm4-blocks').glob('*.boc'):
            if int(file.stem) > height:
                file.unlink()
        result = subprocess.run([str(binary), str(target)], text=True, capture_output=True)
        (target / 'completion-execution.log').write_text(result.stdout + result.stderr)
        output = target / 'completion-observation.json'
        subprocess.run([str(reader or build / 'test-m3-live'), '--completion-observation',
                        case, str(target), str(output)], check=True)
        return result.returncode, json.loads(output.read_text())

    if a.remaining_contract == 'phase-transition':
        def phase_fixture(label, delayed):
            args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                    '--fixture-parent', str(work), '--m5-completion-late', '--phase-replay-cuts']
            if delayed:
                args.append('--phase-delay-transit')
            with (work / (label + '.log')).open('w') as log:
                subprocess.run(args, stdout=log, stderr=log, check=True)
            paths = [Path(line.removeprefix('Test-owned fixture: '))
                     for line in (work / (label + '.log')).read_text().splitlines()
                     if line.startswith('Test-owned fixture: ')]
            if len(paths) != 1:
                raise RuntimeError('phase fixture did not publish one actual predecessor')
            return paths[0]
        def phase_observe(source, output, case):
            subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                            'phase-transition', str(source), str(output)], check=True)
            data = json.loads(output.read_text())
            return data
        def phase_replay(label, fixture, binary):
            destination = work / label
            shutil.copytree(fixture / 'phase-owner6-replay', destination)
            for path in fixture.glob('phase-*'):
                if path.is_file():
                    shutil.copy2(path, destination / path.name)
            for pattern in ('enabled.*', 'closed.*', 'debit-authenticated-*'):
                for path in destination.glob(pattern):
                    if path.is_file():
                        path.unlink()
            with (destination / 'producer.log').open('w') as log:
                result = subprocess.run([str(binary), str(destination)], stdout=log, stderr=log)
            # A pre-existing backing test may abort after real validation and
            # after saving this root. Require the actual accepted artifact;
            # never turn an arbitrary child error into the expected red.
            for origin, suffix in (('enabled.candidate', '.candidate'),
                                   ('enabled.result.validation.result', '.validation'),
                                   ('debit-authenticated-state.boc', '-after.boc')):
                shutil.copyfile(destination / origin, destination / ('phase-owner6' + suffix))
            data = phase_observe(destination, destination / 'phase-observed.json', '')
            return result.returncode, data
        def phase_red(data, case, assertion):
            oracle.expect_red(case, data, assertion)
            print('REMAINING_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red(case, data, assertion, observer=lambda *_: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('phase oracle removal did not fail')
        ordinary = phase_fixture('ordinary', False)
        queued = phase_fixture('queued', True)
        for label, fixture, case in (('ordinary', ordinary, 'phase-transition'),
                                     ('queued', queued, 'phase-still-present')):
            oracle.check(case, phase_observe(fixture, work / (label + '.json'), case))
        needle = 'const auto retained_records = migrated.control.withdrawals.size();'
        mutated = needle + '\n      for (auto& r : migrated.control.withdrawals) if (r.timing.phase == 1) r.timing.queue_removed_height = r.timing.opened_height;'
        binary = shadow_binary('phase-q-link', needle, mutated, 'crypto/test/workchain-m3-node-engine.h')
        _, data = phase_replay('q-link-run', ordinary, binary)
        phase_red(data, 'phase-transition', 'PHASE_STRICT_HEIGHT')
        code, restored = phase_replay('q-link-restored', ordinary, build / 'test-m3-live')
        if code:
            raise RuntimeError('restored phase execution failed')
        oracle.check('phase-transition', restored)
        present = 'if (queue_height_ <= opened_height || queued_.count({custody, created_lt}))'
        binary = shadow_binary('phase-presence', present, 'if (queue_height_ <= opened_height)',
                               'crypto/block/workchain-account-engine.h')
        code, data = phase_replay('presence-run', queued, binary)
        if code:
            raise RuntimeError('presence mutant did not reach the accepted host boundary')
        phase_red(data, 'phase-still-present', 'PHASE_QUEUE_BINDING')
        code, restored = phase_replay('presence-restored', queued, build / 'test-m3-live')
        if code:
            raise RuntimeError('restored queued execution failed')
        oracle.check('phase-still-present', restored)
        # Do not publish a ready marker for only the presently wired subset.
        raise RuntimeError('M5-REMAINING phase-transition incomplete: paired creation/orphan, read-height, wrong observation, later observation and deadline controls')

    if a.completion_contract == 'sweep-atomic':
        # The fixture, account observations and all mutations run the real host.
        # Architecture-level publication isolation is explicitly NOT certified.
        observer_header = 'test/m5-completion-observer.h'
        reader = shadow_binary('reader', '#pragma once', '#pragma once', observer_header)
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--fixture-parent', str(work),
                '--completion-sweep']
        with (work / 'positive.log').open('w') as log:
            subprocess.run(args, stdout=log, stderr=log, check=True)
        paths = [Path(line.removeprefix('COMPLETION_SWEEP_FIXTURE:'))
                 for line in (work / 'positive.log').read_text().splitlines()
                 if line.startswith('COMPLETION_SWEEP_FIXTURE:')]
        if len(paths) != 1:
            raise RuntimeError('sweep fixture did not publish exactly one round')
        positive = paths[0]
        def observe(label, fixture, binary=reader):
            output = work / (label + '.json')
            subprocess.run([str(binary), '--completion-observation', 'sweep-atomic',
                            str(fixture), str(output)], check=True)
            return json.loads(output.read_text())
        data = observe('positive', positive)
        oracle.check('sweep-atomic', data)
        def red(data, assertion):
            oracle.expect_red('sweep-atomic', data, assertion)
            print('COMPLETION_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red('sweep-atomic', data, assertion,
                                  observer=lambda case, observation: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('disabled oracle did not fail')
        native = ('validator/impl/collator.cpp', 'validator/impl/validate-query.cpp')
        transfer_old = '    entry.store_long(0x6b953015, 32).store_bits(it->from.bits(), 256).store_bits(it->to.bits(), 256);'
        transfer_new = '''    auto destination = it->to;
    if (effects.bucket_sweep_credit) {
      std::fill(destination.as_slice().begin(), destination.as_slice().end(), 0x11);
      LOG(ERROR) << "SWEEP_TRANSFER_ENCODING_MUTATION_REACHED";
    }
    entry.store_long(0x6b953015, 32).store_bits(it->from.bits(), 256).store_bits(destination.bits(), 256);'''
        fee_old = '      result.bucket_sweep_credit = WorkchainAccountEffects::BucketSweepCredit{'
        fee_new = '''      LOG(ERROR) << "SWEEP_FEE_MUTATION_REACHED";
      CHECK(!__builtin_add_overflow(credit.slot, credit.compute, &credit.slot));
      credit.compute = 0;
''' + fee_old
        credit_old = '''    owner.origin_pending.push_back({id, amount,
        {owner.account.address.instance, owner.account.key_epoch, owner.account.bindings.asset}, encoded, origin});'''
        cases = (
            ('physical', 'crypto/block/workchain-account-effects.h', transfer_old, transfer_new,
             'SWEEP_TRANSFER_ENCODING_MUTATION_REACHED', 'D63_1_PHYSICAL_TRANSFER', native),
            ('fees', 'crypto/test/workchain-m3-node-engine.h', fee_old, fee_new,
             'SWEEP_FEE_MUTATION_REACHED', 'D63_3_FEE_DESTINATIONS', ()),
            ('credit', 'crypto/test/workchain-m5-sweep.h', credit_old,
             '    LOG(ERROR) << "SWEEP_CREDIT_MUTATION_REACHED";',
             'SWEEP_CREDIT_MUTATION_REACHED', 'D63_4_INSTALLED_CREDIT', ()))
        for label, relative, old, new, marker, assertion, units in cases:
            binary = shadow_binary(label, old, new, relative, native_units=units)
            _, changed = replay_paid(label + '-run', binary, positive, 'sweep-atomic', reader)
            if marker not in (work / (label + '-run/completion-execution.log')).read_text():
                raise RuntimeError('mutated production path not executed: ' + label)
            red(changed, assertion)
            if label == 'fees':
                # A symmetric wrong fee destination still satisfies both sums.
                for state in (changed['observed']['before'], changed['observed']['after']):
                    assert state['R_actual'] == state['R_book']
                    assert state['R_actual'] + state['P'] == state['D'] + state['N_book'] + state['W']
        hold_old = '    bucket.entries.erase(bucket.entries.begin());'
        hold_new = '    LOG(ERROR) << "SWEEP_HOLDINGS_MUTATION_REACHED";'
        helper = 'crypto/test/workchain-m5-sweep.h'
        blocked = shadow_binary('holdings', hold_old, hold_new, helper)
        code, failed = replay_paid('holdings-run', blocked, positive, 'sweep-atomic', reader)
        failed_fixture = work / 'holdings-run'
        if not code or failed['observed']['published'] or (failed_fixture / 'enabled.candidate').exists():
            raise RuntimeError('D60 failed to block the real holdings omission')
        if 'SWEEP_HOLDINGS_MUTATION_REACHED' not in (failed_fixture / 'completion-execution.log').read_text():
            raise RuntimeError('holdings mutation not executed')
        carrier = shadow_binary('holdings-carrier', hold_old, hold_new, helper, native_units=native,
            extra_mutations=(('crypto/block/workchain-account-settlement.h',
                              'expected_holdings != new_holdings', 'false /* remove only D60 pairing */'),))
        _, changed = replay_paid('holdings-carrier-run', carrier, positive, 'sweep-atomic', reader)
        red(changed, 'D63_2_HOLDINGS')
        print('D63_2_PRIMARY_CARRIER:D60_PAIRING', flush=True)
        # Retry the actual failed input, not a newly issued authorization.
        pinned = {name: (failed_fixture / name).read_bytes()
                  for name in ('zerostate.boc', 'completion-before-state.boc', 'accepted-block.id')}
        for name in ('enabled-db', 'closed-db'):
            shutil.rmtree(failed_fixture / name, ignore_errors=True)
        for file in failed_fixture.glob('enabled.*'):
            file.unlink()
        with (work / 'retry.log').open('w') as log:
            subprocess.run([str(reader), str(failed_fixture)], stdout=log, stderr=log, check=True)
        for name in ('zerostate.boc', 'completion-before-state.boc'):
            if (failed_fixture / name).read_bytes() != pinned[name]:
                raise RuntimeError('retry changed authenticated authorization/predecessor')
        restored = observe('retry', failed_fixture)
        oracle.check('sweep-atomic', restored)
        if restored['observed']['authorized_sequence'] != data['observed']['authorized_sequence']:
            raise RuntimeError('retry used a different authorization')
        print('REAL_RETRY_AFTER_UNPUBLISHED_SAME_AUTH', flush=True)
        # Same-height replay: real verifier, authenticated old/consumed buckets,
        # identical height. This is not a second Native publication attempt.
        def reuse_check(value):
            o = value['observed']
            oracle.require(o['authorization_before_ok'] is True, 'SWEEP_AUTH_BEFORE')
            oracle.require(o['authorization_after_same_height_code'] == -7200, 'SWEEP_CONSUMED_SAME_HEIGHT')
        reuse_check(data)
        reuse = shadow_binary('reuse', 'authorization.sequence != *bucket.sweep_sequence',
                              'false /* remove consumed-round comparison */', helper)
        changed = observe('reuse', positive, reuse)
        def reuse_red(value, check=reuse_check):
            try:
                check(value)
            except oracle.Violation as error:
                oracle.require(str(error) == 'SWEEP_CONSUMED_SAME_HEIGHT', 'WRONG_FAILURE_LAYER:' + str(error))
                return
            raise oracle.Violation('ORACLE_MISSING:SWEEP_CONSUMED_SAME_HEIGHT')
        reuse_red(changed)
        print('REAL_VERIFIER_RED:SWEEP_CONSUMED_SAME_HEIGHT', flush=True)
        try:
            reuse_red(changed, check=lambda value: None)
        except oracle.Violation as error:
            if str(error) != 'ORACLE_MISSING:SWEEP_CONSUMED_SAME_HEIGHT':
                raise
            print(str(error), flush=True)
        else:
            raise RuntimeError('reuse oracle disabled without detection')
        old = 'auto native=sweep_native_observation(accepted.block,ingress.executor_address,*ingress.custody_address);'
        height = data['observed']['height']
        new = ('auto native=sweep_native_observation(block_at(' + json.dumps(str(failed_fixture)) + ',' +
               str(height) + '),ingress.executor_address,*ingress.custody_address);')
        mixed = shadow_binary('mixed', old, new, observer_header)
        changed = observe('mixed', positive, mixed)
        if changed['observed']['before'] != data['observed']['before'] or changed['observed']['after'] != data['observed']['after']:
            raise RuntimeError('mixed-block control changed amounts instead of provenance')
        red(changed, 'D63_SAME_BATCH')
        print('ATOMICITY_SCOPE:section9.3 architecture; no premature-publication control; regression gap open')
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-sweep-atomic')
        raise SystemExit(0)

    if a.completion_contract == 'row4':
        def paid_fixture(label, full=False):
            args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                    '--fixture-parent', str(work), '--m5-completion-paid']
            if full:
                args += ['--completion-full-cap']
            with (work / (label + '.log')).open('w') as log:
                completed = subprocess.run(args, stdout=log, stderr=log)
            completed.check_returncode()
            paths = [Path(line.removeprefix('COMPLETION_PAID_FIXTURE:'))
                     for line in (work / (label + '.log')).read_text().splitlines()
                     if line.startswith('COMPLETION_PAID_FIXTURE:')]
            if len(paths) != 1:
                raise RuntimeError('Paid fixture did not reach the frozen oracle')
            data = json.loads((paths[0] / 'completion-observation.json').read_text())
            oracle.check('row4', data)
            if full and (data['input']['withdrawal_limit'] != 3 or
                         len(data['observed']['before']['records']) != 3):
                raise RuntimeError('full-cap test did not start with three obligations')
            return paths[0]

        positive = paid_fixture('positive')
        paid_fixture('full-cap', full=True)
        effect = '      return finish(std::move(result));\n    }\n    if (is_m5_test_failed(host.candidate))'
        mutations = (
            ('skip-expiry', 'crypto/block/workchain-withdrawal-expiry.h',
             '    if (authenticated_height <= deadline) {',
             '    if (true) { // Isolated mutation: never close an expired record.', 'ROW4_TRIGGERED'),
            ('round-trip', 'crypto/test/workchain-m3-node-engine.h', effect,
             '      result.native_transfers.push_back({cfg->ingress.executor_address, *cfg->ingress.custody_address, CurrencyCollection(1)});\n'
             '      result.native_transfers.push_back({*cfg->ingress.custody_address, cfg->ingress.executor_address, CurrencyCollection(1)});\n' + effect,
             'ROW4_NO_VALUE_MOVEMENT'),
            ('extra-fee', 'crypto/test/workchain-m3-node-engine.h', effect,
             '      result.fees->compute_fee = result.fees->compute_fee + td::make_refint(1);\n' + effect,
             'DELTA_R_actual'))
        for label, relative, old, new, assertion in mutations:
            binary = shadow_binary(label, old, new, relative)
            _, data = replay_paid(label + '-run', binary, positive)
            oracle.expect_red('row4', data, assertion)
            print('COMPLETION_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red('row4', data, assertion, observer=lambda case, observation: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('disabled oracle did not fail')
        code, restored = replay_paid('restored', build / 'test-m3-live', positive)
        if code:
            raise RuntimeError('restored Paid execution failed')
        oracle.check('row4', restored)
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-row4')
        raise SystemExit(0)

    def closed_late_fixture():
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--fixture-parent', str(work),
                '--m5-completion-late', '--completion-close-before-return']
        with (work / 'closed-late.log').open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=log)
        result.check_returncode()
        lines = (work / 'closed-late.log').read_text().splitlines()
        fixtures, observations = {}, {}
        for name, case in (('PAID', 'row5-paid'), ('LATE', 'row5')):
            prefix = 'COMPLETION_ROW5_' + name + ':'
            paths = [Path(line[len(prefix):]) for line in lines if line.startswith(prefix)]
            if len(paths) != 1:
                raise RuntimeError('missing unique executed row5 predecessor/return: ' + name)
            output = paths[0] / 'completion-observation.json'
            if output.exists():
                raise RuntimeError('row5 observation must be independently produced')
            subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                            case, str(paths[0]), str(output)], check=True)
            fixtures[name] = paths[0]
            observations[name] = json.loads(output.read_text())
        paid, late = observations['PAID'], observations['LATE']
        oracle.check('row4', paid)
        oracle.check('row5', late)
        for field in ('withdrawal_id', 'x', 'Q', 'window', 'phase'):
            oracle.require(paid['input'][field] == late['input'][field], 'SAME_CLOSED_WITHDRAWAL')
        oracle.require(paid['input']['height'] < late['input']['height'], 'CLOSURE_PRECEDES_RETURN')
        # The late import consumes exactly the installed Paid predecessor;
        # matching only an ID or a missing record would not prove this ordering.
        oracle.require(paid['provenance']['after'] == late['provenance']['before'],
                       'PAID_ROOT_IS_LATE_PREDECESSOR')
        oracle.require(paid['input']['withdrawal_id'] not in
                       late['observed']['before']['records'], 'ROW5_ALREADY_CLOSED')
        return fixtures, observations

    if a.completion_contract == 'row5':
        fixtures, _ = closed_late_fixture()
        old = '    const auto attempt = association->attempt_id;\n    if (matched) owner.control.withdrawals.erase(found);'
        mutations = (
            ('retarget-p',
             '    if (!matched && !owner.control.withdrawals.empty()) owner.control.withdrawals.front().timing.payout_created_lt = association->payout_created_lt;\n' + old,
             'DELTA_P'),
            ('decrement-w',
             '    if (!matched && !owner.control.withdrawals.empty()) {\n'
             '      auto& principal = owner.control.withdrawals.front().principal;\n'
             '      if (__builtin_sub_overflow(principal, std::uint64_t{1}, &principal)) return error("isolated checked decrement failed");\n'
             '    }\n' + old, 'RECORD_CLOSURE'))
        for label, changed, assertion in mutations:
            binary = shadow_binary(label, old, changed)
            _, data = replay_paid(label + '-run', binary, fixtures['LATE'], 'row5')
            before, after = data['observed']['before'], data['observed']['after']
            oracle.require(data['observed']['published'] is True and
                           data['observed']['dispatch'] == ['late-return-admission'], 'MUTANT_REACHED_LATE_PUBLICATION')
            if label == 'retarget-p':
                oracle.require(before['records'] == after['records'] and before['W'] == after['W'] and
                               before['P'] != after['P'], 'P_MUTATION_ISOLATED')
            else:
                oracle.require(before['P'] == after['P'] and before['W'] - after['W'] == 1,
                               'W_MUTATION_ISOLATED')
                changed_ids = [key for key in before['records']
                               if after['records'].get(key) != before['records'][key]]
                oracle.require(len(changed_ids) == 1 and set(before['records']) == set(after['records']) and
                               before['records'][changed_ids[0]] - after['records'][changed_ids[0]] == 1 and
                               data['input']['withdrawal_id'] not in before['records'],
                               'W_RECORD_CHANGE_CAUSES_RELEASE')
            oracle.expect_red('row5', data, assertion)
            print('COMPLETION_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red('row5', data, assertion, observer=lambda *_: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('disabled row5 oracle did not fail')
            if label == 'decrement-w':
                # Remove precisely the comparison of the installed record map,
                # not a diagnostic string or any other oracle. Same real artifact.
                tree = ast.parse((repo / 'crypto/test/workchain_withdrawal_completion_oracle.py').read_text())
                target = ast.dump(ast.parse("after['records'] == records", mode='eval').body)
                removed = []
                class WithoutRecordComparison(ast.NodeTransformer):
                    def visit_Expr(self, node):
                        call = node.value
                        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and
                                call.func.id == 'require' and call.args and ast.dump(call.args[0]) == target):
                            removed.append(node)
                            return ast.copy_location(ast.Pass(), node)
                        return self.generic_visit(node)
                tree = WithoutRecordComparison().visit(tree)
                oracle.require(len(removed) == 1, 'UNIQUE_RECORD_ORACLE_MUTATION')
                scope = {'__name__': 'isolated_record_oracle'}
                exec(compile(ast.fix_missing_locations(tree), '<isolated-record-oracle>', 'exec'), scope)
                try:
                    scope['check']('row5', data)
                except scope['Violation'] as error:
                    oracle.require(str(error) == 'DELTA_W', 'W_CROSSCHECK_WRONG_FAILURE_LAYER')
                    print('UPSTREAM_REMOVED_SAME_ARTIFACT:DELTA_W', flush=True)
                else:
                    raise RuntimeError('W cross-check missing after removing its upstream carrier')
        code, restored = replay_paid('row5-restored', build / 'test-m3-live', fixtures['LATE'], 'row5')
        if code:
            raise RuntimeError('restored row5 execution failed')
        oracle.check('row5', restored)
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-row5')
        raise SystemExit(0)

    if a.completion_contract == 'row6':
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--fixture-parent', str(work),
                '--m5-completion-late', '--completion-window-pair']
        with (work / 'window-pair.log').open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=log)
        result.check_returncode()
        lines = (work / 'window-pair.log').read_text().splitlines()
        fixtures, observations = {}, {}
        for name in ('WITHIN', 'LATE'):
            prefix = 'COMPLETION_WINDOW_' + name + ':'
            paths = [Path(line[len(prefix):]) for line in lines if line.startswith(prefix)]
            if len(paths) != 1:
                raise RuntimeError('missing unique authenticated window branch: ' + name)
            fixtures[name] = paths[0]
            output = paths[0] / 'completion-observation.json'
            if output.exists():
                raise RuntimeError('window observation must be independently produced')
            subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                            'row6', str(paths[0]), str(output)], check=True)
            observations[name] = json.loads(output.read_text())
        within, late = observations['WITHIN'], observations['LATE']
        wi, li = within['input'], late['input']
        for field in ('withdrawal_id', 'x', 'Q', 'window', 'phase'):
            oracle.require(wi[field] == li[field], 'SAME_AUTHENTICATED_WINDOW_RECORD')
        end = oracle.checked(wi['Q'] + wi['window'])
        oracle.require(wi['phase'] == 1 and wi['height'] == end and
                       li['height'] == oracle.checked(end + 1), 'EXACT_HEIGHT_BOUNDARIES')
        o = within['observed']
        oracle.require(o['published'] is True and o['dispatch'] == ['within-window-failed'],
                       'WITHIN_WINDOW_EXECUTED')
        before, after = o['before'], o['after']
        g = oracle.checked(wi['base'] * wi['units'])
        amount = oracle.checked(wi['y'] - oracle.checked(wi['slot'] + g))
        oracle.require(amount > 0, 'WITHIN_WINDOW_POSITIVE_RECEIPT')
        deltas = dict.fromkeys(oracle.FIELDS, 0)
        for field in ('R_actual', 'R_book', 'N_book'):
            deltas[field] = amount
        deltas.update(P=-wi['x'], W=-wi['x'], coordinator=wi['slot'], issuance_fees=g, sequence=1)
        for field in oracle.FIELDS:
            oracle.checked(before[field]); oracle.checked(after[field])
            oracle.require(after[field] - before[field] == deltas[field], 'WITHIN_DELTA_' + field)
        records = dict(before['records'])
        oracle.require(records.pop(wi['withdrawal_id'], None) == wi['x'], 'WITHIN_OPEN_RECORD')
        oracle.require(after['records'] == records, 'WITHIN_RECORD_CLOSURE')
        oracle.require(after['pending'] == before['pending'] +
                       [{'target': wi['account_id'], 'amount': amount}], 'WITHIN_RECEIPT')
        oracle.check('row6', late)
        binary = shadow_binary('row3-misroute', '      late = arrival_height > deadline;',
                               '      late = false; // Isolated mutation: route an open expired record to row3.')
        _, data = replay_paid('row3-misroute-run', binary, fixtures['LATE'], 'row6')
        oracle.expect_red('row6', data, 'LATE_NOT_ROW3')
        print('COMPLETION_REAL_RED:LATE_NOT_ROW3', flush=True)
        try:
            oracle.expect_red('row6', data, 'LATE_NOT_ROW3', observer=lambda *_: None)
        except oracle.Violation as error:
            if str(error) != 'ORACLE_MISSING:LATE_NOT_ROW3':
                raise
            print(str(error), flush=True)
        else:
            raise RuntimeError('disabled dispatch oracle did not fail')
        code, restored = replay_paid('row6-restored', build / 'test-m3-live', fixtures['LATE'], 'row6')
        if code:
            raise RuntimeError('restored late execution failed')
        oracle.check('row6', restored)
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-row6')
        raise SystemExit(0)

    if a.completion_contract == 'bucket-closed':
        # The counterpart has a closed Withdrawal but an active account.
        # Do not confuse it with the genuinely closed-account case below.
        _, active = closed_late_fixture()
        oracle.require(active['LATE']['input']['account_closed'] is False, 'ACTIVE_ACCOUNT_COUNTERPART')
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--fixture-parent', str(work),
                '--m5-completion-late', '--completion-close-account-before-return']
        with (work / 'closed-account.log').open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=log)
        result.check_returncode()
        prefix = 'COMPLETION_CLOSED_ACCOUNT:'
        paths = [Path(line[len(prefix):]) for line in (work / 'closed-account.log').read_text().splitlines()
                 if line.startswith(prefix)]
        if len(paths) != 1:
            raise RuntimeError('missing actual account-closure fixture')
        source = paths[0]
        output = source / 'completion-observation.json'
        if output.exists():
            raise RuntimeError('closed account observation must be independently produced')
        subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                        'bucket-closed', str(source), str(output)], check=True)
        data = json.loads(output.read_text())
        oracle.check('bucket-closed', data)
        oracle.require(data['provenance'].get('real_account_closure') is True, 'REAL_ACCOUNT_CLOSURE')
        for label, old, changed, assertion in (
            ('closed-refusal', '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
             '      return error("isolated bucket disposition refusal");\n'
             '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
             'DISPOSITION_MUST_PUBLISH'),
            ('closed-attribution', '        credited.bucket.entries.back().account_id = owner.account.address.account;',
             '        // Isolated mutation: omit beneficiary from the installed bucket.', 'BUCKET_FIXED_ATTRIBUTION')):
            binary = shadow_binary(label, old, changed)
            _, data = replay_paid(label + '-run', binary, source, 'bucket-closed')
            oracle.expect_red('bucket-closed', data, assertion)
            print('COMPLETION_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red('bucket-closed', data, assertion, observer=lambda *_: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('disabled closed-account oracle did not fail')
        code, data = replay_paid('closed-restored', build / 'test-m3-live', source, 'bucket-closed')
        if code:
            raise RuntimeError('restored closed-account execution failed')
        oracle.check('bucket-closed', data)
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-bucket-closed')
        raise SystemExit(0)

    if a.completion_contract == 'bucket-full':
        def slot_fixture(free_one):
            label = 'free-one' if free_one else 'full'
            args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                    '--fixture-parent', str(work),
                    '--m5-completion-late', '--completion-no-slot']
            if free_one:
                args.append('--completion-free-one-slot')
            with (work / (label + '.log')).open('w') as log:
                result = subprocess.run(args, stdout=log, stderr=log)
            result.check_returncode()
            prefix = 'Test-owned fixture: '
            paths = [Path(line[len(prefix):]) for line in (work / (label + '.log')).read_text().splitlines()
                     if line.startswith(prefix)]
            if len(paths) != 1:
                raise RuntimeError('missing unique full-slot Native fixture')
            case = 'row6' if free_one else 'bucket-full'
            output = paths[0] / 'completion-observation.json'
            if output.exists():
                raise RuntimeError('slot observation must be independently produced')
            subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                            case, str(paths[0]), str(output)], check=True)
            data = json.loads(output.read_text())
            oracle.check(case, data)
            i = data['input']
            oracle.require(i['y'] > oracle.checked(i['slot'] + oracle.checked(i['base'] * i['units'])),
                           'FULL_SLOT_NOT_SMALL_VALUE')
            if free_one:
                oracle.require(data['provenance'].get('collected_one_real_slot') is True and
                               i['system_count'] + 1 == i['system_limit'], 'REAL_COLLECT_FREED_ONE_SLOT')
            return paths[0]
        full = slot_fixture(False)
        slot_fixture(True)
        for label, old, changed, assertion in (
            ('full-refusal', '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
             '      return error("isolated bucket disposition refusal");\n'
             '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
             'DISPOSITION_MUST_PUBLISH'),
            ('full-attribution', '        credited.bucket.entries.back().account_id = owner.account.address.account;',
             '        // Isolated mutation: omit beneficiary from the installed bucket.', 'BUCKET_FIXED_ATTRIBUTION')):
            binary = shadow_binary(label, old, changed)
            _, data = replay_paid(label + '-run', binary, full, 'bucket-full')
            oracle.expect_red('bucket-full', data, assertion)
            print('COMPLETION_REAL_RED:' + assertion, flush=True)
            try:
                oracle.expect_red('bucket-full', data, assertion, observer=lambda *_: None)
            except oracle.Violation as error:
                if str(error) != 'ORACLE_MISSING:' + assertion:
                    raise
                print(str(error), flush=True)
            else:
                raise RuntimeError('disabled full-slot oracle did not fail')
        code, data = replay_paid('full-restored', build / 'test-m3-live', full, 'bucket-full')
        if code:
            raise RuntimeError('restored full-slot execution failed')
        oracle.check('bucket-full', data)
        print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-bucket-full')
        raise SystemExit(0)

    def run_boundary(label, principal=None, offset=None):
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--fixture-parent', str(work),
                '--m5-bucket-small', '--m5-completion-late']
        if principal is not None:
            args += ['--m5-return-principal', str(oracle.checked(principal)),
                     '--completion-expect-offset', str(offset)]
        with (work / (label + '.log')).open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=log)
        lines = (work / (label + '.log')).read_text().splitlines()
        fixtures = [Path(line.removeprefix('Test-owned fixture: ')) for line in lines
                    if line.startswith('Test-owned fixture: ')]
        if len(fixtures) != 1:
            raise RuntimeError(f'{label}: missing unique live fixture; see {work}')
        if result.returncode:
            raise RuntimeError(f'{label}: real boundary run failed ({result.returncode}); see {work}')
        data = json.loads((fixtures[0] / 'completion-observation.json').read_text())
        return fixtures[0], data

    _, calibration = run_boundary('calibration')
    ci = calibration['input']
    h = oracle.checked(oracle.checked(ci['slot']) + oracle.checked(ci['base'] * ci['units']))
    loss = oracle.checked(ci['x'] - ci['y'])
    samples = {}
    for offset, label in ((-1, 'below'), (0, 'equal'), (1, 'above')):
        # Native loss is measured, not a tariff default. Each new run checks its
        # actual y against the requested boundary, so size-dependent repricing
        # cannot silently turn these into tests of different input values.
        samples[label] = run_boundary(label, oracle.checked(oracle.checked(h + loss) + offset), offset)
    for fixture_path, data in samples.values():
        i = data['input']
        if i['phase'] != 1 or i['height'] <= oracle.checked(i['Q'] + i['window']):
            raise RuntimeError('COMPLETION_NOT_READY: authenticated late-phase fixture missing')

    def replay(label, binary):
        source = samples['below'][0]
        target = work / label
        target.mkdir()
        for file in source.iterdir():
            if file.is_file() and not file.name.startswith(('enabled.', 'closed.', 'completion-observation')):
                shutil.copy2(file, target / file.name)
        shutil.copytree(source / 'db', target / 'db')
        shutil.copytree(source / 'm4-blocks', target / 'm4-blocks')
        before_id = (source / 'completion-before-block.id').read_text()
        (target / 'accepted-block.id').write_text(before_id)
        height = int(before_id.split(')')[0].rsplit(',', 1)[1])
        for file in (target / 'm4-blocks').glob('*.boc'):
            if int(file.stem) > height:
                file.unlink()
        result = subprocess.run([str(binary), str(target)], text=True, capture_output=True)
        (target / 'completion-execution.log').write_text(result.stdout + result.stderr)
        output = target / 'completion-observation.json'
        # The unmodified adapter checks actual callee execution even when the
        # mutant refuses before publication; an earlier failure is not a red.
        subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                        'bucket-small', str(target), str(output)], check=True)
        return result.returncode, json.loads(output.read_text())

    for label, target, replacement, assertion in (
        ('refusal', '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
         '      return error("isolated bucket disposition refusal");\n'
         '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
         'DISPOSITION_MUST_PUBLISH'),
        ('attribution', '        credited.bucket.entries.back().account_id = owner.account.address.account;',
         '        // Isolated mutation: omit the beneficiary from the installed bucket entry.',
         'BUCKET_FIXED_ATTRIBUTION')):
        binary = shadow_binary(label, target, replacement)
        _, data = replay(label + '-run', binary)
        oracle.expect_red('bucket-small', data, assertion)
        print('COMPLETION_REAL_RED:' + assertion, flush=True)
        try:
            oracle.expect_red('bucket-small', data, assertion, observer=lambda case, observation: None)
        except oracle.Violation as error:
            if str(error) != 'ORACLE_MISSING:' + assertion:
                raise
            print(str(error), flush=True)
        else:
            raise RuntimeError('disabled oracle driver did not fail')
    code, restored = replay('restored', build / 'test-m3-live')
    if code != 0:
        raise RuntimeError('restored real execution failed')
    oracle.check('bucket-small', restored)
    print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-bucket-small')
    raise SystemExit(0)

fixture = live_fixture('uno-m3-live-')
wallet = pin(repo, build / 'm3-vector-wallet-target/release/examples/m3-scenario', fixture)
# Establish that the same numeric predicate used after each accepted block
# rejects unpaired principal and nonzero cross-block D, then restores to green.
# A crash, unknown mode or missing binary is not an expected rejection.
for mode, expected in [('unpaired', 1), ('cross-block-d', 1), ('restored', 0)]:
    control = subprocess.run([str(build / 'test-m3-live'), '--m4-backing-control', mode],
                             text=True, capture_output=True)
    if control.returncode != expected or f'M4 backing control {mode}:' not in control.stdout:
        raise RuntimeError(f'backing control {mode}: rc={control.returncode}, '
                           f'stdout={control.stdout}, stderr={control.stderr}')
    if expected and 'M4 per-block backing mismatch or nonzero cross-block D' not in control.stdout:
        raise RuntimeError('backing control failed for an unrelated reason')
    print(f'Backing control exit={control.returncode}: {control.stdout.strip()}', flush=True)
# Reader-only controls: distinguish unavailable evidence from actual zero/one.
# Real counter emission is separately exercised by Failed fault injection below.
probe = fixture / 'unknown-reader-probe'
for value, expected, code, diagnostic in [
        (None, '0', 2, 'UNKNOWN_ORIGIN_OBSERVATION_UNAVAILABLE:'),
        ('0\n', '0', 0, ''), ('1\n', '1', 0, ''),
        ('1\n', '0', 2, 'UNKNOWN_ORIGIN_OBSERVATION_MISMATCH:')]:
    if value is not None:
        probe.write_text(value)
    result = subprocess.run([str(build / 'test-m3-live'), '--check-unknown-observation', str(probe), expected],
                            text=True, capture_output=True)
    if result.returncode != code or diagnostic not in result.stderr:
        raise RuntimeError(f'unknown observation reader control failed: {result.returncode}; {result.stderr}')
print('UNKNOWN_READER_CONTROLS: unavailable / zero / one / mismatch distinguished', flush=True)
# Reuse the existing test-owned genesis construction without its collation
# scenarios or cleanup. Never import a deployment DB/configuration. This prefix
# contains all schema-dependent fixture code; do not maintain a second copy.
source = (repo / 'test/test-counter-disk-integration.cmake').read_text()
marker = 'set(node_db "${fixture}/db")\nfunction(run_node'
if source.count(marker) != 1:
    raise RuntimeError('genesis preparation boundary changed')
(fixture / '.counter-managed-v1').write_text('M3 test-owned fixture, not a deployment source.\n')
prepare = fixture / 'prepare.cmake'
if a.completion_sweep:
    (fixture / 'completion-sweep.txt').write_text('1\n')
subprocess.run([str(build / 'test-m3-live'), '--m4-coordinator-data',
                str(fixture / 'coordinator-data.boc')], check=True)
# Keep all instance issuance in the existing create-state route. Change the
# wc=2 state BEFORE its descriptor/instance are issued, never after hashing it.
# These operating coins are assumed test state, not M4 Deposit or principal.
shard = (repo / 'test/counter-shard-genesis.fif').read_text()
old_account = ('empty_cell\n<b x{57424531} s, 0 1 u, <b 40 64 u, b> ref, b>\n'
               'empty_cell 1000 0 0 0 6 register_smc drop')
if shard.count(old_account) != 1:
    raise RuntimeError('test coordinator construction changed')
shard = shard.replace(old_account, '<{ 63 THROW }>c\n"coordinator-data.boc" file>B B>boc\n'
                      'empty_cell 1000000000 0 0 0 6 register_smc drop')
if True:
    # Zero principal custody exists before descriptor issuance. This is not
    # confidential test funding: every later principal coin must be imported.
    # Nonempty inert data is a fixture representation choice: register_smc
    # omits empty data, whereas engine update rows require a present data cell.
    shard = shard.replace('create_state\n', '<{ 63 THROW }>c\n<b 0 1 u, b>\n'
                          'empty_cell 0 0 0 256 1<<1- 6 register_smc drop\ncreate_state\n')
(fixture / 'm3-shard-genesis.fif').write_text(shard)
if a.m5_completion_paid:
    sender = (repo / 'test/m3-native-sender.fif').read_text()
    if sender.count('create_state\n') != 1:
        raise RuntimeError('Native sender genesis boundary changed')
    recipient = int('22' * 32,16)
    sender = sender.replace('create_state\n',
        f'<{{ 0 PUSHINT DROP }}>c\nempty_cell empty_cell 0 0 0 {recipient} 6 register_smc drop\ncreate_state\n')
    (fixture / 'm3-native-paid.fif').write_text(sender)
if a.completion_close_account_before_return:
    sender = (repo / 'test/m3-native-sender.fif').read_text()
    entry = '<{ DROP ACCEPT LDREF ENDS 1 PUSHINT SENDRAWMSG }>c'
    if sender.count(entry) != 1:
        raise RuntimeError('Native test payer entry changed')
    # The real closure refund must be accepted by its Native beneficiary.
    # Otherwise this external-only fixture wallet bounces it back as a second
    # input alongside the payout return. Do not discard that input or relax
    # the one-input host profile. External (-1) execution is unchanged.
    sender = sender.replace(entry, '<{ DUP IFNOTRET DROP ACCEPT LDREF ENDS 1 PUSHINT SENDRAWMSG }>c')
    (fixture / 'm3-native-closed.fif').write_text(sender)
prefix = source.split(marker)[0]
route = '  set(script_path "${SOURCE_DIR}/test/${script}.fif")'
if prefix.count(route) != 1:
    raise RuntimeError('test genesis script route changed')
prefix = prefix.replace(route, route + '''
  if(script STREQUAL "counter-shard-genesis")
    set(script_path "${fixture}/m3-shard-genesis.fif")
  elseif(script STREQUAL "counter-native-sender")
    set(script_path "${SOURCE_DIR}/test/m3-native-sender.fif")
  endif()''')
if a.m5_completion_paid:
    prefix = prefix.replace('${SOURCE_DIR}/test/m3-native-sender.fif', '${fixture}/m3-native-paid.fif')
if a.completion_close_account_before_return:
    prefix = prefix.replace('${SOURCE_DIR}/test/m3-native-sender.fif', '${fixture}/m3-native-closed.fif')
if split_return_route:
    master = (repo / 'test/counter-masterchain-genesis.fif').read_text()
    old = 'base_rhash base_fhash now 0 0 0 0 add-std-workchain'
    if master.count(old) != 1:
        raise RuntimeError('Native split fixture descriptor boundary changed')
    master = master.replace(old, 'base_rhash base_fhash now 0 1 1 0 add-std-workchain')
    (fixture / 'm3-split-master.fif').write_text(master)
    prefix = prefix.replace('  if(script STREQUAL "counter-masterchain-genesis" AND NATIVE_SENDER)',
        '  if(script STREQUAL "counter-masterchain-genesis")\n'
        '    set(script_path "${fixture}/m3-split-master.fif")\n  endif()\n'
        '  if(script STREQUAL "counter-masterchain-genesis" AND NATIVE_SENDER)')
prepare.write_text(prefix)
subprocess.run(['cmake', '-DCOUNTER_FIXTURE_CHILD=ON', f'-DCOUNTER_FIXTURE_PATH={fixture}',
                '-DACCOUNT_BINDING_ONLY=ON', '-DNATIVE_SENDER=ON',
                f'-DSOURCE_DIR={repo}', f'-DBUILD_DIR={build}',
                f'-DCREATE_STATE={build / "crypto/create-state"}',
                f'-DCOLLATOR={build / "test-m3-live"}', '-P', str(prepare)], check=True)
print(f'Test-owned fixture: {fixture}', flush=True)
shutil.copyfile(fixture / 'counter-state.boc', fixture / 'current-state.boc')
if a.completion_full_cap:
    (fixture / 'completion-full-cap.txt').write_text('3\n')
if a.completion_window_pair:
    (fixture / 'completion-window-pair.txt').write_text('2\n')
subprocess.run([str(build / 'test-m3-live'), '--prepare-m5-completion-config' if a.m5_completion_late else
                '--prepare-m5-return-config' if a.m5_return_route else
                '--prepare-m5-debit-config' if a.m5_debit else '--prepare-m4-config', str(fixture)], check=True)
# Bind disk lookup and global.json to the actual edited TEST genesis bytes.
# No prior DB is reused and no deployment configuration is read or written.
zero_bytes = (fixture / 'zerostate.boc').read_bytes()
zero_file_hash = hashlib.sha256(zero_bytes).digest()
(fixture / 'zerostate.fhash').write_bytes(zero_file_hash)
(fixture / 'db/static' / zero_file_hash.hex().upper()).write_bytes(zero_bytes)
global_config = json.loads((fixture / 'global.json').read_text())
zero = global_config['validator']['zero_state']
zero['root_hash'] = base64.b64encode((fixture / 'zerostate.rhash').read_bytes()).decode()
zero['file_hash'] = base64.b64encode(zero_file_hash).decode()
(fixture / 'global.json').write_text(json.dumps(global_config))
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1',
                '--query-result', str(fixture / 'bootstrap.result')], check=True)
(fixture / 'wallet-key.request.txt').write_text('secret=101\n')
subprocess.run([str(wallet), 'key', str(fixture / 'wallet-key.request.txt'),
                str(fixture / 'wallet-key.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-request', str(fixture)], check=True)
subprocess.run([str(wallet), 'register', str(fixture / 'registration-0.request.txt'),
                str(fixture / 'registration-0.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-finish', str(fixture)], check=True)
# Real Native source transaction, then authenticated masterchain top descriptor:
# neither the collator nor the validator is given an invented inbox envelope.
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'registration-0.message.boc'),
                '-s', str(fixture / 'payer-top-'), '--query-result', str(fixture / 'payer.result'),
                '--export-candidate', str(fixture / 'payer.candidate')], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payer-top-1.boc'),
                '--query-result', str(fixture / 'payer-master.result')], check=True)
def registration_pair():
    shutil.copyfile(fixture / 'registration-0.candidate.boc', fixture / 'operation.candidate.boc')
    shutil.copyfile(fixture / 'registration-0.declarations.boc', fixture / 'operation.declarations.boc')
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

registration_pair()

# Continue on the accepted database, not a PureBackend account side table.
# Keep each pair's observations distinct so no earlier sidecar can satisfy a
# later step. These are temporary run files, not a separate evidence archive.
def advance_pair(number):
    (fixture / 'db').rename(fixture / f'before-{number}-db')
    (fixture / 'enabled-db').rename(fixture / 'db')
    (fixture / 'closed-db').rename(fixture / f'closed-{number}-db')
    for path in list(fixture.iterdir()):
        if path.is_file() and path.name.startswith(('closed.', 'enabled.', 'enabled-top')):
            path.rename(fixture / f'{number}-{path.name}')
    shutil.copyfile(fixture / 'accepted-state.boc', fixture / 'current-state.boc')

advance_pair(0)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '0-enabled-top1.boc'),
                '--query-result', str(fixture / 'register-a-master.result')], check=True)
(fixture / 'wallet-key.request.txt').write_text('secret=223\n')
subprocess.run([str(wallet), 'key', str(fixture / 'wallet-key.request.txt'),
                str(fixture / 'wallet-key.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-request-b', str(fixture)], check=True)
subprocess.run([str(wallet), 'register', str(fixture / 'registration-0.request.txt'),
                str(fixture / 'registration-0.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-finish', str(fixture)], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'registration-0.message.boc'),
                '-s', str(fixture / 'payer-b-top'), '--query-result', str(fixture / 'payer-b.result')], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payer-b-top1.boc'),
                '--query-result', str(fixture / 'payer-b-master.result')], check=True)
registration_pair()
print('Both registrations accepted on real collator/validator with paired OFF runs.', flush=True)
advance_pair(1)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '1-enabled-top1.boc'),
                '--query-result', str(fixture / 'register-b-master.result')], check=True)
if True:
    subprocess.run([str(build / 'test-m3-live'), '--wallet-policy', str(fixture)], check=True)
    policy = dict(line.split('=', 1) for line in (fixture / 'wallet-policy.txt').read_text().splitlines())
    # M3 now starts from real backing. Pay the added initial COLLECT explicitly;
    # do not weaken the frozen minimum or install available directly.
    principal = 1000000000 if a.m4 else 1000000000 + int(policy['collect_fee'])
    if principal > 2**64 - 1:
        raise RuntimeError('initial Deposit principal overflow')
    for number in ((2, 3) if a.m4 else (2,)):
        (fixture / 'deposit.request.txt').write_text(f'principal={principal}\n')
        subprocess.run([str(build / 'test-m3-live'), '--deposit-request', str(fixture)], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'deposit.message.boc'),
                        '-s', str(fixture / f'deposit-{number}-payer-top'),
                        '--query-result', str(fixture / f'deposit-{number}-payer.result')], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1',
                        '-M', str(fixture / f'deposit-{number}-payer-top1.boc'),
                        '--query-result', str(fixture / f'deposit-{number}-master.result')], check=True)
        subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
        shutil.copyfile(fixture / 'accepted-receipt.id', fixture / f'deposit-{number}.id')
        advance_pair(number)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / f'{number}-enabled-top1.boc'),
                        '--query-result', str(fixture / f'deposit-{number}-accepted-master.result')], check=True)
    if a.m4 and a.m4_rejections:
        from uno_m4_rejection_sequence import run
        run(build, fixture, advance_pair)
        raise SystemExit(0)
    if a.m4:
        from uno_m4_live_sequence import run
        run(build, fixture, wallet, advance_pair)
        raise SystemExit(0)

from uno_m4_live_sequence import run
initial, initial_blind, send_fee, collect_fee, limits = run(
    build, fixture, wallet, advance_pair, initial_only=True, initial_principal=principal)
if a.completion_no_slot:
    # The explicit test policy sets four system slots. Fill them by actual
    # successful Deposit issuance, never by modifying an authenticated root.
    for index in range(4):
        label = f'full-slot-{index}'
        (fixture / 'deposit.request.txt').write_text('principal=1000000000\n')
        subprocess.run([str(build / 'test-m3-live'), '--deposit-request', str(fixture)], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'deposit.message.boc'),
                        '-s', str(fixture / (label + '-payer-top')),
                        '--query-result', str(fixture / (label + '-payer.result'))], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / (label + '-payer-top1.boc')),
                        '--query-result', str(fixture / (label + '-master.result'))], check=True)
        subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
        shutil.copyfile(fixture / 'accepted-receipt.id', fixture / (label + '.receipt.id'))
        advance_pair(label)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / (label + '-enabled-top1.boc')),
                        '--query-result', str(fixture / (label + '-accepted.result'))], check=True)
    if a.completion_free_one_slot:
        shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-full-before-collect.boc')
        selected = (fixture / 'full-slot-3.receipt.id').read_text()
        initial, initial_blind, send_fee, collect_fee, limits = run(
            build, fixture, wallet, advance_pair, initial_only=True,
            initial_collection=(initial, initial_blind, 71, selected, 1000000000, 'free-one-slot'))
        shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-full-after-collect.boc')
if a.m5_debit:
    def route_block(label, shard, tops=()):
        args = [str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', shard,
                '--query-result', str(fixture / (label + '.result'))]
        if shard != '-1':
            args += ['-s', str(fixture / (label + '-top')),
                     '--export-candidate', str(fixture / (label + '.candidate'))]
        for top in tops:
            args += ['-M', str(fixture / (top + '-top1.boc'))]
        result = subprocess.run(args, capture_output=True)
        # Native diagnostics can contain binary bytes. Preserve the observation
        # before rendering it; text decoding must not hide the child's outcome.
        output = result.stdout + result.stderr
        (fixture / (label + '.log')).write_bytes(output)
        result.check_returncode()
        return output.decode('utf-8', errors='backslashreplace')
    if split_return_route:
        # Split before issuing the payout. Every intermediate block is real;
        # no inbox is dropped and no queue-removal height is fabricated.
        for attempt in range(75):
            label = f'completion-split-{attempt}'
            output = route_block(label, '0')
            route_block(label + '-master', '-1', (label,))
            if 'BEFORE_SPLIT set for the new block' in output:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Native authenticated split did not become ready')
        route_block('completion-left', '0:4')
        route_block('completion-right', '0:c')
        route_block('completion-split-master', '-1', ('completion-left', 'completion-right'))
    request = dict(secret=101, old_value=initial, old_blind=initial_blind, new_blind=71, aux_blind=83,
                   principal=a.m5_return_principal if a.m5_return_principal is not None else
                             1000000 if a.m5_bucket_small else 10000000 if a.m5_return_route else 137, outward_fee=17,
                   fee=257, **limits)
    def debit_write(name, values):
        (fixture / name).write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
    def withdrawal_request(values):
        debit_write('operation.request.txt',values)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-payout-quote',str(fixture)],check=True)
        values['outward_fee'] = int((fixture / 'payout.quote.txt').read_text())
        debit = values['principal'] + values['outward_fee'] + values['fee']
        if not 0 <= debit < 2**64 or values['old_value'] < debit:
            raise RuntimeError('fixture Withdrawal debit overflow or insufficient available')
        debit_write('operation.request.txt',values)
        subprocess.run([str(wallet),'withdrawal-points',str(fixture / 'operation.request.txt'),str(fixture / 'operation.points.txt')],check=True)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-request',str(fixture)],check=True)
        statement = dict(line.split('=',1) for line in (fixture / 'operation.statement.txt').read_text().splitlines())
        debit_write('operation.request.txt',dict(values,**statement))
        subprocess.run([str(wallet),'withdrawal-prove',str(fixture / 'operation.request.txt'),str(fixture / 'operation.proof.txt')],check=True)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-finish',str(fixture)],check=True)
        remaining = values['old_value'] - debit
        debit_write('operation.expected.txt',dict(before=values['old_value'],after=remaining))
        return remaining
    def phase_capture_before(name):
        shutil.copyfile(fixture / 'current-state.boc', fixture / ('phase-' + name + '-before.boc'))
        if a.phase_replay_cuts:
            cut = fixture / ('phase-' + name + '-replay')
            cut.mkdir()
            for source in fixture.iterdir():
                if source.is_file():
                    shutil.copy2(source, cut / source.name)
            # Native child processes have exited. This is a private, stopped DB
            # snapshot, owned by the enclosing fixture's normal cleanup policy.
            shutil.copytree(fixture / 'db', cut / 'db')
            shutil.copytree(fixture / 'm4-blocks', cut / 'm4-blocks')
    def phase_capture_after(name):
        for source, suffix in (('accepted-state.boc', '-after.boc'),
                               ('enabled.candidate', '.candidate'),
                               ('enabled.result.validation.result', '.validation')):
            shutil.copyfile(fixture / source, fixture / ('phase-' + name + suffix))
    available = withdrawal_request(request)
    print(f'DEBIT_FIXTURE={fixture}',flush=True)
    if a.m5_completion_late:
        phase_capture_before('prepare')
    subprocess.run([str(build / 'test-m3-live'),str(fixture)],check=True)
    if a.m5_completion_late:
        phase_capture_after('prepare')
        shutil.copyfile(fixture / 'prepare-payout.boc', fixture / 'phase-original-payout.boc')
    if a.m5_return_route:
        advance_pair(4)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '4-enabled-top1.boc'),
                        '--query-result', str(fixture / 'payout-master.result')], check=True)
        if split_return_route:
            # First import into the non-destination shard only. Its authenticated
            # transit export permits source dequeue before the actual delivery.
            if not a.phase_delay_transit:
                route_block('completion-transit', '0:c')
                route_block('completion-transit-master', '-1', ('completion-transit',))
        else:
            subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '0', '-s', str(fixture / 'payout-recipient-top'),
                        '--query-result', str(fixture / 'payout-recipient.result'),
                        '--export-candidate', str(fixture / 'payout-recipient.candidate')], check=True)
        if not a.m5_completion_paid and not split_return_route:
            subprocess.run([str(build / 'test-m3-live'), '--observe-m5-payout-recipient', str(fixture)], check=True)
        if not a.m5_completion_paid and not split_return_route and not (fixture / 'failed-bounce.boc').is_file():
            raise RuntimeError('funded return route did not produce a real bounce')
        if a.m5_failed:
            if not split_return_route:
                subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                            '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payout-recipient-top1.boc'),
                            '--query-result', str(fixture / 'return-master.result')], check=True)
            if a.m5_completion_late:
                shutil.copyfile(fixture / 'prepare-payout.boc',fixture / 'completion-original-payout.boc')
                old_blind = request['new_blind']
                owner_steps = [(5,79),(6,83)]
                if a.completion_close_account_before_return:
                    # Two real SENDs advance authenticated Q without opening new
                    # W records. The second drains available; closure is then an
                    # actual authorized operation, never an edited state root.
                    for number, new_blind in owner_steps:
                        amount = 1000 if number == 5 else available - send_fee
                        if not 0 < amount <= int(limits['max_value']) or amount + send_fee > available:
                            raise RuntimeError('closed-account fixture cannot fund its real SEND')
                        debit_write('operation.wallet.txt', dict(owner=0))
                        witness = dict(secret=101, receiver_secret=223, old_value=available,
                                       old_blind=old_blind, value=amount, new_blind=new_blind,
                                       transfer_blind=79, aux_blind=43)
                        debit_write('operation.request.txt', dict(witness, kind=1, fee=send_fee, **limits))
                        subprocess.run([str(wallet), 'points', str(fixture / 'operation.request.txt'),
                                        str(fixture / 'operation.points.txt')], check=True)
                        subprocess.run([str(build / 'test-m3-live'), '--send-request', str(fixture)], check=True)
                        statement = dict(line.split('=',1) for line in
                                         (fixture / 'operation.statement.txt').read_text().splitlines())
                        if set(statement) & set(witness):
                            raise RuntimeError('SEND witness overwrites authenticated statement')
                        debit_write('operation.request.txt', dict(witness, **statement))
                        subprocess.run([str(wallet), 'prove', str(fixture / 'operation.request.txt'),
                                        str(fixture / 'operation.proof.txt')], check=True)
                        subprocess.run([str(build / 'test-m3-live'), '--send-finish', str(fixture)], check=True)
                        after = available - amount - send_fee  # bounds checked above
                        debit_write('operation.expected.txt', dict(before=available, after=after))
                        subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
                        advance_pair(number)
                        route_block(f'completion-send-{number}-master', '-1', (f'{number}-enabled',))
                        available, old_blind = after, new_blind
                    shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-record-state.boc')
                    shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-account-close-before-state.boc')
                    debit_write('closure.owner.txt', dict(owner=0))
                    debit_write('closure.expected.txt', dict(other=0))
                    subprocess.run([str(build / 'test-m3-live'), '--closure-request', str(fixture)], check=True)
                    subprocess.run([str(wallet), 'close', str(fixture / 'closure.request.txt'),
                                    str(fixture / 'closure.proof.txt')], check=True)
                    subprocess.run([str(build / 'test-m3-live'), '--closure-finish', str(fixture)], check=True)
                    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
                    for src, dst in [('accepted-state.boc', 'completion-account-close-after-state.boc'),
                                     ('enabled.candidate', 'completion-account-close-candidate'),
                                     ('enabled.result.validation.result', 'completion-account-close-validation.result')]:
                        shutil.copyfile(fixture / src, fixture / dst)
                    advance_pair(7)
                    route_block('completion-account-close-master', '-1', ('7-enabled',))
                    print(f'COMPLETION_CLOSED_ACCOUNT:{fixture}', flush=True)
                    owner_steps = []
                if a.completion_close_before_return or a.completion_window_pair:
                    owner_steps.append((7,97))
                for number, new_blind in owner_steps:
                    if a.completion_window_pair and number == 7:
                        # Both branches inherit the same accepted block 7 and original W.
                        # All Native subprocesses have exited; copy the closed DB, not a live one.
                        within = live_fixture('uno-completion-window-within-')
                        shutil.copytree(fixture, within, dirs_exist_ok=True)
                        sys.stdout.flush(); sys.stderr.flush()
                        child = os.fork()
                        if child == 0:
                            live_capacity('START')  # This fork executes a separate accepted branch.
                            fixture = within
                            window_branch = 'WITHIN'
                            break  # Deliver now: Q=6, window=2, arrival=8.
                        _, status = os.waitpid(child, 0)
                        if os.waitstatus_to_exitcode(status) != 0:
                            raise RuntimeError('deadline branch failed before late branch')
                        window_branch = 'LATE'
                        # One actual owner operation advances to 8 without closing W;
                        # only then deliver the same payout, so return arrival is 9.
                    followup = dict(secret=101, old_value=available, old_blind=old_blind,
                                    new_blind=new_blind, aux_blind=89, principal=137,
                                    outward_fee=17, fee=257, **limits)
                    available = withdrawal_request(followup)
                    if a.completion_close_before_return and number == 7:
                        # Retain the real owner-triggered closure before the later
                        # bounce overwrites the final-operation artifacts.
                        shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-before-state.boc')
                        shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-untouched-state.boc')
                        shutil.copyfile(fixture / 'accepted-block.id', fixture / 'completion-before-block.id')
                    if number in (5, 6):
                        phase_capture_before(f'owner{number}')
                    completed = subprocess.run([str(build / 'test-m3-live'),str(fixture)],
                                               text=True,capture_output=True)
                    (fixture / f'completion-owner-{number}.log').write_text(completed.stdout+completed.stderr)
                    print(completed.stdout,end=''); print(completed.stderr,end='',file=sys.stderr)
                    completed.check_returncode()
                    if number in (5, 6):
                        phase_capture_after(f'owner{number}')
                    if a.completion_close_before_return and number == 7:
                        (fixture / 'completion-execution.log').write_text(completed.stdout + completed.stderr)
                        paid_fixture = live_fixture('uno-row5-paid-predecessor-')
                        shutil.copytree(fixture, paid_fixture, dirs_exist_ok=True)
                        print(f'COMPLETION_ROW5_PAID:{paid_fixture}', flush=True)
                    advance_pair(number)
                    subprocess.run([str(build / 'test-tos-collator'), '-C',str(fixture / 'global.json'),
                                    '-D',str(fixture / 'db'), '-w','-1', '-M',
                                    str(fixture / f'{number}-enabled-top1.boc'), '--query-result',
                                    str(fixture / f'completion-owner-{number}-master.result')],check=True)
                    if a.phase_delay_transit and number == 5:
                        route_block('completion-transit', '0:c')
                        route_block('completion-transit-master', '-1', ('completion-transit',))
                    old_blind = new_blind
                    if a.completion_close_before_return and number == 6:
                        shutil.copyfile(fixture / 'current-state.boc',fixture / 'completion-record-state.boc')
                if not a.completion_close_before_return and not a.completion_close_account_before_return:
                    shutil.copyfile(fixture / 'current-state.boc',fixture / 'completion-record-state.boc')
                shutil.copyfile(fixture / 'completion-original-payout.boc',fixture / 'prepare-payout.boc')
            if split_return_route:
                route_block('payout-recipient', '0:4')
                subprocess.run([str(build / 'test-m3-live'), '--observe-m5-payout-recipient', str(fixture)], check=True)
                route_block('return-master', '-1', ('payout-recipient',))
            if a.m5_completion_paid:
                # A real third-party Deposit to B advances the authenticated
                # height without executing an owner operation on A.
                debit_write('deposit.owner.txt',dict(owner=1))
                debit_write('deposit.request.txt',dict(principal=1000000000))
                subprocess.run([str(build / 'test-m3-live'),'--deposit-request',str(fixture)],check=True)
                subprocess.run([str(build / 'test-tos-collator'),'-C',str(fixture/'global.json'),
                    '-D',str(fixture/'db'),'-w','0','-m',str(fixture/'deposit.message.boc'),
                    '-s',str(fixture/'completion-filler-payer-top'),'--query-result',
                    str(fixture/'completion-filler-payer.result')],check=True)
                subprocess.run([str(build / 'test-tos-collator'),'-C',str(fixture/'global.json'),
                    '-D',str(fixture/'db'),'-w','-1','-M',str(fixture/'completion-filler-payer-top1.boc'),
                    '--query-result',str(fixture/'completion-filler-master.result')],check=True)
                subprocess.run([str(build/'test-m3-live'),str(fixture)],check=True)
                advance_pair(7)
                shutil.copyfile(fixture/'current-state.boc',fixture/'completion-untouched-state.boc')
                subprocess.run([str(build/'test-tos-collator'),'-C',str(fixture/'global.json'),
                    '-D',str(fixture/'db'),'-w','-1','-M',str(fixture/'7-enabled-top1.boc'),
                    '--query-result',str(fixture/'completion-filler-accepted.result')],check=True)
                followup=dict(secret=101,old_value=available,old_blind=old_blind,new_blind=97,
                              aux_blind=101,principal=137,outward_fee=17,fee=257,**limits)
                withdrawal_request(followup)
                shutil.copyfile(fixture/'current-state.boc',fixture/'completion-before-state.boc')
                shutil.copyfile(fixture/'accepted-block.id',fixture/'completion-before-block.id')
                completed=subprocess.run([str(build/'test-m3-live'),str(fixture)],capture_output=True,text=True)
                (fixture/'completion-execution.log').write_text(completed.stdout+completed.stderr)
                print(completed.stdout,end='');print(completed.stderr,end='',file=sys.stderr)
                # The trigger overwrites prepare-payout; retain the original
                # payout as the identity of the old obligation under review.
                shutil.copyfile(fixture/'completion-original-payout.boc',fixture/'prepare-payout.boc')
                completed.check_returncode()
                observation = fixture / 'completion-observation.json'
                subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                                'row4', str(fixture), str(observation)], check=True)
                subprocess.run([sys.executable,
                                str(repo / 'crypto/test/workchain_withdrawal_completion_oracle.py'),
                                '--case', 'row4', '--observation', str(observation)], check=True)
                print(f'COMPLETION_PAID_FIXTURE:{fixture}',flush=True)
                raise SystemExit(0)
            subprocess.run([str(build / 'test-m3-live'), '--failed-request', str(fixture)], check=True)
            if a.failed_routing_probe:
                probe = fixture / 'routing-probe'
                # The backing observer intentionally refuses to overwrite its
                # observations. Mutant and restored runs need separate outputs.
                shutil.copytree(fixture, probe, ignore=shutil.ignore_patterns('routing-probe'))
                result = subprocess.run([str(a.failed_routing_binary or build / 'test-m3-live'), '--failed-fee-routing-control', str(probe)],
                                        text=True, capture_output=True)
                (fixture / 'routing-probe.log').write_text(result.stdout + result.stderr)
                print(f'FAILED_ROUTING_PROBE fixture={fixture} exit={result.returncode}', flush=True)
                for suffix, expected in [('.validation.kind', 'accept\n'),
                                         ('.validation.result', 'validate accept\n')]:
                    if (probe / ('routing-enabled.result' + suffix)).read_text() != expected:
                        raise RuntimeError('routing mutation did not reach accepted Native publication')
                if not (probe / 'routing-enabled.candidate').is_file():
                    raise RuntimeError('routing mutation has no exported candidate')
                if result.returncode == 0 or 'FAILED_COST_ROUTING:' not in result.stderr:
                    raise RuntimeError('FAILED_ORACLE_MISSING:FAILED_COST_ROUTING; '
                                       'expected designated routing red, not an earlier failure')
            subprocess.run([str(build / 'test-m3-live'), '--failed-incarnation-control', str(fixture)], check=True)
            subprocess.run([str(build / 'test-m3-live'), '--failed-unknown-control', str(fixture)], check=True)
            shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-before-state.boc')
            shutil.copyfile(fixture / 'accepted-block.id', fixture / 'completion-before-block.id')
            completed = subprocess.run([str(build / 'test-m3-live'), str(fixture)], text=True, capture_output=True)
            (fixture / 'completion-execution.log').write_text(completed.stdout + completed.stderr)
            print(completed.stdout, end=''); print(completed.stderr, end='', file=__import__('sys').stderr)
            if a.m5_bucket_small:
                observation = fixture / 'completion-observation.json'
                case = 'row6' if a.completion_expect_offset == 1 else 'bucket-small'
                subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                                case, str(fixture), str(observation)], check=True)
                if a.completion_expect_offset is not None:
                    values = json.loads(observation.read_text())['input']
                    h = values['slot'] + values['base'] * values['units']
                    if not 0 <= h < 2**64 or values['y'] != h + a.completion_expect_offset:
                        raise RuntimeError('COMPLETION_BOUNDARY_INPUT_MISMATCH: actual y is not h+offset')
                subprocess.run(['python3', str(repo / 'crypto/test/workchain_withdrawal_completion_oracle.py'),
                                '--case', case, '--observation', str(observation)], check=True)
            completed.check_returncode()
            if a.completion_sweep:
                advance_pair('sweep-bucket-arrival')
                # Commit the return head before COLLECT's existing one-block
                # master import assertion; otherwise it sees accumulated fees
                # from several shard blocks, not just the COLLECT being checked.
                subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                                '-D', str(fixture / 'db'), '-w', '-1',
                                '-M', str(fixture / 'sweep-bucket-arrival-enabled-top1.boc'),
                                '--query-result', str(fixture / 'sweep-arrival-master.result')], check=True)
                # The slot is freed by a genuine proof-authorized COLLECT of
                # an existing Deposit, not by editing a state root or a cap.
                selected = (fixture / 'full-slot-3.receipt.id').read_text()
                run(build, fixture, wallet, advance_pair, initial_only=True,
                    initial_collection=(available, 71, 73, selected, 1000000000, 'sweep-free-slot'))
                shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-before-state.boc')
                shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-sweep-before-state.boc')
                shutil.copyfile(fixture / 'accepted-block.id', fixture / 'completion-before-block.id')
                subprocess.run([str(build / 'test-m3-live'), '--sweep-request', str(fixture)], check=True)
                print(f'COMPLETION_SWEEP_FIXTURE:{fixture}', flush=True)
                subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
            if a.completion_window_pair:
                print(f'COMPLETION_WINDOW_{window_branch}:{fixture}', flush=True)
            if a.completion_close_before_return:
                print(f'COMPLETION_ROW5_LATE:{fixture}', flush=True)
    raise SystemExit(0)
# Keep the final B->A receipt at 432: compensate only the changed SEND/COLLECT
# tariffs in the first receipt. The remaining two receipts retain 251 and 89.
first_value = 137 + (send_fee - 11) + 2 * (collect_fee - 17)
if not 1 <= first_value <= int(limits['max_value']):
    raise RuntimeError('real-Deposit M3 sequence cannot fund the closing sender')

# Wallet witnesses remain proposer-side only. Each validator obtains the full
# public statement and authorization from the emitted permanent block.
def send_pair(owner, old_value, old_blind, value, new_blind, transfer_blind):
    secret, receiver = (101, 223) if owner == 0 else (223, 101)
    witness = dict(secret=secret, receiver_secret=receiver, old_value=old_value,
                   old_blind=old_blind, value=value, new_blind=new_blind,
                   transfer_blind=transfer_blind, aux_blind=43)
    def write_fields(path, fields):
        path.write_text(''.join(f'{k}={v}\n' for k, v in fields.items()))
    write_fields(fixture / 'operation.wallet.txt', dict(owner=owner))
    write_fields(fixture / 'operation.request.txt',
                 dict(witness, kind=1, fee=send_fee, **limits))
    subprocess.run([str(wallet), 'points', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.points.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--send-request', str(fixture)], check=True)
    statement = dict(line.split('=', 1) for line in
                     (fixture / 'operation.statement.txt').read_text().splitlines())
    if set(statement) & set(witness):
        raise RuntimeError('wallet witness overwrites authenticated statement fields')
    write_fields(fixture / 'operation.request.txt', dict(witness, **statement))
    subprocess.run([str(wallet), 'prove', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.proof.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--send-finish', str(fixture)], check=True)
    if value + send_fee > old_value:
        raise RuntimeError('test SEND expectation underflow')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=old_value-value-send_fee))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

send_pair(0, initial, initial_blind, first_value, 31, 37)
first_receipt = (fixture / 'accepted-receipt.id').read_text()

def advance_operation(number):
    advance_pair(number)
    subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                    '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / f'{number}-enabled-top1.boc'),
                    '--query-result', str(fixture / f'operation-{number}-master.result')], check=True)

advance_operation(4)
a_first = initial - first_value - send_fee  # coverage checked by send_pair
send_pair(0, a_first, 31, 251, 47, 43)
second_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(5)

def collect_pair(old_value, old_blind, new_blind, receipts):
    # Wallet selection is sorted here. Host does not duplicate the kernel's
    # strict sorted/unique ID check. Witnesses travel in exactly the same order.
    selected = sorted(receipts)
    fields = dict(secret=223, old_value=old_value, old_blind=old_blind,
                  new_blind=new_blind, aux_blind=83,
                  values=','.join(str(value) for _, value, _ in selected),
                  blinds=','.join(str(blind) for _, _, blind in selected),
                  auxiliaries=','.join(str(89+i) for i in range(len(selected))))
    def write_fields(path, values):
        path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    write_fields(fixture / 'operation.wallet.txt',
                 dict(owner=1, selected=''.join(receipt for receipt, _, _ in selected)))
    write_fields(fixture / 'operation.request.txt',
                 dict(fields, kind=2, fee=collect_fee, **limits))
    subprocess.run([str(wallet), 'points', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.points.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--collect-request', str(fixture)], check=True)
    statement = dict(line.split('=', 1) for line in
                     (fixture / 'operation.statement.txt').read_text().splitlines())
    if set(statement) & set(fields):
        raise RuntimeError('COLLECT witness overwrites authenticated statement')
    write_fields(fixture / 'operation.request.txt', dict(fields, **statement))
    subprocess.run([str(wallet), 'prove', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.proof.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--collect-finish', str(fixture)], check=True)
    total = old_value + sum(value for _, value, _ in selected)
    if total < collect_fee or total > 2**64-1:
        raise RuntimeError('COLLECT expected balance out of range')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=total-collect_fee))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

collect_pair(0, 0, 67, [(first_receipt, first_value, 37)])
advance_operation(6)
a_second = a_first - 251 - send_fee  # coverage checked by send_pair
send_pair(0, a_second, 47, 89, 59, 61)
third_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(7)
collect_pair(first_value - collect_fee, 67, 71, [(second_receipt, 251, 43), (third_receipt, 89, 61)])
advance_operation(8)
send_pair(1, first_value + 340 - 2 * collect_fee, 71, 432, 73, 79)
advance_operation(9)
a_final = a_second - 89 - send_fee  # coverage checked by send_pair
(fixture / 'closure.expected.txt').write_text(f'other={a_final}\n')
(fixture / 'closure.owner.txt').write_text('owner=1\n')
subprocess.run([str(build / 'test-m3-live'), '--closure-request', str(fixture)], check=True)
subprocess.run([str(wallet), 'close', str(fixture / 'closure.request.txt'),
                str(fixture / 'closure.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--closure-finish', str(fixture)], check=True)
subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
print('M3 sequence completed under test-constructed configuration, with paired OFF runs. '
      f'Real Native Deposit principal={principal}; A={a_final}, B=0; '
      'refund is a one-way message, delivery not guaranteed.')
