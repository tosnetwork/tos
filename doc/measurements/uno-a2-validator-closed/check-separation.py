"""Check cross-input and missing-observation controls without editing raw runs."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys

spec = importlib.util.spec_from_file_location('classifier', Path(__file__).with_name('classifier.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
root = Path(sys.argv[1])
output = Path(sys.argv[2])
output.mkdir()
if (root / 'execute-positive.calls').read_text() != 'config=0\nexecute=1\n':
    raise AssertionError('engine-body counter positive control failed')
if (root / 'final-accept/result.validation.kind').read_text() != 'accept\n':
    raise AssertionError('native acceptance positive control failed')
if not (root / 'final-accept/unexpected-export').is_file():
    raise AssertionError('native export positive control failed')
if module.classify(root / 'final-earlier') != 'earlier_configuration_failure':
    raise AssertionError('earlier control changed class')
if module.classify(root / 'final-gate') != 'account_readiness':
    raise AssertionError('gate control changed class')
reject = root / 'final-reject'
if (reject / 'result.validation.kind').read_text() != 'reject\n':
    raise AssertionError('native rejection was not recorded as CandidateReject')
if not (reject / 'result.validation.message').read_text().startswith('block candidate has invalid file hash:'):
    raise AssertionError('native rejection changed reason')
try:
    module.classify(reject)
except ValueError:
    pass
else:
    raise AssertionError('native CandidateReject classified as registry abstention')
records = []
cases = ['earlier_message_gate_counts', 'gate_message_earlier_counts',
         'missing_delivery', 'missing_trace', 'reject_instead_of_local',
         'observer_error', 'boolean_count', 'negative_count', 'wrong_status',
         'pending_delivery', 'engine_executed', 'export_present',
         'missing_registry_event', 'wrong_host', 'pending_breakpoint', 'incomplete_exit']
cases += ['missing_' + site for site in sorted(module.SITES)]
cases += ['nonzero_' + site for site in sorted(module.SITES)
          if site.startswith('downstream_') or site == 'transaction_check']
for name in cases:
    target = output / name
    target.mkdir()
    for item in (root / 'final-gate').iterdir():
        if item.is_file() and (item.name.startswith('result.validation.') or item.name in ('trace.json', 'calls.txt')):
            shutil.copyfile(item, target / item.name)
    if name == 'earlier_message_gate_counts':
        (target / 'result.validation.message').write_text(module.EARLIER)
    elif name == 'gate_message_earlier_counts':
        shutil.copyfile(root / 'final-earlier/trace.json', target / 'trace.json')
    elif name == 'missing_delivery':
        (target / 'result.validation.delivery').unlink()
    elif name == 'missing_trace':
        (target / 'trace.json').unlink()
    elif name == 'reject_instead_of_local':
        (target / 'result.validation.kind').write_text('reject\n')
    elif name == 'wrong_status':
        (target / 'result.validation.result').write_text('validate -7202\n')
    elif name == 'pending_delivery':
        (target / 'result.validation.delivery').write_text('pending\n')
    elif name == 'engine_executed':
        (target / 'calls.txt').write_text('config=1\nexecute=1\n')
    elif name == 'export_present':
        (target / 'unexpected-export').write_bytes(b'present')
    else:
        trace = json.loads((target / 'trace.json').read_text())
        if name == 'observer_error':
            trace['errors'].append('test observation failure')
        elif name == 'incomplete_exit':
            trace['exit_code'] = None
        elif name == 'boolean_count':
            trace['counts']['registry'] = True
        elif name == 'negative_count':
            trace['counts']['registry'] = -1
        elif name == 'missing_registry_event':
            trace['events'] = [event for event in trace['events'] if event['site'] != 'registry']
        elif name == 'wrong_host':
            for event in trace['events']:
                event['stack'] = []
        elif name == 'pending_breakpoint':
            trace['bound_before_run']['registry']['pending'] = True
        elif name.startswith('nonzero_'):
            trace['counts'][name.removeprefix('nonzero_')] = 1
        else:
            del trace['counts'][name.removeprefix('missing_')]
        (target / 'trace.json').write_text(json.dumps(trace, indent=2))
    try:
        answer = module.classify(target)
    except (ValueError, FileNotFoundError) as error:
        records.append({'control': name, 'error': str(error)})
    else:
        raise AssertionError((name, answer))
(output / 'report.json').write_text(json.dumps(records, indent=2))
print(len(records), 'observation controls rejected; two real classifications retained')
