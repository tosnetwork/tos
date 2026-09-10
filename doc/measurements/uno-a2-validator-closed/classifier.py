"""Strict disk-validator typed observation classifier; unknowns are errors."""
import json
from pathlib import Path

EARLIER = ('cannot execute configured workchain: configuration callback incorrectly '
           'classified a local failure as candidate invalid: injected account configuration fault')
GATE = 'cannot execute configured workchain: multi-account admission and replay are not connected'
SITES = {'registry', 'account_variant', 'account_refusal', 'transaction_check',
         'downstream_collator', 'downstream_validator_config',
         'downstream_validator_ready', 'downstream_validator_transactions'}

def classify(run):
    run = Path(run)
    trace = json.loads((run / 'trace.json').read_text())
    if type(trace.get('exit_code')) is not int:
        raise ValueError('observer did not record process completion')
    counts = trace['counts']
    if trace['errors'] or set(counts) != SITES:
        raise ValueError('missing or failed observation')
    bound = trace['bound_before_run']
    if set(bound) != SITES or any(item['pending'] is not False or item['enabled'] is not True
                                 or item['valid'] is not True or not item['location']
                                 for item in bound.values()):
        raise ValueError('observer was not bound before execution')
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise ValueError('invalid observation count')
    fields = {name: (run / ('result.validation.' + name)).read_text()
              for name in ('kind', 'result', 'message', 'delivery')}
    if fields['kind'] != 'error\n' or fields['result'] != 'validate -7201\n':
        raise ValueError('not the measured typed local error: ' + repr(fields))
    if fields['delivery'] != 'recorded\n':
        raise ValueError('unconfirmed typed delivery')
    if any(counts[name] for name in SITES if name.startswith('downstream_') or name == 'transaction_check'):
        raise ValueError('downstream or transaction check reached')
    if (run / 'calls.txt').read_text() != 'config=1\nexecute=0\n':
        raise ValueError('unexpected engine calls')
    if (run / 'unexpected-export').exists():
        raise ValueError('candidate exported')
    registry_events = [event for event in trace['events'] if event['site'] == 'registry']
    if len(registry_events) != 1 or not any(
            'ValidateQuery::fetch_config_params' in (frame['name'] or '')
            for frame in registry_events[0]['stack']):
        raise ValueError('not the measured validator fetch callsite')
    shape = tuple(counts[name] for name in ('registry', 'account_variant', 'account_refusal'))
    matches = []
    if fields['message'] == EARLIER and shape == (1, 0, 0):
        matches.append('earlier_configuration_failure')
    if fields['message'] == GATE and shape == (1, 1, 1):
        matches.append('account_readiness')
    if len(matches) != 1:
        raise ValueError('unclassifiable: ' + repr((fields, counts, matches)))
    return matches[0]

if __name__ == '__main__':
    import sys
    actual = classify(sys.argv[1])
    if actual != sys.argv[2]:
        raise AssertionError((actual, sys.argv[2]))
    print(actual)
