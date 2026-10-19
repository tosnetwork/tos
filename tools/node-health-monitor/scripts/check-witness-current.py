#!/usr/bin/env python3
"""Validate an actual M current-route body and boundary countercontrols."""
import copy
import json
import re
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / 'contracts/witness-current.schema.json').read_text())
actual = json.loads(Path(sys.argv[1]).read_text())
formats = FormatChecker()

@formats.checks('uint64')
def uint64(value):
    return isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value) is not None and int(value) <= 2**64 - 1

validator = Draft202012Validator(schema, format_checker=formats)

def valid(value):
    if not validator.is_valid(value):
        return False
    if value['status'] == 'qualified':
        rows = value['rows']
        return bool(rows) and all(
            row['qualification']['relative_age'] == 'fresh'
            and row['qualification']['remote_clock'] == 'compatible'
            and row['qualification']['role_at_observer_receipt'] in ('normal', 'probe_only', 'non_voting')
            for row in rows
        )
    return True

assert actual['status'] in ('qualified', 'unknown')
assert valid(actual), 'actual current handler output fails closed contract'
bad = copy.deepcopy(actual)
bad['rows'][0]['qualification']['verified_finality'] = True
assert not valid(bad), 'reported proof must not become locally verified'
bad = copy.deepcopy(actual)
bad['rows'][0]['qualification']['extra'] = True
assert not valid(bad), 'unknown qualification field admitted'
bad = copy.deepcopy(actual)
bad['status'] = 'qualified'
bad['rows'][0]['qualification']['remote_clock'] = 'unknown'
assert not valid(bad), 'unknown remote clock called qualified'
assert not validator.is_valid(bad), 'closed schema itself must reject qualified/unknown clock'
bad = copy.deepcopy(actual)
bad['status'] = 'qualified'
bad['rows'] = []
assert not validator.is_valid(bad), 'closed schema itself must reject vacuous qualified rows'
bad = copy.deepcopy(actual)
bad['status'] = 'qualified'
bad['rows'][0]['qualification']['role_at_observer_receipt'] = 'outside_window'
assert not validator.is_valid(bad), 'closed schema itself must reject outside role window'
bad = copy.deepcopy(actual)
bad['collector_to_m_ms'] = 0
assert not valid(bad), 'integer must not substitute for exact decimal string'
bad = copy.deepcopy(actual)
bad['collector_to_m_ms'] = '١'
assert not valid(bad), 'Unicode decimal must not substitute for ASCII canonical u64'
unavailable = {'schema_version': 1, 'status': 'unavailable', 'production_usable': False,
               'reason': 'current_unavailable'}
assert valid(unavailable)
unknown = copy.deepcopy(actual)
unknown['status'] = 'unknown'
unknown['m_elapsed_ms'] = None
unknown['collector_to_m_ms'] = None
unknown['rows'][0]['source_age_at_first_receipt_ms'] = None
unknown['rows'][0]['effective_age_at_read_ms'] = None
unknown['rows'][0]['qualification']['relative_age'] = 'unknown'
assert valid(unknown), 'nullable unknown timing must remain representable'
print('actual current body valid; four malformed/semantic negatives refused; unavailable and null timing valid')
