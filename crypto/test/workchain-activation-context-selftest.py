#!/usr/bin/env python3
"""Record-validator unit vectors only; never claim these are live host results."""
import copy
import importlib.util
import json
from pathlib import Path
import sys


def run(source):
    spec = importlib.util.spec_from_file_location('pair_context', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    closed = dict(result_kind='local-error', status_code=-7201, status_message='not classified by this unit',
                  transactions=0, candidate_exports=[], run_id='unit-records',
                  host_path='unit-record-schema', input_sha256='1' * 64,
                  common_config_sha256='2' * 64, config_origin='test-internal',
                  capability_enabled=False, config_sha256='3' * 64)
    enabled = dict(closed, capability_enabled=True, config_sha256='4' * 64,
                   reached_required_frontier=True)
    failures = []
    module.check_pair_context(enabled, closed)
    vectors = [(303, 'closed', 'status_code', 0),
               (304, 'closed', 'status_code', -7202),
               (305, 'closed', 'transactions', 1),
               (306, 'closed', 'candidate_exports', ['candidate.boc']),
               (307, 'enabled', 'run_id', 'other-run'),
               (308, 'enabled', 'host_path', 'other-path'),
               (309, 'enabled', 'input_sha256', '5' * 64),
               (310, 'enabled', 'common_config_sha256', '6' * 64),
               (311, 'enabled', 'config_origin', 'deployment'),
               (312, 'closed', 'capability_enabled', True),
               (313, 'enabled', 'config_sha256', closed['config_sha256']),
               (314, 'enabled', 'reached_required_frontier', False),
               (316, 'closed', 'result_kind', 'candidate-reject')]
    observed = []
    for identity, side, field, value in vectors:
        on, off = copy.deepcopy(enabled), copy.deepcopy(closed)
        (on if side == 'enabled' else off)[field] = value
        actual = None
        try:
            module.check_pair_context(on, off)
        except module.ControlFailure as error:
            actual = error.identity
        observed.append(dict(expected=identity, actual=actual))
        if identity != actual:
            failures.append(identity)
    print(json.dumps(dict(scope='Synthetic schema unit vectors, not host observations or activation classification.',
                          failures=failures, vectors=observed)))
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(run(Path(sys.argv[1]) if len(sys.argv) == 2 else
                 Path(__file__).with_name('workchain-activation-context.py')))
