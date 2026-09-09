#!/usr/bin/env python3
"""Real resolver calibration using the one shared activation instrument.

No collator transaction/export observations are fabricated by this driver.
Missing probe/helper or unknown observations fail rather than skip.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

from workchain_activation_control import require, check_pair, ControlFailure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--shared-helper', type=Path,
                        default=Path(__file__).with_name('workchain_activation_rejection.py'))
    args = parser.parse_args()
    path = args.shared_helper.resolve(strict=True)
    spec = importlib.util.spec_from_file_location('workchain_activation_rejection', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    sys.modules['workchain_activation_rejection'] = helper
    helper.check_activation_source(args.repo)
    suite = unittest.defaultTestLoader.loadTestsFromModule(helper)
    require(suite.countTestCases() > 0, 330)
    require(unittest.TextTestRunner().run(suite).wasSuccessful(), 331)
    context = subprocess.run([sys.executable, str(Path(__file__).with_name(
        'workchain-activation-context-selftest.py'))], check=False, capture_output=True)
    sys.stderr.buffer.write(context.stderr)
    require(context.returncode == 0, 340)
    result = subprocess.run([str(args.probe.resolve(strict=True))], check=False, capture_output=True)
    sys.stderr.buffer.write(result.stderr)
    require(result.returncode == 0, 332)
    output = result.stdout.decode()
    helper.check_scoped_probe_output(output)
    rows = [line.split('\t') for line in output.splitlines()]
    require(rows[0][4] == rows[2][4] and rows[1][4] == rows[3][4] and rows[0][4] != rows[1][4], 336)
    # Schema calibration only: statuses/config hashes are real resolver outputs;
    # the zero/export fields below are unit inputs, NOT collator observations.
    closed = dict(status_code=int(rows[2][2]), status_message=rows[2][3],
                  transactions=0, candidate_exports=[], run_id='schema-calibration',
                  host_path='scoped-resolver-calibration', input_sha256='1' * 64,
                  common_config_sha256='2' * 64, config_origin='test-internal',
                  capability_enabled=False, config_sha256=rows[2][4])
    enabled = dict(closed, capability_enabled=True, config_sha256=rows[3][4],
                   reached_required_frontier=(int(rows[3][2]) == 0))
    check_pair(enabled, closed, boundary='scoped')
    caught_identities = []
    for earlier_row in rows:
        if int(earlier_row[2]) == 0:
            continue  # Success/unknown-domain checks belong to the shared calibration.
        if helper.is_activation_rejection(int(earlier_row[2]), earlier_row[3]):
            continue
        earlier = dict(closed, status_code=int(earlier_row[2]), status_message=earlier_row[3])
        caught = None
        try:
            check_pair(enabled, earlier, boundary='scoped')
        except ControlFailure as error:
            caught = error.identity
        require(caught == 315, 341)
        caught_identities.append(caught)
    print(json.dumps({'scope': 'Resolver-only real configuration/status calibration; no live I13e claim, '
                             'no simulated zero-transaction or no-export observations.',
                      'rows': rows, 'classification_expectations': 'shared check_scoped_probe_output',
                      'schema_consumer_earlier_rejection_identities': caught_identities,
                      'schema_consumer_scope': 'Unit record fields, not actual transaction/export observations.'}))


if __name__ == '__main__':
    try:
        main()
    except ControlFailure as error:
        print(json.dumps({'guard': error.identity}), file=sys.stderr)
        sys.exit(1)
