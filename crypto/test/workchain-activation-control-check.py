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
    rows = [line.split('\t') for line in result.stdout.decode().splitlines()]
    require(len(rows) == 4 and all(len(r) == 5 for r in rows), 333)
    require([(r[0], r[1]) for r in rows] == [('0', '0'), ('0', '1'), ('1', '0'), ('1', '1')], 334)
    # No application success code is passed to the rejection instrument.
    require([int(r[2]) for r in rows] == [-7201, -7201, -7201, 0] and rows[3][3] == '', 335)
    require(rows[0][4] == rows[2][4] and rows[1][4] == rows[3][4] and rows[0][4] != rows[1][4], 336)
    require(helper.is_activation_rejection(int(rows[2][2]), rows[2][3], boundary='scoped') is True, 337)
    require(helper.is_activation_rejection(int(rows[1][2]), rows[1][3], boundary='scoped') is False, 338)
    # Another earlier failure is outside the shared instrument's known domain.
    # Preserve the unknown; do not silently promote it to a classified rejection.
    try:
        helper.is_activation_rejection(int(rows[0][2]), rows[0][3], boundary='scoped')
    except helper.UnclassifiableActivationStatus:
        unknown = True
    else:
        unknown = False
    require(unknown, 339)
    # Schema calibration only: statuses/config hashes are real resolver outputs;
    # the zero/export fields below are unit inputs, NOT collator observations.
    closed = dict(status_code=int(rows[2][2]), status_message=rows[2][3],
                  transactions=0, candidate_exports=[], run_id='schema-calibration',
                  host_path='scoped-resolver-calibration', input_sha256='1' * 64,
                  common_config_sha256='2' * 64, config_origin='test-internal',
                  capability_enabled=False, config_sha256=rows[2][4])
    enabled = dict(closed, capability_enabled=True, config_sha256=rows[3][4],
                   reached_required_frontier=True)
    check_pair(enabled, closed, boundary='scoped')
    earlier = dict(closed, status_code=int(rows[1][2]), status_message=rows[1][3])
    caught = None
    try:
        check_pair(enabled, earlier, boundary='scoped')
    except ControlFailure as error:
        caught = error.identity
    require(caught == 315, 341)
    print(json.dumps({'scope': 'Resolver-only real configuration/status calibration; no live I13e claim, '
                             'no simulated zero-transaction or no-export observations.',
                      'rows': rows, 'activation': [1, 0], 'known_earlier': [0, 1],
                      'unclassifiable_earlier': [0, 0],
                      'schema_consumer_earlier_rejection_identity': caught,
                      'schema_consumer_scope': 'Unit record fields, not actual transaction/export observations.'}))


if __name__ == '__main__':
    try:
        main()
    except ControlFailure as error:
        print(json.dumps({'guard': error.identity}), file=sys.stderr)
        sys.exit(1)
