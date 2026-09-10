#!/usr/bin/env python3
"""Extract exact validator visitor statements for local-expression tests.

This does not bypass registry readiness inside ValidateQuery. It does not run
ValidateQuery or emit CandidateAccept/CandidateReject or transaction/export counts.
The live call-site obligation remains separate and blocked on the earlier gate.
"""
import argparse
import hashlib
import json
from pathlib import Path


def extract(source, start, end):
    if source.count(start) != 1:
        raise ValueError('visitor start is absent or ambiguous')
    begin = source.index(start)
    finish = source.index(end, begin) + len(end)
    return source[begin:finish]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    path = args.repo / 'validator/impl/validate-query.cpp'
    data = path.read_bytes()
    source = data.decode()
    args.out.mkdir(parents=True, exist_ok=True)
    regions = {
        'validator-custom-visitor.inc': extract(source, 'auto custom = std::visit(td::overloaded(',
                                                '}), *resolved_execution.ok());'),
        'validator-ready-visitor.inc': extract(source, 'auto ready = std::visit(td::overloaded(',
                                               '}), *execution_res.ok());'),
    }
    for name, text in regions.items():
        (args.out / name).write_text(text + '\n')
    (args.out / 'visitor-source.json').write_text(json.dumps({
        'source': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
        'scope': 'Verbatim local visitor statements; not production call-site reachability.',
        'regions': {name: {'offset': source.index(text), 'text': text,
                           'sha256': hashlib.sha256(text.encode()).hexdigest()}
                    for name, text in regions.items()},
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
