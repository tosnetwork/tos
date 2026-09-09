#!/usr/bin/env python3
"""Fail closed if Counter's hand-encoded wire tags drift from generated TL-B."""
import argparse
from pathlib import Path
import re


def check(repo: Path):
    generated = (repo / 'crypto/block/block-auto.h').read_text()
    fixture = (repo / 'test/test-counter-disk-integration.cmake').read_text()
    required = {'UnoV2ResourceInput', 'UnoV2ResourceState', 'UnoV2ResourceWorkOutput',
                'UnoV2ResourcePolicy', 'UnoV2EngineConfiguration', 'WorkchainNativeIngressPolicy'}
    rows = re.findall(r'// @generated-tag (\w+) (\d+)\n[^\n]*?x\{([0-9a-fA-F]+)\}', fixture)
    assert len(rows) == len(required) and {r[0] for r in rows} == required, '960: incomplete tag inventory'
    for name, index, actual in rows:
        declaration = re.search(r'struct ' + re.escape(name) + r' final : TLB_Complex \{(.*?)\n\};', generated, re.S)
        assert declaration is not None, f'961: missing generated type {name}'
        tags = re.search(r'cons_tag\[\d+\] = \{([^}]+)\}', declaration[1])
        assert tags is not None, f'962: missing generated tags {name}'
        values = re.findall(r'0x([0-9a-fA-F]+)', tags[1])
        assert int(index) < len(values), f'963: missing generated constructor {name}'
        assert int(actual, 16) == int(values[int(index)], 16), f'964: tag mismatch {name}: {actual} != {values[int(index)]}'
        print(f'{name}\t{index}\t{actual.lower()}')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    check(parser.parse_args().repo)
