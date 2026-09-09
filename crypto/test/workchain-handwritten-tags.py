#!/usr/bin/env python3
"""Fail closed if Counter's hand-encoded wire tags drift from generated TL-B."""
import argparse
import ast
import json
from pathlib import Path
import re


class GuardFailure(Exception):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(f"{code}: {detail}")


def require(condition, code, detail):
    if not condition:
        raise GuardFailure(code, detail)


def check(repo: Path):
    inventory = json.loads((repo / 'crypto/test/workchain-wire-representations.json').read_text())
    roles = inventory['representations']
    require(len(roles) == 5 and {r['id'] for r in roles} == {'schema', 'generated_cpp', 'fift', 'python', 'rust'},
            972, 'incomplete representation inventory')
    for role in roles:
        require((repo / role['path']).is_file(), 973, f'missing representation {role["id"]}')
    print('Rust.McStateExtra: existence only; migration BLOCKED; not format-validated')
    generated = (repo / 'crypto/block/block-auto.h').read_text()
    fixture = (repo / 'test/test-counter-disk-integration.cmake').read_text()
    required = {'UnoV2ResourceInput', 'UnoV2ResourceState', 'UnoV2ResourceWorkOutput',
                'UnoV2ResourcePolicy', 'UnoV2EngineConfiguration', 'WorkchainNativeIngressPolicy'}
    rows = re.findall(r'// @generated-tag (\w+) (\d+)\n[^\n]*?x\{([0-9a-fA-F]+)\}', fixture)
    require(len(rows) == len(required) and {r[0] for r in rows} == required, 960, 'incomplete tag inventory')
    for name, index, actual in rows:
        declaration = re.search(r'struct ' + re.escape(name) + r' final : TLB_Complex \{(.*?)\n\};', generated, re.S)
        require(declaration is not None, 961, f'missing generated type {name}')
        tags = re.search(r'cons_tag\[\d+\] = \{([^}]+)\}', declaration[1])
        require(tags is not None, 962, f'missing generated tags {name}')
        values = re.findall(r'0x([0-9a-fA-F]+)', tags[1])
        require(int(index) < len(values), 963, f'missing generated constructor {name}')
        require(int(actual, 16) == int(values[int(index)], 16), 964, f'tag mismatch {name}: {actual} != {values[int(index)]}')
        print(f'{name}\t{index}\t{actual.lower()}')
    # Parse source without importing optional Python harness dependencies.
    module = ast.parse((repo / 'test/tostester/src/pytosiq_core/tlb/block.py').read_text())
    classes = [node for node in module.body if isinstance(node, ast.ClassDef) and node.name == 'McStateExtra']
    require(len(classes) == 1, 965, 'missing or duplicate Python McStateExtra')
    cls = classes[0]
    constants = {target.id: ast.literal_eval(node.value) for node in cls.body
                 if isinstance(node, ast.Assign) for target in node.targets
                 if isinstance(target, ast.Name) and target.id in {'WIRE_TAG', 'WIRE_TAG_BITS'}}
    decl = re.search(r'struct McStateExtra final : TLB_Complex \{(.*?)\n\};', generated, re.S)
    require(decl is not None, 966, 'missing generated McStateExtra')
    tag = re.search(r'cons_tag\[1\] = \{ 0x([0-9a-fA-F]+)[Uu]? \}', decl[1])
    width = re.search(r'cons_len_exact = (\d+)', decl[1])
    require(tag and width, 966, 'unsupported generated McStateExtra declaration')
    require(constants.get('WIRE_TAG') == int(tag[1], 16), 967, 'Python McStateExtra tag drift')
    require(constants.get('WIRE_TAG_BITS') == int(width[1]), 968, 'Python McStateExtra tag width drift')
    schema = re.sub(r'//[^\n]*', '', (repo / 'crypto/block/block.tlb').read_text())
    layouts = re.findall(r'(?m)^masterchain_state_extra[^;]*= McStateExtra;', schema)
    require(len(layouts) == 1, 969, 'missing or ambiguous McStateExtra schema')
    compact = lambda text: re.sub(r'\s+', '', text)
    require(compact(ast.get_docstring(cls) or '') == compact(layouts[0]), 970, 'Python McStateExtra layout declaration drift')
    auxiliary = re.search(r'struct McStateExtra_aux::Record \{(.*?)\n\};', generated, re.S)
    require(auxiliary and re.search(r'Ref<Cell> workchain_instances;.*// workchain_instances : \^WorkchainInstanceLedger', auxiliary[1]), 971, 'generated auxiliary ledger field changed')
    print(f'Python.McStateExtra\t{constants["WIRE_TAG_BITS"]}\t{constants["WIRE_TAG"]:08x}')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    check(parser.parse_args().repo)
