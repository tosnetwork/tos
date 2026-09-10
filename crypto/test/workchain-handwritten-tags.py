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
    rust = (repo / 'tosctl/src/block/src/master.rs').read_text()
    rust_layout = re.search(r'/\*\n(masterchain_state_extra[^;]*= McStateExtra;)\n\*/', rust)
    require(rust_layout and compact(rust_layout[1]) == compact(layouts[0]),
            974, 'Rust McStateExtra layout declaration drift')
    for name, constant in [('McStateExtra', 'MC_STATE_EXTRA_TAG'),
                           ('WorkchainInstanceRecord', 'WORKCHAIN_INSTANCE_RECORD_TAG'),
                           ('WorkchainInstanceLedger', 'WORKCHAIN_INSTANCE_LEDGER_TAG')]:
        cpp = re.search(r'struct ' + name + r' final : TLB_Complex \{(.*?)\n\};', generated, re.S)
        actual = re.search(r'const ' + constant + r': u(\d+) = 0x([0-9a-f]+);', rust)
        expected = re.search(r'cons_tag\[1\] = \{ 0x([0-9a-fA-F]+)[Uu]? \}', cpp[1]) if cpp else None
        bits = re.search(r'cons_len_exact = (\d+)', cpp[1]) if cpp else None
        require(actual and expected and bits and int(actual[1]) == int(bits[1])
                and int(actual[2], 16) == int(expected[1], 16), 975, f'Rust {name} tag or width drift')
        reader = re.search(r'impl Deserializable for ' + name + r' \{(.*?)\n\}', rust, re.S)
        writer = re.search(r'impl Serializable for ' + name + r' \{(.*?)\n\}', rust, re.S)
        require(reader and writer and 'cell.get_next_u32()?' in reader[1]
                and f'.append_u32({constant})?' in writer[1], 976, f'Rust {name} tag I/O width drift')
    reader = re.search(r'impl Deserializable for McStateExtra \{(.*?)\n\}', rust, re.S)[1]
    writer = re.search(r'impl Serializable for McStateExtra \{(.*?)\n\}', rust, re.S)[1]
    require('self.workchain_instances = WorkchainInstanceLedger::construct_from_cell(cell1.checked_drain_reference()?)?;' in reader
            and 'builder1.checked_append_reference(self.workchain_instances.serialize()?)?;' in writer,
            977, 'Rust mandatory auxiliary ledger reference missing')
    require(reader.index('self.workchain_instances =') < reader.index('self.global_balance.read_from')
            and writer.index('builder1.checked_append_reference(self.workchain_instances')
                < writer.index('builder.checked_append_reference(builder1.into_cell()?)'),
            978, 'Rust ledger reference is outside auxiliary cell')
    print('Rust.McStateExtra: generated tags, widths, declared layout and mandatory auxiliary reference checked')
    print(f'Python.McStateExtra\t{constants["WIRE_TAG_BITS"]}\t{constants["WIRE_TAG"]:08x}')
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    check(parser.parse_args().repo)
