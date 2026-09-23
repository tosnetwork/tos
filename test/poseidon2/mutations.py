#!/usr/bin/env python3
"""Remove one protection at a time, in both VMs; a mutation that fails to
compile is not a killed mutation, and a mutation that turns the wrong assertion
red is not evidence for the one it was aimed at.

Each case names the suites that must go red and the exact complaint they must
make, and the suites that must stay green. That second half is what shows a
mutation was contained: changing a Rust constant must not be reported by the C++
VM, or the two would not be independent implementations.

Usage: mutations.py [--build BUILD] [--only NAME ...]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CPP_PARAMS = ROOT / 'crypto/vm/poseidon2-params.h'
CPP_OPS = ROOT / 'crypto/vm/poseidon2ops.cpp'
CPP_HEADER = ROOT / 'crypto/vm/poseidon2ops.h'
RS_PARAMS = ROOT / 'tosctl/src/block/src/poseidon2_params.rs'
RS_PERM = ROOT / 'tosctl/src/block/src/poseidon2.rs'
RS_OPS = ROOT / 'tosctl/src/vm/src/executor/poseidon2.rs'
CARGO_ROOT = ROOT / 'tosctl/src'


def bump_first_byte_after(marker: str):
    """Change one constant: the first hex byte of the first entry of a table.

    Anchoring on the table name rather than on a literal keeps the script
    working when the tables are regenerated, which is the point -- a mutation
    script that has to be edited whenever the pin moves would be edited into
    agreement with whatever the pin now says.
    """

    def mutate(text: str) -> str:
        start = text.index(marker) + len(marker)
        match = re.compile(r'0x([0-9a-f]{2})').search(text, start)
        assert match, f'no constant found after {marker!r}'
        original = int(match.group(1), 16)
        replacement = f'0x{(original ^ 1):02x}'
        return text[: match.start()] + replacement + text[match.end() :]

    return mutate


def replace(before: str, after: str, count: int = 1):
    def mutate(text: str) -> str:
        assert text.count(before) == count, \
            f'anchor {before!r} appears {text.count(before)} times, expected {count}'
        return text.replace(before, after)

    return mutate


@dataclass
class Case:
    name: str
    why: str
    edits: list[tuple[Path, object]]
    # suite -> substrings that must all appear in its failure output
    expect_red: dict[str, list[str]] = field(default_factory=dict)
    expect_green: list[str] = field(default_factory=list)
    # substrings that must NOT appear, to show the mutation hit what it aimed at
    expect_absent: dict[str, list[str]] = field(default_factory=dict)


CASES = [
    Case('cpp/round-constant', 'one RC8 field, C++',
         [(CPP_PARAMS, bump_first_byte_after('rc8_be[rounds_total]'))],
         expect_red={'cpp': ['manifest digest', 'permutation does not match']},
         expect_green=['block', 'vm']),
    Case('cpp/internal-matrix', 'one MAT_INTERNAL8 element, C++',
         [(CPP_PARAMS, bump_first_byte_after('mat_internal8_be[state_width]'))],
         # The permutation never reads this table; only the manifest commits to
         # it. If the digest check were dropped, this mutation would survive.
         expect_red={'cpp': ['manifest digest']},
         expect_absent={'cpp': ['permutation does not match']},
         expect_green=['block', 'vm']),
    Case('cpp/diagonal-matrix', 'one MAT_DIAG8 element, C++',
         [(CPP_PARAMS, bump_first_byte_after('mat_diag8_be[state_width]'))],
         expect_red={'cpp': ['manifest digest', 'permutation does not match']},
         expect_green=['block', 'vm']),
    Case('cpp/partial-rounds', 'RP 57 -> 56 in the loop, C++',
         [(CPP_OPS, replace('const int partial_end = rounds_f_beginning + rounds_p;',
                            'const int partial_end = rounds_f_beginning + rounds_p - 1;'))],
         # The manifest still says 57, so only the vectors can catch this.
         expect_red={'cpp': ['permutation does not match']},
         expect_absent={'cpp': ['manifest digest']},
         expect_green=['block', 'vm']),
    Case('cpp/swapped-lanes', 'two input lanes swapped, C++',
         [(CPP_OPS, replace('  poseidon2::permute(state);\n  for (int i = 0;',
                            '  std::swap(state[0], state[1]);\n  poseidon2::permute(state);\n  for (int i = 0;'))],
         expect_red={'cpp': ['differs in the VM']},
         expect_green=['block', 'vm']),
    Case('cpp/hash7-lane', 'HASH7 returns lane 1, C++',
         [(CPP_OPS, replace('  push_field_element(stack, state[0]);',
                            '  push_field_element(stack, state[1]);'))],
         expect_red={'cpp': ['HASH7']},
         expect_green=['block', 'vm']),
    Case('cpp/silent-reduction', 'an out-of-range input is reduced to zero, C++',
         [(CPP_OPS, replace('    throw VmError{Excno::range_chk, "Poseidon2 input is not below the field modulus"};',
                            '    std::memset(out, 0, 32);'))],
         expect_red={'cpp': ['was accepted in lane']},
         expect_green=['block', 'vm']),
    Case('cpp/version-gate', 'the version gate removed, C++',
         [(CPP_OPS, replace('->require_version(poseidon2_min_version)',
                            '->require_version(0)', count=2))],
         expect_red={'cpp': ['was accepted at version']},
         expect_green=['block', 'vm']),
    Case('cpp/zero-gas', 'the instruction charges nothing, C++',
         [(CPP_HEADER, replace('poseidon2_perm8_gas_price = 2800', 'poseidon2_perm8_gas_price = 0'))],
         expect_red={'cpp': ['gas is']},
         expect_green=['block', 'vm']),

    Case('rust/round-constant', 'one RC8 field, Rust -- and the C++ VM must not notice',
         [(RS_PARAMS, bump_first_byte_after('RC8_BE: '))],
         expect_red={'block': ['the_manifest_rebuilt_here_has_the_pinned_digest',
                               'every_pinned_vector_is_reproduced']},
         expect_green=['cpp']),
    Case('rust/internal-matrix', 'one MAT_INTERNAL8 element, Rust',
         [(RS_PARAMS, bump_first_byte_after('MAT_INTERNAL8_BE: '))],
         expect_red={'block': ['the_manifest_rebuilt_here_has_the_pinned_digest']},
         expect_absent={'block': ['every_pinned_vector_is_reproduced']},
         expect_green=['cpp']),
    Case('rust/partial-rounds', 'RP 57 -> 56 in the loop, Rust',
         [(RS_PERM, replace('let partial_end = ROUNDS_F_BEGINNING + ROUNDS_P;',
                            'let partial_end = ROUNDS_F_BEGINNING + ROUNDS_P - 1;'))],
         expect_red={'block': ['every_pinned_vector_is_reproduced']},
         expect_absent={'block': ['the_manifest_rebuilt_here_has_the_pinned_digest']},
         expect_green=['cpp']),
    Case('rust/swapped-lanes', 'two input lanes swapped, Rust',
         [(RS_OPS, replace('    Ok(poseidon2::permute(&state))',
                           '    state.swap(0, 1);\n    Ok(poseidon2::permute(&state))'))],
         expect_red={'vm': ['every_pinned_permutation_vector_runs_in_the_vm']},
         expect_green=['cpp']),
    Case('rust/hash7-lane', 'HASH7 returns lane 1, Rust',
         [(RS_OPS, replace('IntegerData::from_unsigned_bytes_be(&result[0])',
                           'IntegerData::from_unsigned_bytes_be(&result[1])'))],
         expect_red={'vm': ['every_pinned_hash_vector_runs_in_the_vm']},
         expect_green=['cpp']),
    Case('rust/silent-reduction', 'an out-of-range input is reduced to zero, Rust',
         [(RS_OPS, replace('        fail!(ExceptionCode::RangeCheckError, "Poseidon2 input is not below the field modulus");',
                           '        out = [0u8; 32];'))],
         expect_red={'vm': ['anything_that_is_not_already_a_field_element_is_refused']},
         expect_green=['cpp']),
    Case('rust/version-gate', 'the version gate removed, Rust',
         [(RS_OPS, replace('pub(super) const MIN_VERSION: u32 = 17;',
                           'pub(super) const MIN_VERSION: u32 = 0;'))],
         expect_red={'vm': ['neither_instruction_exists_before_its_version']},
         expect_green=['cpp']),
    Case('rust/zero-gas', 'the instruction charges nothing, Rust',
         [(RS_OPS, replace('pub(super) const GAS_PRICE: i64 = 2800;',
                           'pub(super) const GAS_PRICE: i64 = 0;'))],
         expect_red={'vm': ['both_instructions_cost_the_tariff']},
         expect_green=['cpp']),

    # PATH7's two prices. Both VMs pin them as literals in their own tests --
    # deliberately, because a test that reads the constant it is checking
    # cannot check it -- but until these four cases existed nobody had watched
    # either tripwire fire. A guard nobody has seen go red is a guard that
    # might be measuring nothing, and these two numbers decide how much a
    # withdrawal costs on a chain whose two VMs have to agree to the gas.
    Case('cpp/path7-level-price', 'a level of PATH7 costs less, C++',
         [(CPP_HEADER, replace('poseidon2_path7_level_gas_price = 3000',
                               'poseidon2_path7_level_gas_price = 2999'))],
         expect_red={'cpp': ['one more level of POSEIDON2_PATH7 costs']},
         expect_green=['block', 'vm']),
    Case('cpp/path7-base-price', 'the PATH7 base costs nothing, C++',
         [(CPP_HEADER, replace('poseidon2_path7_base_gas_price = 500',
                               'poseidon2_path7_base_gas_price = 0'))],
         expect_red={'cpp': ['extrapolates back to']},
         expect_green=['block', 'vm']),
    Case('rust/path7-level-price', 'a level of PATH7 costs less, Rust',
         [(RS_OPS, replace('pub(super) const PATH7_LEVEL_GAS_PRICE: i64 = 3000;',
                           'pub(super) const PATH7_LEVEL_GAS_PRICE: i64 = 2999;'))],
         expect_red={'vm': ['a_path_costs_its_base_plus_a_level']},
         expect_green=['cpp']),
    # The ordering that decides an oversized index. Both VMs must refuse it
    # before charging a level; until 2026-09-23 the C++ one refused after
    # twelve of them, and charged more to refuse than to succeed. Two
    # implementations of one public instruction that price the same operand
    # differently are two instructions.
    Case('cpp/path7-index-decided-late', 'the oversized index is decided after the loop, C++',
         [(CPP_OPS, replace('  if (remaining->sgn() != 0) {\n'
                            '    throw VmError{Excno::range_chk, "Poseidon2 path index is past the depth given"};\n'
                            '  }\n\n  Ref<Cell> node = std::move(path);',
                            '  Ref<Cell> node = std::move(path);'))],
         expect_red={'cpp': ['refusing an oversized index cost']},
         expect_green=['block', 'vm']),
    Case('rust/path7-index-not-refused', 'the leftover digit is not refused, Rust',
         [(RS_OPS, replace('    if value.iter().any(|byte| *byte != 0) {\n'
                           '        fail!(ExceptionCode::RangeCheckError, "Poseidon2 path index is past the depth given");\n'
                           '    }',
                           '    // mutated'))],
         expect_red={'vm': ['an_index_past_the_depth_is_refused_before_a_level_is_charged']},
         expect_green=['cpp']),

    Case('rust/path7-base-price', 'the PATH7 base costs nothing, Rust',
         [(RS_OPS, replace('pub(super) const PATH7_BASE_GAS_PRICE: i64 = 500;',
                           'pub(super) const PATH7_BASE_GAS_PRICE: i64 = 0;'))],
         expect_red={'vm': ['a_path_costs_its_base_plus_a_level']},
         expect_green=['cpp']),
]


def failure_signature(suite: str, output: str) -> str:
    """What actually went red, rather than everything the runner printed.

    Cargo lists every test it ran, passing ones included, so matching a test
    name against the raw output would report a mutation as having broken tests
    that were green. Only the failures are evidence.
    """
    if suite == 'cpp':
        return '\n'.join(line for line in output.splitlines() if line.startswith('FAIL'))
    return '\n'.join(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


class Suites:
    def __init__(self, build: Path):
        self.build = build

    def run(self, name: str) -> subprocess.CompletedProcess:
        if name == 'cpp':
            built = subprocess.run(['cmake', '--build', str(self.build), '--target', 'test-poseidon2',
                                    '-j', '8'], capture_output=True, text=True)
            if built.returncode:
                return subprocess.CompletedProcess(built.args, 125, built.stdout, built.stderr)
            return subprocess.run([str(self.build / 'crypto/test-poseidon2')],
                                  capture_output=True, text=True, timeout=600)
        if name == 'block':
            return self._cargo(['test', '-p', 'chain_block', 'poseidon2'])
        if name == 'vm':
            return self._cargo(['test', '-p', 'tos_vm', '--test', 'test_poseidon2'])
        raise KeyError(name)

    def _cargo(self, args: list[str]) -> subprocess.CompletedProcess:
        import os
        env = dict(os.environ)
        env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
        env['CARGO_TERM_COLOR'] = 'never'
        return subprocess.run(['cargo', *args], cwd=CARGO_ROOT, capture_output=True,
                              text=True, timeout=3600, env=env)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, default=ROOT / 'build')
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    suites = Suites(options.build)

    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    needed = sorted({s for c in cases for s in list(c.expect_red) + c.expect_green})
    for suite in needed:
        baseline = suites.run(suite)
        if baseline.returncode:
            raise SystemExit(f'{suite} is not green before any mutation:\n'
                             f'{baseline.stdout}\n{baseline.stderr}')
        print(f'baseline green: {suite}', flush=True)

    def killed(suite, result, expected, case) -> bool:
        if result.returncode in (0, 125):
            return False
        output = failure_signature(suite, result.stdout + result.stderr)
        if any(text not in output for text in expected):
            return False
        return not any(t in output for t in case.expect_absent.get(suite, []))

    survivors = []
    retries = []
    for case in cases:
        originals = [(path, path.read_text()) for path, _ in case.edits]
        try:
            for (path, mutate), (_, original) in zip(case.edits, originals):
                mutated = mutate(original)
                assert mutated != original, f'{case.name}: the mutation changed nothing'
                path.write_text(mutated)
            verdicts = []
            for suite, expected in case.expect_red.items():
                # Run twice when the first answer is not a clean kill. Running
                # these batteries back to back has twice produced a verdict that
                # did not reproduce in isolation, so a single disagreeing run is
                # not evidence either way: it is reported as a retry rather than
                # quietly replaced by whichever answer was wanted.
                result = suites.run(suite)
                if not killed(suite, result, expected, case):
                    retried = suites.run(suite)
                    if killed(suite, retried, expected, case):
                        retries.append(f'{case.name}/{suite}')
                        result = retried
                output = failure_signature(suite, result.stdout + result.stderr)
                if result.returncode == 125:
                    survivors.append(f'{case.name}: {suite} no longer compiles, which is not evidence')
                    verdicts.append(f'{suite}=UNCOMPILED')
                    continue
                if result.returncode == 0:
                    survivors.append(f'{case.name}: {suite} stayed green')
                    verdicts.append(f'{suite}=SURVIVED')
                    continue
                missing = [text for text in expected if text not in output]
                if missing:
                    survivors.append(f'{case.name}: {suite} failed, but not about {missing}')
                    verdicts.append(f'{suite}=WRONG-ASSERTION')
                    continue
                unwanted = [t for t in case.expect_absent.get(suite, []) if t in output]
                if unwanted:
                    survivors.append(f'{case.name}: {suite} also failed about {unwanted}')
                    verdicts.append(f'{suite}=OVERSHOT')
                    continue
                verdicts.append(f'{suite}=killed')
            for suite in case.expect_green:
                result = suites.run(suite)
                if result.returncode:
                    survivors.append(f'{case.name}: {suite} was expected to be unaffected but failed')
                    verdicts.append(f'{suite}=LEAKED')
                else:
                    verdicts.append(f'{suite}=unaffected')
            print(f'{case.name:26} {case.why:52} {" ".join(verdicts)}', flush=True)
        finally:
            for path, original in originals:
                path.write_text(original)

    for suite in needed:
        restored = suites.run(suite)
        if restored.returncode:
            raise SystemExit(f'{suite} did not come back green after restoring:\n'
                             f'{restored.stdout}\n{restored.stderr}')
    print('all suites green again', flush=True)

    if retries:
        print(f'\nNOT REPRODUCIBLE ON THE FIRST RUN: {", ".join(retries)}', file=sys.stderr)
        print('  Each was killed on a second, isolated run. The mutation is real; the harness '
              'is not reliable when batteries run back to back, and that cuts both ways.',
              file=sys.stderr)

    if survivors:
        print('\nSURVIVORS:', file=sys.stderr)
        for line in survivors:
            print('  ' + line, file=sys.stderr)
        return 1
    print(f'\n{len(cases)} mutations, all killed by the assertion they were aimed at')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
