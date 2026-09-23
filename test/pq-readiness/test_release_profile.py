#!/usr/bin/env python3
"""The advertised ceiling and the opcode's gate are one number, not two.

`SUPPORTED_VERSION` is what a binary claims it can execute. It is not a switch:
a chain configured above it is logged and then executed anyway. What it does
control is the version a VM is built at when no configuration supplies one --
tooling paths such as `lite-client runmethod`, Fift and `run_get_method`. So if
the ceiling and the instruction's own minimum ever disagree, the shipped tools
either cannot run an instruction this build implements, or run one it does not.

There is deliberately no build option here any more. A profile that selects a
different ceiling from the same source is a second answer to "what does this
binary implement", and the activation evidence then has to carry which one was
built. One source commit, one ceiling.

With more than one gated instruction the rule is no longer "the two numbers are
equal". Each instruction keeps the minimum it shipped with -- moving an older
gate forward would retire an instruction a running network may already rely on
-- so what must hold is that the ceiling is exactly the highest of them. Below
that, the shipped tools cannot reach an instruction this build implements;
above it, the binary claims a version it has nothing to show for.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROBE = """
#include "common/global-version.h"
#include "crypto/vm/poseidon2ops.h"
#include "crypto/vm/pqops.h"
#include <iostream>
int main() {
  std::cout << tos::SUPPORTED_VERSION << ' ' << vm::pq_mldsa44_min_version << ' '
            << vm::poseidon2_min_version << ' ' << vm::poseidon2_path7_min_version;
}
"""

# Every version-gated instruction this binary implements, by the minimum it
# shipped with. Adding one here is how a new gate joins the invariant below.
GATES = {
    'PQCHECKSIG_MLDSA44': 16,
    'POSEIDON2_PERM8/POSEIDON2_HASH7': 17,
    'POSEIDON2_PATH7': 18,
}


def ceiling(*flags: str) -> tuple[int, ...]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / 'probe.cpp'
        source.write_text(PROBE)
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-I', str(ROOT),
                        str(source), *flags, '-o', str(root / 'probe')], check=True)
        return tuple(int(value) for value in
                     subprocess.check_output([str(root / 'probe')], text=True).split())


# Zipped against GATES, which PROBE must print in the same order, so that
# adding a gate means editing those two and nothing else. The fixed-arity form
# did not survive that: PATH7 joined PROBE and GATES and left this line
# expecting three values, so the check stopped checking and started crashing.
# The length guard is what makes the drift say so instead of unpacking wrongly.
values = ceiling()
if len(values) != len(GATES) + 1:
    raise SystemExit(f'the probe printed {len(values)} numbers, but GATES names {len(GATES)} '
                     'instruction gates; PROBE and GATES have drifted apart')
supported, *gates = values
built = dict(zip(GATES, gates))
if built != GATES:
    raise SystemExit(f'the built gates {built} are not the expected {GATES}')
if supported != max(GATES.values()):
    raise SystemExit(f'the advertised ceiling is {supported}, but the highest instruction gate '
                     f'is {max(GATES.values())}; the shipped tools and the instruction set '
                     'would not match')
for name, gate in built.items():
    if gate > supported:
        raise SystemExit(f'{name} needs version {gate}, above the advertised ceiling {supported}')

# The removed option must stay removed. Defining it again has to change nothing,
# or a v15 binary can be produced from a commit whose evidence says v16.
for revived in ('-DTOS_PQ_V16_CANDIDATE=1', '-DTOS_PQ_V16_CANDIDATE=0'):
    again = ceiling(revived)[0]
    if again != supported:
        raise SystemExit(f'{revived} still selects a different ceiling ({again})')

print(f'PASS: one ceiling ({supported}), equal to the highest instruction gate '
      f'({", ".join(f"{name}={gate}" for name, gate in sorted(built.items()))}), '
      'with no build profile to select')
