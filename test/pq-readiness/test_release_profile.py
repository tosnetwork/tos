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
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROBE = """
#include "common/global-version.h"
#include "crypto/vm/pqops.h"
#include <iostream>
int main() {
  std::cout << tos::SUPPORTED_VERSION << ' ' << vm::pq_mldsa44_min_version;
}
"""


def ceiling(*flags: str) -> tuple[int, int]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / 'probe.cpp'
        source.write_text(PROBE)
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-I', str(ROOT),
                        str(source), *flags, '-o', str(root / 'probe')], check=True)
        supported, minimum = subprocess.check_output([str(root / 'probe')], text=True).split()
        return int(supported), int(minimum)


supported, minimum = ceiling()
if supported != 16:
    raise SystemExit(f'the advertised ceiling is {supported}, not 16')
if supported != minimum:
    raise SystemExit(f'ceiling {supported} and opcode gate {minimum} disagree; the shipped '
                     'tools and the instruction would not match')

# The removed option must stay removed. Defining it again has to change nothing,
# or a v15 binary can be produced from a commit whose evidence says v16.
for revived in ('-DTOS_PQ_V16_CANDIDATE=1', '-DTOS_PQ_V16_CANDIDATE=0'):
    again, _ = ceiling(revived)
    if again != supported:
        raise SystemExit(f'{revived} still selects a different ceiling ({again})')

print(f'PASS: one ceiling ({supported}), matching the opcode gate, with no build profile to select')
