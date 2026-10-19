"""Transport genuine exotic cells into both VMs; decoding must reject them."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(R / "test/tostester/src"))
from pytosiq_core import Builder
from pytosiq_core.boc.exotic import CellTypes

p = argparse.ArgumentParser()
p.add_argument("scenarios", type=Path)
a = p.parse_args()
rows = a.scenarios.read_text().splitlines()
good = next(x.split("\t") for x in rows if x.startswith("auth\t"))
library = Builder(type_=CellTypes.library_ref).store_uint(2, 8).store_bytes(bytes(32)).end_cell()
pruned = (
    Builder(type_=CellTypes.pruned_branch)
    .store_uint(1, 8)
    .store_uint(1, 8)
    .store_bytes(bytes(32))
    .store_uint(0, 16)
    .end_cell()
)
for label, cell in [("library", library), ("pruned", pruned)]:
    for slot in (6, 8, 9):
        row = good.copy()
        row[0] = label + "-" + str(slot)
        row[5] = "M"
        row[slot] = cell.to_boc().hex()
        rows.append("\t".join(row))
a.scenarios.write_text("\n".join(rows) + "\n")
