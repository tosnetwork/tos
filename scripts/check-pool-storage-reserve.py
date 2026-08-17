#!/usr/bin/env python3
"""Does a nominator pool's reserved balance actually cover its masterchain rent?

pool.fc keeps `MIN_TOS_FOR_STORAGE` behind at all times: it will not stake or
pay out anything that would take the balance below that line. The number is a
constant chosen upstream, and whether it is enough depends entirely on the
masterchain storage prices of the network the contract runs on, which is a
per-network configuration value (ConfigParam 18).

Rent is charged as

    nanotomi = (cells * mc_cell_price + bits * mc_bit_price) * seconds / 2^16

(transaction.cpp, add_partial_storage_payment and compute_storage_fees) and it
comes out of the account balance -- which for a pool is the nominators'
principal. Nothing in the contract accounts for that drain: the pool's
bookkeeping keeps saying each nominator is owed what they deposited while the
balance quietly shrinks underneath it. The first place this becomes visible is
withdrawal, where a request that no longer fits under the reserve is skipped
without an error and simply stays queued.

So this reports how long the reserve survives, and how long the whole pool
survives, at a given size.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

NANOTOS_PER_TOS = 1_000_000_000
SECONDS_PER_YEAR = 31_557_600
# pool.fc constants.
MIN_TOS_FOR_STORAGE = 10 * NANOTOS_PER_TOS
# One validation round plus its holding period, at the shipped ConfigParam 15.
ROUND_SECONDS = 65536 + 32768


def measure_cells(path: Path) -> tuple[int, int]:
    """Unique cells and total bits in a BOC, which is what rent is charged on."""
    import importlib

    boc = importlib.import_module("pytosiq_core.boc.deserialize")
    root = boc.Boc(path.read_bytes()).deserialize()[0]
    seen: dict[bytes, object] = {}

    def walk(cell) -> None:
        if cell.hash in seen:
            return
        seen[cell.hash] = cell
        for ref in cell.refs:
            walk(ref)

    walk(root)
    return len(seen), sum(len(cell.bits) for cell in seen.values())


def dictionary_cost(entries: int, value_bits: int, key_bits: int = 256) -> tuple[int, int]:
    """Cells and bits of a hashmap holding that many entries.

    A hashmap over n keys is a Patricia trie: n leaves and n-1 forks. Labels
    add up to the key width across any root-to-leaf path, so the whole trie
    carries roughly one key's worth of label bits per entry plus the values.
    Addresses are effectively random, so assuming no shared prefixes is the
    realistic case rather than a pessimistic one.
    """
    if entries == 0:
        return 0, 0
    cells = 2 * entries - 1
    bits = entries * (key_bits + value_bits) + (entries - 1) * 2
    return cells, bits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--code",
        type=Path,
        default=REPO / "crypto/smartcont/artifacts/nominator-pool-v1.boc",
        help="pool code BOC (build it with scripts/build-nominator-pool-v1.sh)",
    )
    parser.add_argument("--nominators", type=int, default=40, help="nominators held by the pool")
    parser.add_argument("--mc-cell-price", type=int, default=500_000, help="ConfigParam 18 mc_cell_price_ps")
    parser.add_argument("--mc-bit-price", type=int, default=1_000, help="ConfigParam 18 mc_bit_price_ps")
    args = parser.parse_args()

    if not args.code.exists():
        print(f"pool code not found: {args.code}", file=sys.stderr)
        print("build it first: scripts/build-nominator-pool-v1.sh", file=sys.stderr)
        return 2

    code_cells, code_bits = measure_cells(args.code)

    # save_data's scalars, plus the config sub-cell it always carries.
    data_cells, data_bits = 2, 8 + 16 + 128 + 128 + 32 + 256 + 8 + 32 + 32 + 3 + (256 + 16 + 16 + 128 + 128)
    # Each nominator entry stores two Coins amounts.
    nominator_cells, nominator_bits = dictionary_cost(args.nominators, 128 + 128)
    data_cells += nominator_cells
    data_bits += nominator_bits

    cells = code_cells + data_cells
    bits = code_bits + data_bits

    per_second = (cells * args.mc_cell_price + bits * args.mc_bit_price) / (1 << 16)
    per_year = per_second * SECONDS_PER_YEAR
    per_round = per_second * ROUND_SECONDS

    print(f"pool code            : {code_cells} cells, {code_bits} bits")
    print(f"pool data ({args.nominators:>3} nominators): {data_cells} cells, {data_bits} bits")
    print(f"account total        : {cells} cells, {bits} bits")
    print()
    print(f"masterchain rent     : {per_second:,.0f} nanotomi/s")
    print(f"  per staking round  : {per_round / NANOTOS_PER_TOS:,.3f} TOS")
    print(f"  per year           : {per_year / NANOTOS_PER_TOS:,.2f} TOS")
    print()

    reserve_days = MIN_TOS_FOR_STORAGE / per_second / 86400
    print(f"MIN_TOS_FOR_STORAGE  : {MIN_TOS_FOR_STORAGE / NANOTOS_PER_TOS:g} TOS")
    print(f"  covers             : {reserve_days:,.1f} days of rent on its own")
    print(f"  which is           : {MIN_TOS_FOR_STORAGE / per_round:,.1f} staking rounds")

    if reserve_days < 365:
        print()
        print(
            "NOTE: the reserve alone does not cover a year. Rent is charged against"
        )
        print(
            "      the pool's balance, which is nominator principal, and the contract"
        )
        print(
            "      never books that drain against anyone. A pool operating for longer"
        )
        print(
            "      than this needs the validator to top it up, or it eventually owes"
        )
        print(
            "      its nominators more than it holds and withdrawals start being"
        )
        print("      skipped silently rather than failing.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
