"""Independent genesis vectors; synthetic code/public keys are encoding fixtures only."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
from cells import Cell  # noqa: E402
from native import state_init  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import chain  # noqa: E402
from test_state import fee, state  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    rows = []
    key = (
        (1).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (3).to_bytes(4, "big")
        + bytes([0x33]) * 16
        + bytes([0x44]) * 32
    )
    for policy, wallet_id, tree_id in [(1, 42, 456), (2, 42, 456), (1, 43, 456), (1, 42, 457)]:
        md = (
            Cell()
            .uint(1, 8)
            .sint(42, 32)
            .uint(123, 256)
            .uint(1, 8)
            .ref(chain(bytes([0x11]) * 1312))
            .raw(bytes([0x22]) * 32)
            .uint(policy, 8)
        )
        mi = state_init(Cell().uint(2, 8), md)
        metadata = fee(key=chain(key), tree_id=tree_id, epoch0=1_779_992_790)
        wd = state(mi, metadata=metadata, mode=2, retired=0, seqno=0, epoch=1, primary=0, rescue=0)
        wd.bits = wd.bits[:33] + format(wallet_id, "032b") + wd.bits[65:]
        wi = state_init(Cell().uint(1, 8), wd)
        vd = vault_data(
            metadata=metadata,
            wallet=int.from_bytes(wi.hash, "big"),
            module=int.from_bytes(mi.hash, "big"),
        )
        vi = state_init(Cell().uint(3, 8), vd)
        rows.append(
            dict(
                policy=policy,
                wallet_id=wallet_id,
                tree_id=tree_id,
                module_data=md.hash.hex(),
                module_init=mi.hash.hex(),
                metadata=metadata.hash.hex(),
                wallet_data=wd.hash.hex(),
                wallet_init=wi.hash.hex(),
                vault_data=vd.hash.hex(),
                vault_init=vi.hash.hex(),
                config_hash=f"{vd.slice().uint(296) & ((1 << 256) - 1):064x}",
            )
        )
    args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
