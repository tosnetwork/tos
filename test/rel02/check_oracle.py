"""Independent on-chain output extraction from original BOCs, never emulator output."""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tostester/src"))
from pytosiq_core.boc import Cell
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.block import Block


def transaction(tx):
    d = tx.description
    c = d.compute_ph
    a = d.action
    assert d.type_ in ("ordinary", "tick_tock")
    return dict(
        kind="transaction",
        account=tx.account_addr.hex().upper(),
        lt=str(tx.lt),
        result_hash=tx.cell.hash.hex().upper(),
        account_hash=tx.state_update.new_hash.hex().upper(),
        description_hash=tx.cell.refs[-1].hash.hex().upper(),
        description="ordinary" if d.type_ == "ordinary" else ("tock" if d.is_tock else "tick"),
        description_tag=0 if d.type_ == "ordinary" else 2,
        aborted=d.aborted,
        gas_used=str(getattr(c, "gas_used", 0)),
        exit_code=getattr(c, "exit_code", None),
        action_result_code=None if a is None else a.result_code,
        out_message_hashes=[m.cell.hash.hex().upper() for m in tx.out_msgs],
    )


def boc_mode(raw):
    h = Boc.deserialize_boc_header(raw)
    mode = (
        (1 if h["has_idx"] else 0)
        + (2 if h["hash_crc32"] else 0)
        + (16 if h["has_cache_bits"] else 0)
    )
    data = h["cells_data"]
    offset = 0
    for index in range(h["cells_num"]):
        d1, d2 = data[offset : offset + 2]
        has_hashes = bool(d1 & 16)
        if has_hashes:
            mode |= 4 if index in h["root_list"] else 8
        offset += (
            2
            + ((d1 >> 5).bit_count() + 1) * 34 * has_hashes
            + (d2 + 1) // 2
            + (d1 & 7) * h["size_bytes"]
        )
    assert offset == len(data)
    return mode


def block(path):
    raw = path.read_bytes()
    root = Cell.one_from_boc(raw)
    b = Block.deserialize(root.begin_parse())
    i = b.info
    # Decode the original container flags and stored-hash descriptors independently.
    result = [
        dict(
            kind="block",
            seqno=i.seqno,
            workchain=i.shard.workchain_id,
            shard=str(i.shard.shard_prefix + (1 << (63 - i.shard.shard_pfx_bits))),
            root_hash=root.hash.hex().upper(),
            file_hash=hashlib.sha256(raw).hexdigest().upper(),
            old_state_hash=b.state_update.old_hash.hex().upper(),
            new_state_hash=b.state_update.new_hash.hex().upper(),
            boc_mode=boc_mode(raw),
        )
    ]
    for address, ab in sorted(b.extra.account_blocks[0].items()):
        for lt, tx in sorted(ab.transactions[0].items()):
            result.append(transaction(tx))
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).parent / "corpus/manifest.json"
    )
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    expected = [
        record for name in manifest["blocks"] for record in block(args.manifest.parent / name)
    ]
    roots = [
        cell
        for name in manifest["supplements"]
        for cell in Cell.from_boc((args.manifest.parent / name).read_bytes())
    ]
    if len(roots) != len(manifest["supplement_roots"]):
        raise SystemExit("original cell-bank root count differs")
    for index, (cell, entry) in enumerate(zip(roots, manifest["supplement_roots"])):
        if (
            entry["index"] != index
            or cell.hash.hex().upper() != entry["cell_hash"]
            or cell.get_hash(0).hex().upper() != entry["virtual_hash"]
        ):
            raise SystemExit(f"original cell-bank root {index} differs")
    if expected != manifest["expected"]:
        raise SystemExit("original BOC decode differs from the recorded oracle")
    print(f"PASS: {len(manifest['blocks'])} blocks, {len(expected)} original records")
