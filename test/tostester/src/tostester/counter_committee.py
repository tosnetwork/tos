"""Test-network config-owner update; not a validator election workflow."""
import asyncio
import subprocess

from pytosiq_core import Address, Builder, Cell, HashMap

CONFIG_ADDRESS = Address((-1, bytes.fromhex("55" * 32)))


def rewrite_committee(cell, replacement=None):
    # replacement is (retired public key, new public key, new ADNL identity).
    if replacement is not None and (len(replacement) != 3 or any(len(value) != 32 for value in replacement)
                                    or replacement[0] == replacement[1]):
        raise ValueError("invalid replacement identity")
    part = cell.begin_parse()
    if part.load_uint(8) != 0x12:
        raise ValueError("requires an extended validator set")
    since, until = part.load_uint(32), part.load_uint(32)
    total, main, weight = part.load_uint(16), part.load_uint(16), part.load_uint(64)
    entries = part.load_dict(16)
    if part.remaining_bits or part.remaining_refs or set(entries) != set(range(total)) or not 1 <= main <= total:
        raise ValueError("invalid validator set shape")
    if replacement is None and weight >= (1 << 64) - 1:
        raise ValueError("validator total weight overflow")
    values = {}
    measured = 0
    replaced = 0
    original_keys = set()
    for index, value in entries.items():
        tag = value.load_uint(8)
        if tag not in (0x53, 0x73) or value.load_uint(32) != 0x8e81278a:
            raise ValueError("invalid validator descriptor")
        key, old_weight = value.load_bytes(32), value.load_uint(64)
        original_keys.add(key)
        adnl = value.load_bytes(32) if tag == 0x73 else None
        if value.remaining_bits or value.remaining_refs or old_weight == 0:
            raise ValueError("invalid validator weight or trailing data")
        measured += old_weight
        new_weight = old_weight + int(index == 0 and replacement is None)
        if replacement is not None and key == replacement[0]:
            key, adnl = replacement[1:]
            tag = 0x73
            replaced += 1
        if new_weight >= 1 << 64:
            raise ValueError("validator weight overflow")
        builder = Builder().store_uint(tag, 8).store_uint(0x8e81278a, 32).store_bytes(key).store_uint(new_weight, 64)
        if adnl is not None:
            builder.store_bytes(adnl)
        values[index] = builder.end_cell()
    if measured != weight:
        raise ValueError("validator total weight mismatch")
    if replacement is not None and (replaced != 1 or replacement[1] in original_keys):
        raise ValueError("replacement must remove one member and introduce a new key")
    dictionary = HashMap(16, value_serializer=lambda value, builder: builder.store_cell(value), map_=values).serialize()
    return (Builder().store_uint(0x12, 8).store_uint(since, 32).store_uint(until, 32)
            .store_uint(total, 16).store_uint(main, 16).store_uint(weight + int(replacement is None), 64)
            .store_dict(dictionary).end_cell())


async def read_committee(client, block):
    state = await client.raw_get_account_state(CONFIG_ADDRESS, block_id=block)
    if state.block_id is None or state.block_id.to_json() != block.to_json():
        raise AssertionError("configuration account response is not block-bound")
    part = Cell.one_from_boc(state.data).begin_parse()
    config = part.load_ref().begin_parse().load_hashmap(32)
    seqno = part.load_uint(32)
    return config[34].load_ref(), seqno


async def submit_committee_update(install, state_dir, client, block, replacement=None):
    original, seqno = await read_committee(client, block)
    updated = rewrite_committee(original, replacement)
    (state_dir / "counter-committee.boc").write_bytes(updated.to_boc())
    command = [str(install.fift_exe)]
    for include in install.fift_include_dirs:
        command += ["-I", str(include)]
    command += ["-s", str(install.source_dir / "crypto/smartcont/update-config.fif"),
                "config-master", str(seqno), "34", "counter-committee.boc", "counter-committee-query"]
    result = await asyncio.to_thread(subprocess.run, command, cwd=state_dir, capture_output=True, text=True)
    (state_dir / "counter-committee-signing.log").write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        raise RuntimeError("configuration signing failed; see counter-committee-signing.log")
    await client.raw_send_message((state_dir / "counter-committee-query.boc").read_bytes())
    return original, updated


async def wait_committee_updated(client, expected):
    while True:
        tip = (await client.get_masterchain_info()).last
        current, _ = await read_committee(client, tip)
        if current.hash == expected.hash:
            header = await client.get_block_header(tip)
            if header.prev_key_block_seqno > 0:
                key = await client.lookup_block(-1, tip.shard, seqno=header.prev_key_block_seqno)
                key_header = await client.get_block_header(key)
                if not key_header.is_key_block:
                    raise AssertionError("committee boundary is not a key block")
                return tip, key
        await asyncio.sleep(0.2)
