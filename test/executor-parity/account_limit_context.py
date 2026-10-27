"""Original account-ceiling fixture constants and native configuration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_CELLS = 400
MASTERCHAIN_CEILING = 200
ORDINARY_CEILING = 65536


def size_limits_v2():
    """ConfigParam 43 version 2, which is the first that carries both ceilings."""
    from cells import Cell

    return (
        Cell()
        .uint(0x02, 8)
        .uint(1 << 21, 32)
        .uint(1 << 13, 32)
        .uint(1000, 32)
        .uint(512, 16)
        .uint(65535, 32)
        .uint(512, 16)
        .uint(ORDINARY_CEILING, 32)
        .uint(MASTERCHAIN_CEILING, 32)
        .uint(256, 32)
        .uint(256, 32)
        .uint(2, 32)
        .uint(8, 8)
        .uint(26, 32)
    )


def configuration(global_version):
    import native
    from cells import Cell, from_boc, make_dict, read_dict

    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    entries = read_dict(fixture.refs[0], 32)
    entries[0] = Cell().ref(Cell().uint(int(fixture.bits, 2), 256))
    old = entries[8].refs[0].slice()
    assert old.uint(8) == 0xC4
    old.uint(32)
    caps = old.uint(64)
    entries[8] = Cell().ref(Cell().uint(0xC4, 8).uint(global_version, 32).uint(caps, 64))
    entries[19] = Cell().ref(Cell().sint(native.GLOBAL_ID, 32))
    entries[43] = Cell().ref(size_limits_v2())
    return make_dict(entries, 32)
