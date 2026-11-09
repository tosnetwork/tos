import pytest
from tostester.zerostate import NetworkConfig, _block_limits_fift

# The development profile as the template carried it inline before the profile was split out.
LEGACY_DEV = """// DEV-SPECIFIC: higher gas limits for tests (production: mc=2.5M, base=20M)
128 *Ki 512 *Ki {mul} * 1 *Mi {mul} * triple  // bytes: underload soft hard
2000000 100000000 100000000 triple  // gas: underload soft hard
1000 500000 1000000 triple        // lt: underload soft hard
triple dup
untriple make-block-limits 22 config!
untriple make-block-limits 23 config!"""


@pytest.mark.parametrize("mul", [1, 4])
def test_dev_profile_is_unchanged(mul):
    config = NetworkConfig(auth_network_tag=bytes(32), block_limit_mul=mul)
    assert _block_limits_fift(config) == LEGACY_DEV.format(mul=mul)


def test_production_profile_matches_the_canonical_genesis():
    text = _block_limits_fift(
        NetworkConfig(auth_network_tag=bytes(32), production_block_limits=True)
    )
    mc, base = text.split("make-block-limits 22 config!")
    assert "128 *Ki 512 *Ki 1 *Mi triple" in mc and "500000 1000000 2500000 triple" in mc
    assert "256 *Ki 1 *Mi 2 *Mi triple" in base and "2000000 10000000 20000000 triple" in base
    assert mc.count("1000 5000 10000 triple") == 1 and base.count("1000 5000 10000 triple") == 1
    assert base.strip().endswith("triple untriple make-block-limits 23 config!")
    assert mc.strip().endswith("triple untriple")


def test_production_profile_refuses_a_multiplier():
    with pytest.raises(ValueError):
        _ = _block_limits_fift(
            NetworkConfig(
                auth_network_tag=bytes(32), production_block_limits=True, block_limit_mul=2
            )
        )
    with pytest.raises(ValueError):
        _ = _block_limits_fift(NetworkConfig(auth_network_tag=bytes(32), block_limit_mul=0))


def _triples(fift: str) -> list[list[int]]:
    """Numeric (underload, soft, hard) triples in Fift text, with *Ki / *Mi expanded."""
    import re

    scale = {"*Ki": 1 << 10, "*Mi": 1 << 20}
    out = []
    for line in fift.splitlines():
        code = line.split("//", 1)[0]
        if not code.strip().endswith("triple") or "untriple" in code:
            continue
        tokens = code.split()[:-1]
        values: list[int] = []
        for token in tokens:
            if token in scale:
                values[-1] *= scale[token]
            elif re.fullmatch(r"\d+", token):
                values.append(int(token))
        if len(values) == 3:
            out.append(values)
    return out


def test_production_profile_equals_gen_zerostate():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    canonical = (root / "crypto/smartcont/gen-zerostate.fif").read_text()
    start = canonical.index("// masterchain block limits")
    end = canonical.index("config.block_limits!", start)
    expected = _triples(canonical[start:end])
    profile = _block_limits_fift(
        NetworkConfig(auth_network_tag=bytes(32), production_block_limits=True)
    )
    assert len(expected) == 6
    assert _triples(profile) == expected


def test_production_basechain_bytes_override_only_the_basechain_byte_triple():
    canonical = _block_limits_fift(
        NetworkConfig(auth_network_tag=bytes(32), production_block_limits=True)
    )
    soft, hard = 2560 << 10, 3 << 20
    profile = _block_limits_fift(
        NetworkConfig(
            auth_network_tag=bytes(32),
            production_block_limits=True,
            production_basechain_bytes=(256 << 10, soft, hard),
        )
    )
    old, new = _triples(canonical), _triples(profile)
    assert len(old) == len(new) == 6
    # Masterchain bytes, gas, lt (0-2) and basechain gas, lt (4-5) stay canonical.
    assert [new[i] for i in (0, 1, 2, 4, 5)] == [old[i] for i in (0, 1, 2, 4, 5)]
    assert new[3] == [256 << 10, soft, hard]


@pytest.mark.parametrize(
    "triple",
    [(0, 1 << 20, 2 << 20), (2 << 20, 1 << 20, 2 << 20), (1, 2, 1), (1, 2, (4 << 20) + 1)],
)
def test_production_basechain_bytes_refuse_an_unordered_or_oversized_triple(triple):
    with pytest.raises(ValueError):
        _ = _block_limits_fift(
            NetworkConfig(
                auth_network_tag=bytes(32),
                production_block_limits=True,
                production_basechain_bytes=triple,
            )
        )
