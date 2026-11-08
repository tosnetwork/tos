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
