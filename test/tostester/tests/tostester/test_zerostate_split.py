"""The basechain descriptor's split fields: the defaults keep the old genesis, bad values refuse."""

import pytest
from tostester.zerostate import NetworkConfig, _basechain_split_fift


def test_defaults_reproduce_the_fixed_layout_genesis():
    assert _basechain_split_fift(NetworkConfig(split=2)) == {
        "max_split": 2,
        "split_merge_delay": 20,
        "split_merge_interval": 20,
        "min_split_merge_interval": 10,
        "max_split_merge_delay": 1000,
        "persistent_state_split_depth": 0,
    }


def test_the_canonical_genesis_values():
    config = NetworkConfig(
        split=0,
        max_split=2,
        split_merge_timings=(100, 100, 30, 1000),
        persistent_state_split_depth=4,
    )
    assert _basechain_split_fift(config) == {
        "max_split": 2,
        "split_merge_delay": 100,
        "split_merge_interval": 100,
        "min_split_merge_interval": 30,
        "max_split_merge_delay": 1000,
        "persistent_state_split_depth": 4,
    }


@pytest.mark.parametrize(
    "over,match",
    [
        ({"split": 2, "max_split": 1}, "below split"),
        ({"max_split": 61}, "max_split"),
        ({"split": 1, "monitor_min_split": 2}, "monitor_min_split"),
        ({"split_merge_timings": (100, 100, 30)}, "split_merge_timings"),
        ({"split_merge_timings": (100, 0, 30, 1000)}, "positive"),
        ({"split_merge_timings": (100, 100, 30, 1 << 32)}, r"split_merge_timings\[3\]"),
        ({"persistent_state_split_depth": 64}, "persistent_state_split_depth"),
        ({"max_split": True}, "max_split"),
    ],
)
def test_invalid_split_fields_are_refused(over, match):
    with pytest.raises(ValueError, match=match):
        _basechain_split_fift(NetworkConfig(**over))
