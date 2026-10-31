"""Use the native client API's account-absence contract for lifecycle evidence."""

from tosapi import toslib_api
from tostester.wallet_index_verify_fixtures import account_is_absent


def test_native_account_absence_uses_the_negative_balance_sentinel():
    # RawAccountState leaves balance=-1 when the authenticated account root is
    # absent. An existing zero-balance uninitialized account is different.
    assert account_is_absent(toslib_api.Raw_fullAccountState(balance=-1))
    assert not account_is_absent(toslib_api.Raw_fullAccountState(balance=0))


def test_account_absence_never_accepts_active_frozen_or_funded_state():
    for state in (
        toslib_api.Raw_fullAccountState(balance=1),
        toslib_api.Raw_fullAccountState(balance=-1, code=b"code"),
        toslib_api.Raw_fullAccountState(balance=-1, data=b"data"),
        toslib_api.Raw_fullAccountState(balance=-1, frozen_hash=bytes([1]) * 32),
        toslib_api.Raw_fullAccountState(
            balance=-1, extra_currencies=[toslib_api.ExtraCurrency(id=1, amount=1)]
        ),
        toslib_api.Raw_fullAccountState(balance=-2),
    ):
        assert not account_is_absent(state)
