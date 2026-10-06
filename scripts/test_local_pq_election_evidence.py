"""Actual TL-B wire positives and controlled refusal-correlation mutations."""
import pytest
from pytosiq_core import Builder

from local_pq_election_evidence import election_result
from local_pq_test_wire import address, message, transaction

QUERY = (1 << 63) + 1
OWNER, POOL, CONTROLLER = address(1), address(2), address(3)


def fixture(*, bounced=True, query=QUERY, commitment=42, sender=CONTROLLER, dest=POOL,
            short=False, code=180, applied=True):
    order_body = Builder().store_uint(0x4E73744B,32).store_uint(QUERY,64).end_cell()
    relay_body = (Builder().store_uint(0x50517232,32).store_uint(QUERY,64)
                  .store_uint(42,160).end_cell())
    relay = message(POOL, CONTROLLER, relay_body, lt=100)
    order = transaction(POOL, 10, message(OWNER, POOL, order_body), [relay])
    bounce_body = (Builder().store_uint(0xFFFFFFFF,32).store_uint(0x50517232,32)
                   .store_uint(query,64))
    if not short:
        bounce_body.store_uint(commitment,160)
    bounced_tx = transaction(POOL, 30, message(sender,dest,bounce_body.end_cell(),
                                               amount=75,bounced=bounced), success=applied)
    controller_tx = transaction(CONTROLLER, 20, relay, success=False, exit_code=code)
    kwargs = dict(owner=OWNER,pool=POOL,controller=CONTROLLER,query=QUERY,
                  body_hash=order_body.hash.hex())
    return [bounced_tx, order], [controller_tx], kwargs


def test_matching_native_bounce_reads_controller_exit_not_bounce():
    pools, controllers, args = fixture(code=102)
    answer = election_result(pools, controllers, **args)
    assert answer["kind"] == "controller_bounced" and answer["exit_code"] == 102
    assert answer["returned_nano"] == 75 and answer["pool_bounce_applied"]


def test_bounce_without_controller_transaction_reports_unknown():
    pools, _, args = fixture()
    assert election_result(pools, [], **args)["exit_code"] is None


@pytest.mark.parametrize("mutation", [dict(bounced=False),dict(query=QUERY+1),dict(commitment=43),
                                      dict(sender=address(9)),dict(dest=address(9)),dict(short=True)])
def test_unrelated_or_truncated_bounce_is_not_a_refusal(mutation):
    pools, controllers, args = fixture(**mutation)
    assert election_result(pools, controllers, **args) is None


def test_pool_bounce_handler_failure_is_not_hidden():
    pools, controllers, args = fixture(applied=False)
    assert election_result(pools, controllers, **args)["pool_bounce_applied"] is False


def test_wrong_order_body_is_not_correlated():
    pools, controllers, args = fixture()
    args["body_hash"] = "ff"*32
    assert election_result(pools, controllers, **args) is None


def test_a_failed_pool_order_is_reported_directly():
    pools, controllers, args = fixture()
    from local_pq_transactions import decoded
    original = decoded(pools[-1])
    pools[-1] = transaction(POOL,10,original.in_msg,success=False,exit_code=123)
    assert election_result(pools,controllers,**args) == dict(kind="pool_refused",exit_code=123,action_code=None)


def receipt(success=True, reason=0):
    # The actual controller result wire, including full request hash and payer ref.
    return (Builder().store_uint(0x50516232,32).store_uint(QUERY,64).store_uint(123,256)
            .store_coins(2_000_000_000).store_coins(1_000_000_000 if success else 0)
            .store_uint(reason,32).store_uint(success,1).store_coins(100).store_coins(100)
            .store_ref(Builder().store_address(OWNER).end_cell()).end_cell())


@pytest.mark.parametrize("success,reason,kind",[(True,0,"accepted"),(False,0,"elector_refused"),
                                                (False,42,"elector_refused")])
def test_successful_pool_receipts_use_real_relay_wire(success,reason,kind):
    pools, controllers, args = fixture()
    pools[0] = transaction(POOL,30,message(CONTROLLER,POOL,receipt(success,reason)))
    assert election_result(pools,controllers,**args)["kind"] == kind


def test_failed_pool_receipt_is_not_acceptance():
    pools,controllers,args=fixture()
    pools[0]=transaction(POOL,30,message(CONTROLLER,POOL,receipt()),success=False,exit_code=180)
    assert election_result(pools,controllers,**args) is None
