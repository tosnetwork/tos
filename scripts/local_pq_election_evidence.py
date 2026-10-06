"""Correlate the real pool/controller transaction wire, not a log substring."""

from types import SimpleNamespace

from pytosiq_core import InternalMsgInfo
from tosapi import toslib_api
from tostester.pq_election_fixture import elector_reply

from local_pq_transactions import decoded, fingerprint, successful

RELAY = 0x50517232
RESULT = 0x50516232
NEW_STAKE = 0x4E73744B


def internal(message, sender, destination, *, bounced=False):
    return (message is not None and isinstance(message.info, InternalMsgInfo)
            and message.info.src == sender and message.info.dest == destination
            and message.info.bounced is bounced)


def failure(transaction, kind):
    compute = getattr(transaction.description, "compute_ph", None)
    action = getattr(transaction.description, "action", None)
    return dict(kind=kind, exit_code=getattr(compute, "exit_code", None),
                action_code=getattr(action, "result_code", None))


def election_result(pool_history, controller_history, *, owner, pool, controller, query, body_hash):
    """Only a successful pool receipt is acceptance. Native bounces bind 256 bits.

    Histories must already be bounded to the saved pre-order transaction cursors.
    An exit code is read from the correlated controller transaction, never from
    the bounce body. A bounce without that transaction has an unknown exit code.
    """
    orders = []
    for item in pool_history:
        tx = decoded(item)
        message = tx.in_msg
        if not internal(message, owner, pool) or message.body.hash.hex() != body_hash:
            continue
        cs = message.body.begin_parse()
        if cs.remaining_bits >= 96 and cs.load_uint(32) == NEW_STAKE and cs.load_uint(64) == query:
            orders.append(tx)
    if not orders:
        return None
    if len(orders) != 1:
        raise ValueError("more than one pool order for the saved election intent")
    order = orders[0]
    if not successful(order):
        return failure(order, "pool_refused")
    relays = []
    for message in order.out_msgs:
        if internal(message, pool, controller):
            cs = message.body.begin_parse()
            if cs.remaining_bits >= 256 and cs.load_uint(32) == RELAY and cs.load_uint(64) == query:
                relays.append(message)
    if len(relays) != 1:
        raise ValueError("successful stake order did not emit one exact controller relay")
    relay = relays[0]
    prefix = relay.body.begin_parse().load_uint(256)
    for item in pool_history:
        tx = decoded(item)
        message = tx.in_msg
        if internal(message, controller, pool) and successful(tx):
            cs = message.body.begin_parse()
            if cs.remaining_bits >= 96 and cs.load_uint(32) == RESULT:
                # Decode business fields from the same verified transaction BOC,
                # not independently supplied raw-RPC message metadata.
                envelope = SimpleNamespace(in_msg=SimpleNamespace(
                    source=SimpleNamespace(account_address=message.info.src.to_str(is_user_friendly=False)),
                    msg_data=toslib_api.Msg_dataRaw(body=message.body.to_boc(), init_state=b"")))
                answer = elector_reply([envelope], query, controller=controller)
                if answer:
                    return dict(kind="accepted" if answer[0] == 0xF374484C else "elector_refused",
                                reply=list(answer))
        if not internal(message, controller, pool, bounced=True):
            continue
        cs = message.body.begin_parse()
        if (cs.remaining_bits < 288 or cs.load_uint(32) != 0xFFFFFFFF
                or cs.load_uint(256) != prefix):
            continue
        result = dict(kind="controller_bounced", exit_code=None, action_code=None,
                      returned_nano=message.info.value.tomis,
                      pool_bounce_applied=successful(tx))
        for controller_item in controller_history:
            controller_tx = decoded(controller_item)
            if (controller_tx.in_msg is not None
                    and fingerprint(controller_tx.in_msg) == fingerprint(relay)):
                result.update(failure(controller_tx, "controller_bounced"))
                break
        return result
    return None
