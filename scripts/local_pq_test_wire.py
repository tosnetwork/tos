"""Small real TL-B transaction fixtures for local-driver regression tests only."""
from types import SimpleNamespace as Obj

from tosapi import toslib_api

from pytosiq_core import Address, Builder, Cell, CurrencyCollection, InternalMsgInfo, MessageAny
from pytosiq_core.boc import HashMap


def address(number):
    return Address((-1, number.to_bytes(32, "big")))


def message(source, destination, body=None, *, amount=100, lt=1, bounced=False, init=None):
    return MessageAny(InternalMsgInfo(True, not bounced, bounced, source, destination,
                                     CurrencyCollection(tomis=amount), 0, 0, lt, 1),
                      init, body if body is not None else Cell.empty())


def transaction(account, lt, inbound, outputs=(), *, success=True, exit_code=0,
                previous=None, action_code=None):
    """Encode a genuine transaction BOC; the production decoder consumes it."""
    previous = previous or Obj(lt=0, hash=bytes(32))
    vm = (Builder().store_var_uint(1, 3).store_var_uint(200000, 3).store_bit(0)
          .store_int(0, 8).store_int(exit_code, 32).store_bit(0)
          .store_uint(1, 32).store_bytes(bytes(64)).end_cell())
    descr = (Builder().store_uint(0, 4).store_bit(0).store_bit(0).store_bit(0)
             .store_bit(1).store_bit(success).store_bit(0).store_bit(0)
             .store_coins(0).store_ref(vm))
    if action_code is None:
        descr.store_bit(0)
    else:
        action = (Builder().store_bit(action_code == 0).store_bit(1).store_bit(0)
                  .store_bit(0).store_bit(0).store_bit(0).store_int(action_code, 32)
                  .store_bit(0).store_uint(0, 16 * 4).store_bytes(bytes(32))
                  .store_var_uint(0, 3).store_var_uint(0, 3).end_cell())
        descr.store_bit(1).store_ref(action)
    descr.store_bit(not success or (action_code is not None and action_code != 0)).store_bit(0).store_bit(0)
    messages = (Builder().store_maybe_ref(inbound.serialize() if inbound else None)
                .store_dict(HashMap(15, map_=dict(enumerate(outputs)),
                                   value_serializer=lambda src, dst: dst.store_ref(src.serialize())).serialize())
                .end_cell())
    cell = (Builder().store_uint(7, 4).store_bytes(account.hash_part).store_uint(lt, 64)
            .store_bytes(previous.hash).store_uint(previous.lt, 64).store_uint(1, 32)
            .store_uint(len(outputs), 15).store_uint(2, 2).store_uint(2, 2)
            .store_ref(messages).store_cell(CurrencyCollection(tomis=0).serialize())
            .store_ref(Builder().store_uint(0x72, 8).store_bytes(bytes(64)).end_cell())
            .store_ref(descr.end_cell()).end_cell())
    return Obj(data=cell.to_boc(), transaction_id=Obj(lt=lt, hash=cell.hash),
               in_msg=Obj(source=Obj(account_address=inbound.info.src.to_str(is_user_friendly=False)),
                          msg_data=toslib_api.Msg_dataRaw(body=inbound.body.to_boc(), init_state=b"")) if inbound and isinstance(inbound.info, InternalMsgInfo) else None)
