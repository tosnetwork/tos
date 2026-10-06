"""Shared authorization logic with actual state/config BOCs and a fake chain.

These tests are not controller VM execution. Signatures are deliberately replaced
by a payload carrier so refusal/readback paths can be exercised deterministically.
"""
import asyncio
import base64
from types import SimpleNamespace as Obj

import pytest
from pytosiq_core import Builder, Cell, StateInit

import local_pq_funding as funding
from local_pq_funding_policy import DAY, NANO
from local_pq_test_wire import address

NOW = 1791250000
ROOT = Builder().store_uint(123,32).end_cell()
CODE = Builder().store_uint(456,32).end_cell()
PAYER = address(1)


def data(*,nonce=0,epoch=0,operations=None,root=ROOT,key=bytes(32),pending=False):
    value=(Builder().store_uint(epoch,64).store_uint(nonce,64).store_uint(1,16)
           .store_bytes(key).store_ref(root))
    if operations is not None or pending:
        relay=(Builder().store_uint(1<<63,64).store_maybe_ref(Cell.empty() if pending else None).end_cell())
        value.store_maybe_ref(relay)
        if operations is not None:
            op=Builder()
            for name in ('funds','allowance','limit','floor'): op.store_coins(operations[name])
            op.store_uint(operations['expires'],32).store_address(operations['payer'])
            value.store_maybe_ref(op.end_cell())
        else: value.store_maybe_ref(None)
        value.store_maybe_ref(None)
    return value.end_cell()


INIT=StateInit(code=CODE,data=data())
CONTROLLER=address(0)
CONTROLLER.hash_part=INIT.serialize().hash
CANDIDATE=dict(controller=CONTROLLER.to_str(is_user_friendly=False),
               state_init_b64=base64.b64encode(INIT.serialize().to_boc()).decode())


def prices(*,flat=True,gas_price=10000*65536):
    gas=Builder().store_uint(0xde,8)
    for number in (gas_price,1000000,1000000,10000,10000000,100000000,1000000000):
        gas.store_uint(number,64)
    if flat:
        gas=(Builder().store_uint(0xd1,8).store_uint(100,64).store_uint(1000000,64)
             .store_cell(gas.end_cell()))
    forward=(Builder().store_uint(0xea,8).store_uint(10000000,64)
             .store_uint(655360000,64).store_uint(65536000000,64)
             .store_uint(98304,32).store_uint(21845,16).store_uint(21845,16).end_cell())
    return gas.end_cell(),forward


def operations(**changes):
    value=dict(funds=50000*NANO,allowance=50000*NANO,limit=20*NANO,
               floor=10*NANO,expires=NOW+30*DAY,payer=PAYER)
    value.update(changes)
    return value


class Chain:
    def __init__(self,op=None):
        self.op=op
        self.nonce=7
        self.epoch=2
        self.balance=(op['funds'] if op else 0)+40*NANO
        self.lt=100
        self.bad_readback=False
        self.refuse=False
        self.calls=[]
        self.wallet=Obj(address=PAYER)

    async def raw_get_account_state(self,addr):
        assert addr == CONTROLLER
        return Obj(code=CODE.to_boc(),data=data(nonce=self.nonce,epoch=self.epoch,operations=self.op).to_boc(),
                   balance=self.balance,sync_utime=NOW,
                   last_transaction_id=Obj(lt=self.lt,hash=bytes(32)))

    async def get_config_param(self,number):
        return prices()[{20:0,24:1}[number]]

    async def transfer(self,label,dest,amount,body=None,**kwargs):
        self.calls.append((label,amount,body,kwargs))
        self.lt+=1
        if body is not None and not self.refuse:
            cs=body.begin_parse()
            assert cs.load_uint(8)==4
            payload=cs.load_ref().begin_parse()
            payer=payload.load_address()
            deposit=payload.load_coins()
            self.op=dict(funds=(self.op['funds'] if self.op else 0)+deposit,
                         allowance=payload.load_coins(),limit=payload.load_coins(),
                         floor=payload.load_coins(),expires=payload.load_uint(32),payer=payer)
            if self.bad_readback: self.op['funds']+=1
            self.balance+=deposit
            self.nonce+=1
        elif body is None:
            self.balance+=amount
        return dict(label=label,ok=not self.refuse,transaction=dict(lt=self.lt,hash='00'*32),
                    exit_code=180 if self.refuse else 0,action_code=None)


def signer(seed,global_id,controller,epoch,nonce,payload,valid_until,tool):
    assert global_id==3 and controller==CONTROLLER
    assert epoch==2 and nonce==7 and valid_until==NOW+600
    assert seed.name=='root-1.seed'
    return Builder().store_uint(4,8).store_ref(payload).end_cell()


def run(chain,tmp_path,monkeypatch,**kwargs):
    monkeypatch.setattr(funding.time,'time',lambda:NOW)
    return asyncio.run(funding.ensure_operations(chain,chain,CANDIDATE,1,tmp_path,3,signer=signer,**kwargs))


def test_fee_budget_matches_sr_helpers():
    gas,forward=prices()
    value=funding.fee_budget(gas,forward)
    # Independent integer expansion of the FunC formulas at these exact prices.
    ff=10000000 + 4096*10000 + 8*1000000
    control=1000000+(50000-100)*10000+ff
    callback=1000000+(200000-100)*10000+ff
    assert value['grant']==4*control+callback
    assert value['processing']==1000000+(200000-100)*10000+control


def test_nonflat_gas_configuration_is_supported():
    value=funding.fee_budget(*prices(flat=False))
    ff=10000000+4096*10000+8*1000000
    assert value['grant']==4*(50000*10000+ff)+(200000*10000+ff)


def test_existing_manual_surplus_is_not_recharged(tmp_path,monkeypatch):
    chain=Chain(operations())
    assert run(chain,tmp_path,monkeypatch)['ready']
    assert chain.calls==[]


def test_initial_authorization_uses_current_nonce_and_thirty_day_grants(tmp_path,monkeypatch):
    chain=Chain()
    result=run(chain,tmp_path,monkeypatch)
    grant=funding.fee_budget(*prices())['grant']
    assert chain.op['funds']==chain.op['allowance']==grant*4320
    assert chain.op['expires']==NOW+30*DAY and chain.nonce==8
    assert len(chain.calls)==1 and chain.calls[0][3]['bounce'] is True
    assert result['ready']


def test_allowance_expiry_renewal_uses_zero_deposit(tmp_path,monkeypatch):
    chain=Chain(operations(expires=NOW+DAY))
    before=chain.op['funds']
    run(chain,tmp_path,monkeypatch)
    assert chain.op['funds']==before
    assert chain.calls[0][1]==funding.fee_budget(*prices())['processing']+NANO


def test_deficit_only_not_another_full_deposit(tmp_path,monkeypatch):
    chain=Chain(operations(funds=70*NANO,allowance=0))
    before=chain.op['funds']
    run(chain,tmp_path,monkeypatch,target=80*NANO,days=1)
    assert chain.op['funds']==80*NANO
    assert chain.calls[0][1] == 80*NANO-before+funding.fee_budget(*prices())['processing']+NANO


def test_capital_is_an_independent_deficit(tmp_path,monkeypatch):
    chain=Chain(operations())
    chain.balance=chain.op['funds']+NANO
    run(chain,tmp_path,monkeypatch)
    assert len(chain.calls)==1 and chain.calls[0][1]==29*NANO and chain.calls[0][2] is None


def test_read_only_check_neither_signs_nor_writes(tmp_path,monkeypatch):
    chain=Chain(operations(expires=NOW+DAY))
    result=run(chain,tmp_path,monkeypatch,check=True)
    assert result['ready'] and result['renewal_due']
    assert chain.calls==[] and not list(tmp_path.iterdir())


def test_target_transaction_failure_cannot_pass_readback(tmp_path,monkeypatch):
    chain=Chain();chain.refuse=True
    with pytest.raises(ValueError,match='refused'):
        run(chain,tmp_path,monkeypatch)


def test_additive_readback_is_exact_not_a_lower_bound(tmp_path,monkeypatch):
    chain=Chain(operations(funds=70*NANO,allowance=0));chain.bad_readback=True
    with pytest.raises(ValueError,match='exact transition'):
        run(chain,tmp_path,monkeypatch,target=80*NANO)


@pytest.mark.parametrize('change',['root','key','code','birth'])
def test_controller_identity_drift_is_refused(change):
    account=asyncio.run(Chain().raw_get_account_state(CONTROLLER))
    addr=CONTROLLER
    if change=='root': account.data=data(root=Cell.empty()).to_boc()
    if change=='key': account.data=data(key=b'\x01'*32).to_boc()
    if change=='code': account.code=Cell.empty().to_boc()
    if change=='birth': addr=address(99)
    with pytest.raises(ValueError): funding.read_controller(account,addr,INIT)


def test_confirmed_readback_waits_for_the_destination_view(monkeypatch):
    states = [Obj(last_transaction_id=Obj(lt=99)), Obj(last_transaction_id=Obj(lt=100))]
    class Client:
        async def raw_get_account_state(self, address):
            return states.pop(0)
    async def sleep(_):
        return None
    monkeypatch.setattr(funding.asyncio, "sleep", sleep)
    account = asyncio.run(funding.confirmed_state(Client(), CONTROLLER, dict(transaction=dict(lt=100))))
    assert account.last_transaction_id.lt == 100 and not states
