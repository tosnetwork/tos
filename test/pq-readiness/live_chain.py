#!/usr/bin/env python3
"""Shared setup for the scripts that drive a running chain.

A chain answers when it has produced a block, not when it is asked, so every
read here is a poll with a deadline rather than a single call. Nothing in this
module decides whether a test passed; it only gets an account funded, deployed
and able to pay, which is the part every live script needs before it can begin.
"""
import json
import time
import urllib.request

import nacl.signing
from pytosiq_core import Cell, ExternalMsgInfo, MessageAny

from contract import WalletV5, WalletV5Blueprint, WalletV5State
from contract.pq_lite_transport import (LiteClientError, LiteClientTransport,
                                        WalletSigner, WalletV5Signer)


def faucet(control: str, address, amount: int) -> None:
    """The zerostate wallet, which is the only pre-funded account on a new chain."""
    body = json.dumps({'address': address.to_str(False), 'amount': amount}).encode()
    request = urllib.request.Request(f'http://{control}/transfer', data=body,
                                     headers={'content-type': 'application/json'})
    with urllib.request.urlopen(request, timeout=180) as response:
        answer = json.loads(response.read())
    if not answer.get('ok', True):
        raise RuntimeError(f'faucet refused to fund {address.to_str(False)}: {answer}')


def wait_for(condition, what: str, attempts: int = 45, seconds: float = 2.0):
    """Poll until the chain shows it, or say which expectation was never met."""
    for _ in range(attempts):
        try:
            value = condition()
            if value:
                return value
        except LiteClientError:
            pass
        time.sleep(seconds)
    raise RuntimeError(f'the chain never reached: {what}')


def funded_payer(transport: LiteClientTransport, control: str, code: Cell,
                 network: int, tos: int = 120):
    """Bring up the wallet that pays for everything the caller deploys.

    A wallet accepts external messages, so it can deploy itself once the faucet
    has funded the address its own StateInit determines. Every contract that
    refuses external messages -- the authentication module refuses every one by
    design -- is then deployed by a funded internal message from this account.
    """
    key = nacl.signing.SigningKey(__import__('os').urandom(32))
    payer = WalletV5Blueprint(code, 0, network, key.verify_key.encode(), key=key)
    faucet(control, payer.address, tos)
    wait_for(lambda: transport.balance(payer.address) > 0, 'the funding wallet is funded')
    _, chain_time = transport.head()
    view = WalletV5(None, payer.address, network, key)
    initial = WalletV5State(True, 0, 0, key.verify_key.encode())
    transport.broadcast_external(MessageAny(
        info=ExternalMsgInfo(None, payer.address, 0), init=payer.state_init,
        body=view.sign(None, initial, chain_time + 600)).serialize())
    # The deploying message is signed, so it consumes seqno 0 and the data cell
    # no longer hashes to the one the address came from. Check what does not
    # change instead: the stored key, the wallet id, and that seqno moved once.
    def deployed():
        live = WalletV5State.parse(Cell.one_from_boc(
            transport.account_data(payer.address).boc()))
        return (live.public_key == initial.public_key
                and live.wallet_id == initial.wallet_id and live.seqno == 1)

    wait_for(deployed, f'{payer.address.to_str(False)} is deployed')
    signer = WalletV5Signer(transport, payer.address, key)
    transport.attach_wallet(WalletSigner(payer.address, signer.sign_body, signer.read_seqno))
    return payer, key
