#!/usr/bin/env python3
"""Exercise the lite-client transport against a running chain.

Opt-in: set TOS_LITE_CLIENT and TOS_LITE_CONFIG to a built binary and a chain
configuration. Without them these are skipped, because a chain is not something
CI brings up here. What they cover is the part no emulator can produce — reading
the environment from a chain instead of a constant, pricing from that chain's
own gas configuration, and refusing to broadcast when the wallet cannot pay.
"""
import asyncio
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'test/tostester/src'), str(ROOT/'test/auth-extensions')]
from contract.pq_lite_transport import (LiteClientTransport, LiteClientError,
                                        WalletSigner, WalletV5Signer)
from contract import Mldsa44ModuleBlueprint
from contract.pq_auth import AuthRequest, transfer_message
from contract.wallet_v5 import WalletV5State
from pytosiq_core import Address, Cell
from cells import from_boc
import nacl.signing

BINARY = os.environ.get('TOS_LITE_CLIENT')
CONFIG = os.environ.get('TOS_LITE_CONFIG')


@unittest.skipUnless(BINARY and CONFIG, 'set TOS_LITE_CLIENT and TOS_LITE_CONFIG')
class LiveChain(unittest.TestCase):
    def setUp(self):
        self.unfunded = Address('0:' + 'ee' * 32)
        self.transport = LiteClientTransport(Path(BINARY), Path(CONFIG),
                                             WalletSigner(self.unfunded, None, None))

    def test_the_environment_comes_from_the_chain(self):
        network = self.transport.global_id()
        version = self.transport.global_version()
        block, chain_time = self.transport.head()
        self.assertIsInstance(network, int)
        self.assertGreaterEqual(version, 15)
        self.assertTrue(block.startswith('('), block)
        # Wall-clock, not the fixed timestamp the contract harnesses use.
        self.assertGreater(chain_time, 1_700_000_000)

    def test_the_estimate_is_priced_by_the_chain(self):
        prices = self.transport.gas_prices(0)
        self.assertGreater(prices['gas_price'], prices['flat_gas_price'],
                           'the flat price was read in place of the gas price')
        request = AuthRequest(self.transport.global_id(), Address('0:' + '12' * 32),
                              1, 0, 1600, 0, Cell.empty())
        budget = asyncio.run(self.transport.estimate(request, Address('0:' + '22' * 32)))
        self.assertEqual(budget.total, budget.module_compute + budget.forwarding
                         + budget.account_execution + budget.margin)
        # Priced from this chain, so it moves when the chain's price moves.
        self.assertGreater(budget.module_compute, 0)

    def test_an_unfunded_wallet_broadcasts_nothing(self):
        self.assertEqual(self.transport.balance(self.unfunded), 0)
        with self.assertRaises(LiteClientError) as refused:
            asyncio.run(self.transport.submit_internal(
                Address('0:' + '22' * 32), Cell.empty(), 1_000_000))
        self.assertIn('nothing was broadcast', str(refused.exception))


NETWORK = 42
WALLET_ID = 698983191


class FakeNode(LiteClientTransport):
    """Answers the handful of lite-client commands the signing path issues.

    A chain is not something CI brings up, but the message this builds and the
    account state it reads are the real ones; only the process boundary is
    replaced. Nothing here decides whether a signature is valid.
    """

    def __init__(self, accounts: dict, balance: int = 100_000_000_000):
        super().__init__(Path('/nonexistent'), Path('/nonexistent'),
                         poll_seconds=0.0, attempts=3)
        self.accounts, self._balance, self.sent = accounts, balance, []
        self.on_send = None

    def _run(self, command: str) -> str:
        if command == 'getconfig 19':
            return f'global_id:{NETWORK}\n'
        if command == 'getconfig 8':
            return 'version:16 capabilities:494\n'
        if command == 'last':
            return ('latest masterchain block known to server is (-1,8000000000000000,3)\n'
                    'created at 1780000000\n')
        if command.startswith('getaccount'):
            return f'account balance is {self._balance}ng\n'
        if command.startswith('sendfile'):
            self.sent.append(Path(command.split()[1]).read_bytes())
            if self.on_send is not None:
                self.on_send()
            return 'external message status is 1\n'
        raise AssertionError('unexpected command: ' + command)

    def account_data(self, address: Address):
        cell = self.accounts.get(address.to_str(False))
        if cell is None:
            raise LiteClientError(f'no account data for {address.to_str(False)}')
        return cell


def wallet_account(key, seqno: int):
    state = WalletV5State(True, seqno, WALLET_ID, key.verify_key.encode())
    return from_boc(state.serialize().to_boc())


class SigningWithoutAChain(unittest.TestCase):
    """The parts of the loop that do not need a node, so CI can run them."""

    def setUp(self):
        self.key = nacl.signing.SigningKey(bytes([0x7f]) * 32)
        self.address = Address('0:' + '11' * 32)
        self.module = Address('0:' + '22' * 32)
        self.accounts = {self.address.to_str(False): wallet_account(self.key, 0)}
        self.node = FakeNode(self.accounts)
        self.signer = WalletV5Signer(self.node, self.address, self.key)
        self.node.attach_wallet(WalletSigner(self.address, self.signer.sign_body,
                                             self.signer.read_seqno))

    def advance(self):
        self.accounts[self.address.to_str(False)] = wallet_account(
            self.key, self.signer.read_seqno() + 1)

    def test_a_transport_without_a_wallet_broadcasts_nothing(self):
        bare = FakeNode(self.accounts)
        with self.assertRaises(LiteClientError) as refused:
            asyncio.run(bare.submit_internal(self.module, Cell.empty(), 1))
        self.assertIn('nothing was broadcast', str(refused.exception))
        self.assertFalse(bare.sent)

    def test_the_seqno_is_read_from_the_account_and_never_remembered(self):
        self.assertEqual(self.signer.read_seqno(), 0)
        self.accounts[self.address.to_str(False)] = wallet_account(self.key, 7)
        self.assertEqual(self.signer.read_seqno(), 7)

    def test_signing_for_a_seqno_the_wallet_has_left_behind_is_refused(self):
        self.accounts[self.address.to_str(False)] = wallet_account(self.key, 4)
        with self.assertRaises(LiteClientError) as refused:
            self.signer.sign_body(self.module, Cell.empty(), 1, 3, 1_780_000_600, None)
        self.assertIn('nothing was signed', str(refused.exception))

    def test_the_signed_message_carries_the_transfer_it_was_asked_for(self):
        body = Cell.empty()
        value = 1_234_000_000
        external = self.signer.sign_body(self.module, body, value, 0, 1_780_000_600, None)
        # Walk what was actually built rather than trusting the builder: the
        # signed body sits inline in the external message, its one reference is
        # the wallet action payload, and the transfer is that payload's second.
        payload = from_boc(external.to_boc()).refs[0]
        expected = transfer_message(self.address, self.module, value, body).serialize()
        self.assertEqual(payload.refs[1].hash, expected.hash)
        # A different amount must not produce the same message.
        other = transfer_message(self.address, self.module, value + 1, body).serialize()
        self.assertNotEqual(payload.refs[1].hash, other.hash)

    def test_a_broadcast_that_never_moves_the_wallet_is_not_reported_as_sent(self):
        with self.assertRaises(LiteClientError) as refused:
            asyncio.run(self.node.submit_internal(self.module, Cell.empty(), 1))
        self.assertIn('unconfirmed', str(refused.exception))
        self.assertEqual(len(self.node.sent), 1, 'the message was still broadcast once')

    def test_deployment_waits_for_the_state_the_address_was_derived_from(self):
        blueprint = Mldsa44ModuleBlueprint(Cell.empty(), 0, NETWORK, bytes(1312))
        self.node.on_send = self.advance
        # An account that comes up carrying something else is a different
        # contract, and waiting for it must time out rather than succeed.
        self.accounts[blueprint.address.to_str(False)] = wallet_account(self.key, 0)
        with self.assertRaises(LiteClientError) as refused:
            asyncio.run(self.node.deploy(blueprint, 1_000_000_000))
        self.assertIn('never came up', str(refused.exception))

        self.accounts[self.address.to_str(False)] = wallet_account(self.key, 0)
        self.accounts[blueprint.address.to_str(False)] = from_boc(
            blueprint.state_init.data.to_boc())
        self.assertEqual(asyncio.run(self.node.deploy(blueprint, 1_000_000_000)),
                         blueprint.address)

    def test_deployment_refuses_to_be_free(self):
        blueprint = Mldsa44ModuleBlueprint(Cell.empty(), 0, NETWORK, bytes(1312))
        with self.assertRaises(LiteClientError):
            asyncio.run(self.node.deploy(blueprint, 0))
        self.assertFalse(self.node.sent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
