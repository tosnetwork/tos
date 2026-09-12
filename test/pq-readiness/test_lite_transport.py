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
        forwarding = self.transport.forward_prices(0)
        self.assertGreater(forwarding['cell_price'], forwarding['lump_price'])
        request = AuthRequest(self.transport.global_id(), Address('0:' + '12' * 32),
                              1, 0, 1600, 0, Cell.empty())
        budget = asyncio.run(self.transport.estimate(request, Address('0:' + '22' * 32)))
        self.assertEqual(budget.total, budget.module_compute + budget.forwarding
                         + budget.account_execution + budget.margin)
        # Priced from this chain, so it moves when the chain's prices move.
        self.assertGreater(budget.module_compute, 0)
        self.assertGreater(budget.forwarding, 0)

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
        self.transactions: dict = {}
        self.module_key = bytes(1312)
        self.on_send = None

    def _run(self, command: str) -> str:
        if command == 'getconfig 19':
            return f'global_id:{NETWORK}\n'
        if command == 'getconfig 8':
            return 'version:16 capabilities:494\n'
        if command == 'getconfig 21':
            # Production-shaped basechain prices. These deliberately include a
            # flat prefix so a test that falls back to gas_price/2^16 is wrong.
            return ('gas_price:26214400 flat_gas_limit:100 '
                    'flat_gas_price:40000\n')
        if command == 'getconfig 25':
            return ('lump_price:400000 bit_price:26214400 cell_price:2621440000 '
                    'ihr_price_factor:98304 first_frac:21845 next_frac:21845\n')
        if command == 'last':
            return ('latest masterchain block known to server is (-1,8000000000000000,3)\n'
                    'created at 1780000000\n')
        if command.startswith('getaccount'):
            reference = self.transactions.get(command.split()[1])
            trailer = ''
            if reference is not None:
                lt, digest = reference[1].split(':')
                trailer = f'last transaction lt = {lt} hash = {digest}\n'
            return f'account balance is {self._balance}ng\n' + trailer
        if command.startswith('lasttransdump'):
            for exit_code, reference in self.transactions.values():
                if reference.split(':')[0] == command.split()[2]:
                    return f'exit_code:{exit_code}\n'
            raise AssertionError('no such transaction: ' + command)
        if command.startswith('sendfile'):
            self.sent.append(Path(command.split()[1]).read_bytes())
            if self.on_send is not None:
                self.on_send()
            return 'external message status is 1\n'
        raise AssertionError('unexpected command: ' + command)

    def read_module_key(self, module: Address) -> bytes:
        return self.module_key

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

    def test_fee_estimate_uses_the_chain_compute_and_message_formulas(self):
        request = AuthRequest(NETWORK, Address('0:' + '44' * 32),
                              1, 0, 1_780_000_600, 0, Cell.empty())
        budget = asyncio.run(self.node.estimate(request, self.module))
        gas = self.node.gas_prices(0)
        self.assertEqual(budget.module_compute,
                         self.node._gas_fee(64_400, gas))
        self.assertEqual(budget.module_compute, 25_760_000)
        self.assertEqual(budget.account_execution,
                         self.node._gas_fee(20_000, gas))
        # The forward charge is based on Config25 and the cell tree the module
        # actually relays. It must not regress to the old 10k-gas proxy.
        envelope = request.envelope(bytes(64))
        cells, bits = self.node._tree_size(envelope)
        expected = self.node._forward_fee(cells, bits,
                                          self.node.forward_prices(0))
        self.assertEqual(budget.forwarding, expected)
        self.assertNotEqual(budget.forwarding, 10_000 * 400)

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

    def test_a_receipt_never_claims_a_transaction_that_predates_the_attempt(self):
        """Both accounts already exist and already have a last transaction."""
        from contract.pq_auth import AuthRequest, AuthState
        module = Address('0:' + '33' * 32)
        account = Address('0:' + '44' * 32)
        registered = WalletV5State(True, 0, WALLET_ID, self.key.verify_key.encode(),
                                   auth=AuthState(2, 1, 0, module.hash_part))
        self.accounts[account.to_str(False)] = from_boc(registered.serialize().to_boc())
        request = AuthRequest(NETWORK, account, 1, 0, 1_780_000_600, 0, Cell.empty())
        # Deployments that succeeded long before this attempt was prepared.
        self.node.transactions = {account.to_str(False): (0, '100:AA'),
                                  module.to_str(False): (0, '100:BB')}
        self.node.module_key = bytes(1312)
        asyncio.run(self.node.snapshot(account, module))
        self.node._module_marks['b'] = 100
        stale = asyncio.run(self.node.receipt('b', request, module))
        self.assertEqual(stale.status, 'pending')
        self.assertIsNone(stale.module_success)
        self.assertIsNone(stale.account_nonce_consumed,
                          'an earlier transaction was read as this attempt')

        # The module refuses this attempt. The account cannot have acted on it,
        # whatever its own last transaction happens to say.
        self.node.transactions[module.to_str(False)] = (1808, '200:CC')
        self.node.transactions[account.to_str(False)] = (0, '300:DD')
        refused = asyncio.run(self.node.receipt('b', request, module))
        self.assertEqual(refused.status, 'module_rejected')
        self.assertIsNone(refused.account_nonce_consumed)
        self.assertIsNone(refused.account_transaction)

        # Only once the module relayed does the account's later transaction
        # belong to this attempt.
        self.node.transactions[module.to_str(False)] = (0, '200:CC')
        executed = asyncio.run(self.node.receipt('b', request, module))
        self.assertEqual(executed.status, 'executed')
        self.assertTrue(executed.account_nonce_consumed)

    def test_deployment_refuses_to_be_free(self):
        blueprint = Mldsa44ModuleBlueprint(Cell.empty(), 0, NETWORK, bytes(1312))
        with self.assertRaises(LiteClientError):
            asyncio.run(self.node.deploy(blueprint, 0))
        self.assertFalse(self.node.sent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
