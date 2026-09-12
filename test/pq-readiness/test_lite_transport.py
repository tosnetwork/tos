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
from contract.pq_lite_transport import LiteClientTransport, LiteClientError, WalletSigner
from contract.pq_auth import AuthRequest
from pytosiq_core import Address, Cell

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
