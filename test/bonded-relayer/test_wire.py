"""Additional native wire-format guards; uses the real shared TVM fixture."""

import unittest

import test_native as native_suite
from test_native import ACTIVATE, COIN, METADATA, REPORTER, RETIRE, Cell, header


class WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_suite.BondTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        native_suite.BondTests.tearDownClass()

    def bond(self):
        value = native_suite.Bond()
        self.addCleanup(value.close)
        return value

    def test_statement_lifetime_and_zero_slot_are_checked(self):
        b = self.bond()
        b.activate()
        for fields in ({"until": b.now + 301}, {"until": b.now}, {"slot": 0}):
            a, c = b.acceptance(**fields), b.acceptance(intent=124, **fields)
            b.send(b.proof(a, c), sender=REPORTER, expected=2407)

    def test_trailing_payload_is_refused_not_ignored(self):
        b = self.bond()
        b.activate()
        b.send(header(RETIRE).uint(1, 1), expected=9)
        b.send(header(METADATA).uint(1, 256).ref(Cell()), expected=9)

    def test_signature_shape_is_checked_before_verification(self):
        b = self.bond()
        signature = Cell().uint(2419, 32).ref(Cell())
        b.send(header(ACTIVATE).coins(10 * COIN).ref(signature), value=13 * COIN, expected=2400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
