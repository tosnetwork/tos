"""Independent controls for the retirement scanner; enforcement is not yet active."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "retirement_guard", Path(__file__).with_name("check-retired-wallets.py")
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class RetirementGuardTests(unittest.TestCase):
    def check(self, name, text, historical=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            return guard.violations(root, [name], historical)

    def test_source_path_outside_exceptions(self):
        self.assertTrue(self.check("crypto/smartcont/wallet-v4-code.fc", "() main() {}"))

    def test_api_outside_exceptions(self):
        self.assertTrue(self.check("src/api.rs", "enum Wallet { V5R1 }"))

    def test_embedding_outside_exceptions(self):
        self.assertTrue(self.check("src/codes.ts", 'const WALLET_V4R2_CODE = "abcd";'))

    def test_registration_outside_exceptions(self):
        self.assertTrue(self.check("src/register.cpp", 'add("wallet.v4.accountState");'))

    def test_neutral_and_quantum_revision_names_pass(self):
        self.assertFalse(self.check("src/register.cpp", "quantum_wallet_v4; wallet_action;"))

    def test_only_exact_historical_file_is_exempt(self):
        name = "evidence/record.txt"
        self.assertFalse(self.check(name, "V5R1", historical=[name]))
        self.assertTrue(self.check("evidence/new-source.rs", "V5R1", historical=[name]))

    def test_compiler_fixture_is_exempt(self):
        self.assertFalse(self.check(guard.COMPILER_FIXTURE + "wallet-v4-code.fc", "WalletV4"))


if __name__ == "__main__":
    unittest.main()
