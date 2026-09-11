"""Prove that deleting nonce validation turns the native tests red."""
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from native import ROOT, compile_contract
from test_auth import AuthenticationTests, CODES


def main():
    AuthenticationTests.setUpClass()
    try:
        for impl, source, helper, before, after in [
            ('agent', 'agent-account-code.fc', 'auth-extension.fc',
             'throw_unless(auth::bad_nonce, cs~load_uint(64) == nonce);', 'cs~load_uint(64);'),
            ('wallet-func', 'wallet-v5-code.fc', 'auth-extension.fc',
             'throw_unless(auth::bad_nonce, cs~load_uint(64) == nonce);', 'cs~load_uint(64);'),
            ('wallet-tol', 'wallet-v5.tol', 'auth-extension.tol',
             'assert (cs.loadUint(64) == nonce) throw 1804;', 'cs.loadUint(64);'),
        ]:
            original = CODES[impl]
            with tempfile.TemporaryDirectory() as work:
                work = Path(work)
                shutil.copy2(ROOT / 'crypto/smartcont' / source, work / source)
                text = (ROOT / 'crypto/smartcont' / helper).read_text()
                assert text.count(before) == 1
                (work / helper).write_text(text.replace(before, after))
                CODES[impl] = compile_contract(str(work / source), work / 'mutant.boc')
                # Run an instantiated case directly: a TestSuite would rerun
                # setUpClass and silently overwrite the mutated code.
                stream = io.StringIO()
                result = unittest.TestResult()
                AuthenticationTests('test_each_binding_is_enforced').run(result)
                CODES[impl] = original
                assert not result.wasSuccessful(), f'{impl}: nonce mutation survived'
                assert result.failures and not result.errors, stream.getvalue()
                assert any('expected exit 1804' in failure for _, failure in result.failures), result.failures
                print(f'Killed nonce-check mutation: {impl}')
    finally:
        AuthenticationTests.tearDownClass()


if __name__ == '__main__':
    main()
