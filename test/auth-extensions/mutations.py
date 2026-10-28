"""Prove that deleting nonce validation or the state bound turns the native tests red."""

import io
import shutil
import tempfile
import unittest
from pathlib import Path

from native import ROOT, compile_contract
from test_auth import (
    CODES,
    SCENARIOS,
    AuthenticationTests,
    observe,
    refused_once_problems,
    result_50_problems,
)

# Every file the wallet sources include, so a mutant compiles beside them.
WALLET_INCLUDES = {
    "wallet-func": [
        "wallet-v5-action-list.fc",
        "strong-ed25519-key.fc",
        "auth-extension.fc",
    ],
    "wallet-tol": ["auth-extension.tol"],
}

# Each state-bound guard, the scenario it alone stops, and the test that must
# go red without it.
STATE_BOUND_MUTANTS = [
    (
        "wallet-func",
        "wallet-v5-code.fc",
        "        enforce_state_bound(old_data, added);\n",
        ["addition", "removal"],
        "test_growth_past_the_state_limit_is_consumed_not_replayed",
    ),
    (
        "wallet-func",
        "wallet-v5-code.fc",
        "  enforce_state_bound(old_data, false);\n",
        ["staging"],
        "test_staging_at_the_state_limit_is_consumed_not_replayed",
    ),
    (
        "wallet-tol",
        "wallet-v5.tol",
        "                enforceStateBound(oldData, added);\n",
        ["addition", "removal"],
        "test_growth_past_the_state_limit_is_consumed_not_replayed",
    ),
    (
        "wallet-tol",
        "wallet-v5.tol",
        "    enforceStateBound(oldData, false);\n",
        ["staging"],
        "test_staging_at_the_state_limit_is_consumed_not_replayed",
    ),
]


def drive(impl, scenario):
    a, body = SCENARIOS[scenario](impl)
    try:
        seqno, extensions = a.counters()[1], a.extensions().hash
        return observe(a, body), seqno, extensions
    finally:
        a.close()


def kill_state_bound_mutants():
    for impl, source, guard, scenarios, test in STATE_BOUND_MUTANTS:
        # The unmutated wallet refuses each scenario once, so a red mutant
        # below is the guard's doing and not the fixture's.
        for scenario in scenarios:
            observations, seqno, extensions = drive(impl, scenario)
            assert not refused_once_problems(observations, seqno, extensions), (impl, scenario)
        original = CODES[impl]
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            for name in WALLET_INCLUDES[impl]:
                shutil.copy2(ROOT / "crypto/smartcont" / name, work / name)
            text = (ROOT / "crypto/smartcont" / source).read_text()
            assert text.count(guard) == 1, (impl, guard)
            (work / source).write_text(text.replace(guard, ""))
            # A mutant that does not compile is a harness error, not a kill.
            CODES[impl] = compile_contract(str(work / source), work / "mutant.boc")
            try:
                for scenario in scenarios:
                    observations, seqno, _ = drive(impl, scenario)
                    problems = result_50_problems(observations, seqno)
                    assert not problems, (impl, guard.strip(), scenario, problems)
                    print(
                        f"Without {guard.strip()!r} ({impl}) {scenario}: result 50 on both deliveries"
                    )
                result = unittest.TestResult()
                AuthenticationTests(test).run(result)
            finally:
                CODES[impl] = original
            assert not result.wasSuccessful(), f"{impl}: {guard.strip()} mutation survived {test}"
            assert result.failures and not result.errors, result.errors
            print(f"Killed state-bound mutation: {impl} {guard.strip()} ({test})")


def main():
    AuthenticationTests.setUpClass()
    try:
        for impl, source, helper, before, after in [
            (
                "agent",
                "agent-account-code.fc",
                "auth-extension.fc",
                "throw_unless(auth::bad_nonce, cs~load_uint(64) == nonce);",
                "cs~load_uint(64);",
            ),
            (
                "wallet-func",
                "wallet-v5-code.fc",
                "auth-extension.fc",
                "throw_unless(auth::bad_nonce, cs~load_uint(64) == nonce);",
                "cs~load_uint(64);",
            ),
            (
                "wallet-tol",
                "wallet-v5.tol",
                "auth-extension.tol",
                "assert (cs.loadUint(64) == nonce) throw 1804;",
                "cs.loadUint(64);",
            ),
        ]:
            original = CODES[impl]
            with tempfile.TemporaryDirectory() as work:
                work = Path(work)
                shutil.copy2(ROOT / "crypto/smartcont" / source, work / source)
                if impl == "wallet-func":
                    shutil.copy2(
                        ROOT / "crypto/smartcont/wallet-v5-action-list.fc",
                        work / "wallet-v5-action-list.fc",
                    )
                    shutil.copy2(
                        ROOT / "crypto/smartcont/strong-ed25519-key.fc",
                        work / "strong-ed25519-key.fc",
                    )
                text = (ROOT / "crypto/smartcont" / helper).read_text()
                assert text.count(before) == 1
                (work / helper).write_text(text.replace(before, after))
                CODES[impl] = compile_contract(str(work / source), work / "mutant.boc")
                # Run an instantiated case directly: a TestSuite would rerun
                # setUpClass and silently overwrite the mutated code.
                stream = io.StringIO()
                result = unittest.TestResult()
                AuthenticationTests("test_each_binding_is_enforced").run(result)
                CODES[impl] = original
                assert not result.wasSuccessful(), f"{impl}: nonce mutation survived"
                assert result.failures and not result.errors, stream.getvalue()
                assert any("expected exit 1804" in failure for _, failure in result.failures), (
                    result.failures
                )
                print(f"Killed nonce-check mutation: {impl}")
        kill_state_bound_mutants()
    finally:
        AuthenticationTests.tearDownClass()


if __name__ == "__main__":
    main()
