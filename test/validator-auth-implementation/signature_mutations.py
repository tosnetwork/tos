"""Compile removals of the signature charge; require the named measurement to fail.

Two halves, because the price and the count live in two places on purpose. The
registry says how many verifications it is about to perform and says so before
performing them; the machine says what one costs. Neither can be checked by the
other's tests, so each is removed here against the file that measures it.
"""
import argparse
import json
import subprocess
from pathlib import Path

from context_mutations import checked, mutate

# Guard name, failing case, original production expression, replacement.
#
# The count, in the registry's own verification path.
VERIFY = [
    # A verification performed and not announced is a verification nobody pays
    # for, which is the whole of the charge.
    ('signature-unreported', 'governance-reports-one-verification-for-each-signature-it-checks',
     'if (meter)\n      (*meter)(p.key->suite());\n', ''),
    # And announcing while the structure is still being read charges for
    # certificates that are refused before any signature is looked at.
    ('signature-before-structure', 'a-certificate-refused-before-verification-reports-none',
     'pending.push_back({&member->second.keys[duty.role_ - 1], std::move(statement.value()), &c.signature_});',
     '{\n      const auto* early = &member->second.keys[duty.role_ - 1];\n'
     '      if (meter)\n        (*meter)(early->suite());\n'
     '      auto valid = early->verify(statement.value(), c.signature_);\n'
     '      if (!valid.ok())\n        return valid.error();\n'
     '      if (!valid.value())\n        return Error{"signature"};\n    }'),
]

# The same removal again, against the whole transaction rather than the
# verification path alone. A capacity bound that survived the verification being
# skipped would be measuring the contract and calling it the cost of governance.
CAPACITY = [
    ('signature-unreported-in-transaction',
     'the-whole-transaction-verifies-every-signature-the-committee-supplied',
     'if (meter)\n      (*meter)(p.key->suite());\n', ''),
]

# The price, in the machine that publishes it.
TARIFF = [
    ('classical-tariff', 'verification-past-the-free-allowance-pays-the-machine-tariff',
     'st->register_chksgn_call();', ''),
    ('post-quantum-tariff', 'a-post-quantum-verification-pays-the-post-quantum-tariff',
     'st->consume_gas_chk(pq_mldsa44_base_gas);', ''),
    ('unpriced-suite', 'a-suite-the-machine-has-no-tariff-for-is-refused-not-charged',
     'throw VmError{Excno::cell_und, "unpriced signature suite"};', 'return;'),
]


def main(args):
    build = args.build.resolve()
    folder = build / 'test/validator-auth-implementation'

    def runner(target, arguments=()):
        def run(_label=None):
            checked(['cmake', '--build', str(build), '--target', target, '-j2'])
            return subprocess.run([str(folder / target), *arguments], capture_output=True, text=True)
        return run

    report = mutate(folder / 'signature-verify-mutated.cpp', VERIFY, runner('test-p0-governance-gas-mutant'))
    if args.contract:
        report += mutate(folder / 'signature-verify-mutated.cpp', CAPACITY,
                         runner('test-p0-governance-capacity-mutant', [str(args.contract.resolve())]))
    report += mutate(folder / 'signature-tariff-mutated.cpp', TARIFF, runner('test-p0-signature-tariff-mutant'))
    args.out.write_text(json.dumps(dict(signature_mutations=report, restored_baselines=True), indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    # The built configuration contract. Without it the whole-transaction bound
    # cannot be run, so its mutation is skipped rather than reported as killed.
    parser.add_argument('--contract', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    main(parser.parse_args())
