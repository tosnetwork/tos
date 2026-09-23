#!/usr/bin/env python3
"""Remove one rule at a time from the shielded authorization library and require
the sandbox suite to report it, by name.

A mutation that turns the wrong test red is not evidence for the one it was
aimed at, so each case names the test that must fail. A mutation that fails to
compile is not evidence at all: every replacement below still compiles and
still runs, it is simply wrong.

Usage: mutations-auth.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys

# This repository, never another checkout: TOS_ROOT points at the built
# toolchain, which may live somewhere else entirely.
from toolchain import toolchain_root

ROOT = Path(__file__).resolve().parents[2]
AUTH = ROOT / 'crypto/smartcont/shielded/auth.fc'
CONTRACTS = ROOT / 'tosctl/src/node-control/contracts'
SUITE = 'shielded_auth_sandbox'

CHAIN_TEST = 'a_noncanonical_public_key_chain_is_refused'
HASH_TEST = 'the_public_key_hash_is_the_sha256_rule_over_the_whole_key'
DIGEST_TEST = 'the_intent_digest_binds_every_field_it_is_specified_to_bind'
SIGNED_TEST = 'the_signed_bytes_are_the_digest_under_the_fixed_context'
SUBSTITUTION_TEST = 'an_attackers_own_valid_keypair_cannot_authorize_the_transaction'
VALIDITY_TEST = 'valid_until_must_be_now_or_within_the_hour'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # --- 4.1, the public key hash -----------------------------------------
    Case('key-hash-prefix', 'the public key preimage loses its domain prefix', AUTH,
         'sha256_of_twelve("TOS-SHIELDED-MLDSA44-PK-v1",',
         'sha256_of_twelve("TOS-SHIELDED-MLDSA44-PK-v2",',
         HASH_TEST),
    Case('key-hash-reduction', 'the key hash is no longer brought into the field', AUTH,
         '  return reduce_to_field(digest);', '  return digest;',
         HASH_TEST),
    Case('key-length', 'the operand length is one byte short of the key', AUTH,
         'int mldsa44_public_key_bytes() asm "1312 PUSHINT";',
         'int mldsa44_public_key_bytes() asm "1311 PUSHINT";',
         HASH_TEST),

    # --- the canonical byte chain rules of crypto/vm/pqops.cpp -------------
    Case('chain-null', 'a missing chain cell is no longer refused', AUTH,
         '  throw_if(130, cell_null?(chunk));', '  throw_if(130, 0);',
         CHAIN_TEST),
    Case('chain-special', 'a special cell is accepted as a chain cell', AUTH,
         '  throw_if(131, special);', '  throw_if(131, 0);',
         CHAIN_TEST),
    Case('chain-level', 'a cell above level zero is accepted', AUTH,
         '  throw_unless(132, cell_level(chunk) == 0);',
         '  throw_unless(132, cell_level(chunk) >= 0);',
         CHAIN_TEST),
    Case('chain-size', 'a chunk of any size is accepted', AUTH,
         '  throw_unless(133, slice_bits(body) == payload_bytes * 8);',
         '  throw_unless(133, slice_bits(body) >= 0);',
         CHAIN_TEST),
    Case('chain-refs', 'the reference rule weakens to "at most one"', AUTH,
         '  throw_unless(134, slice_refs(body) == has_next);',
         '  throw_unless(134, slice_refs(body) <= 1);',
         CHAIN_TEST),
    Case('chain-length-guard', 'an operand length of zero bytes is accepted', AUTH,
         '  throw_unless(135, total_bytes > 0);\n', '',
         SIGNED_TEST),
    Case('signature-chain', 'the signature chain is no longer checked', AUTH,
         '  check_pq_byte_chain(signature, mldsa44_signature_bytes());\n', '',
         SIGNED_TEST),

    # --- 9.3, the intent digest -------------------------------------------
    Case('core-domain', 'intent_core borrows the output half\'s domain', AUTH,
         '  return h7(domain_intent_core(),', '  return h7(domain_intent_outputs(),',
         DIGEST_TEST),
    Case('core-dropped-field', 'recovery_template_hash is not bound into the core', AUTH,
         '            withdrawal_fee, public_recipient_hash, recovery_template_hash);',
         '            withdrawal_fee, public_recipient_hash, 0);',
         DIGEST_TEST),
    Case('outputs-order', 'the two key hashes are absorbed the other way round', AUTH,
         '            pq_auth_key_hash_0, pq_auth_key_hash_1, intent_nonce, valid_until);',
         '            pq_auth_key_hash_1, pq_auth_key_hash_0, intent_nonce, valid_until);',
         DIGEST_TEST),
    Case('final-padding', 'one padding lane of the final hash is no longer zero', AUTH,
         '  return h7(domain_intent_final(), intent_core, intent_outputs, 0, 0, 0, 0, 0);',
         '  return h7(domain_intent_final(), intent_core, intent_outputs, 1, 0, 0, 0, 0);',
         DIGEST_TEST),
    Case('recovery-domain', 'the recovery template borrows another domain', AUTH,
         '  return h7(domain_recovery_template(),', '  return h7(domain_intent_final(),',
         DIGEST_TEST),

    # --- 9.4, the signed bytes --------------------------------------------
    Case('context-string', 'the signing context is a different 28-byte string', AUTH,
         'store_slice("TOS-SHIELDED-POOL-MLDSA44-v1")',
         'store_slice("TOS-SHIELDED-POOL-MLDSA44-v2")',
         SIGNED_TEST),
    Case('message-canonical', 'a digest outside the field is signed anyway', AUTH,
         '  throw_unless(136, (digest >= 0) & (digest < field_modulus()));',
         '  throw_unless(136, digest >= 0);',
         SIGNED_TEST),

    # --- 9.1, two signatures always ---------------------------------------
    Case('slot-0-signature', 'the signature in input slot 0 is not verified', AUTH,
         '  throw_unless(137, verify_intent_signature(public_key_0, signature_0, digest));\n', '',
         SUBSTITUTION_TEST),
    Case('slot-1-signature', 'the signature in input slot 1 is not verified', AUTH,
         '  throw_unless(138, verify_intent_signature(public_key_1, signature_1, digest));\n', '',
         SUBSTITUTION_TEST),
    Case('slot-1-key-hash', 'slot 1 reports slot 0\'s key hash instead of its own', AUTH,
         '  int key_hash_1 = pq_auth_key_hash(public_key_1);',
         '  int key_hash_1 = key_hash_0;',
         SUBSTITUTION_TEST),

    # --- 9.3, the validity window -----------------------------------------
    Case('validity-uint32', 'valid_until is no longer held to the uint32 field', AUTH,
         '  throw_unless(139, (valid_until >= 0) & (valid_until < uint32_limit()));\n', '',
         VALIDITY_TEST),
    Case('validity-past', 'a valid_until already in the past is accepted', AUTH,
         '  throw_unless(140, valid_until >= now_seconds);\n', '',
         VALIDITY_TEST),
    Case('validity-window', 'the one-hour ceiling on valid_until is removed', AUTH,
         '  throw_unless(141, valid_until <= now_seconds + intent_validity_window());\n', '',
         VALIDITY_TEST),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    # TOS_ROOT only locates the built func/fift toolchain and stdlib.fc; the
    # library under test is found from the crate manifest, inside this tree.
    env.setdefault('TOS_ROOT', str(toolchain_root(ROOT)))
    return subprocess.run(['cargo', 'test', '--test', SUITE, '--', '--test-threads=1'],
                          cwd=CONTRACTS, capture_output=True, text=True, timeout=3600, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    options = parser.parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    baseline = run_suite()
    if baseline.returncode:
        raise SystemExit('the suite is not green before any mutation:\n'
                         + baseline.stdout + baseline.stderr)
    print('baseline green', flush=True)

    survivors = []
    for case in cases:
        original = case.path.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            case.path.write_text(original.replace(case.before, case.after))
            result = run_suite()
            failures = failed_tests(result.stdout + result.stderr)
            if result.returncode == 0:
                survivors.append(f'{case.name}: the suite stayed green')
                verdict = 'SURVIVED'
            elif 'error[' in result.stderr or 'could not compile' in result.stderr:
                survivors.append(f'{case.name}: no longer compiles, which is not evidence')
                verdict = 'UNCOMPILED'
            elif case.expect not in failures:
                survivors.append(f'{case.name}: failed as {sorted(failures)}, not {case.expect}')
                verdict = 'WRONG-TEST'
            else:
                verdict = 'killed'
            print(f'{case.name:20} {case.why:58} {verdict}', flush=True)
        finally:
            case.path.write_text(original)

    restored = run_suite()
    if restored.returncode:
        raise SystemExit('the suite did not come back green:\n' + restored.stdout + restored.stderr)
    print('green again', flush=True)

    if survivors:
        print('\nSURVIVORS:', file=sys.stderr)
        for line in survivors:
            print('  ' + line, file=sys.stderr)
        return 1
    print(f'\n{len(cases)} mutations, all killed by the test they were aimed at')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
