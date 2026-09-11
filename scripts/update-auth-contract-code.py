#!/usr/bin/env python3
"""Regenerate the existing Agent Account and Wallet V5 SDK BOCs, without a version bump.

Build func/fift first and set FUNC_PATH/FIFT_PATH (or use build/crypto).
--check verifies reproducibility without writing to the working tree.
"""
import argparse
import base64
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'test/auth-extensions'))
from native import compile_contract  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    os.environ.setdefault('FUNC_PATH', str(ROOT / 'build/crypto/func'))
    os.environ.setdefault('FIFT_PATH', str(ROOT / 'build/crypto/fift'))
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        outputs = {}
        for name, source in [('agent', 'agent-account-code.fc'), ('wallet', 'wallet-v5-code.fc')]:
            output = work / f'{name}.boc'
            code = compile_contract(source, output)
            outputs[name] = output.read_bytes()
            print(f'{name}: code hash {code.hash.hex()}')
        replacements = [
            ('tosctl/src/node-control/contracts/src/agent_account.rs',
             r'(pub const AGENT_ACCOUNT_CODE_B64: &str =\s*")[^"]*(";)',
             base64.b64encode(outputs['agent']).decode()),
            ('tosctl/src/node-control/contracts/src/wallet/wallet_contract.rs',
             r'(pub const V5R1_CODE_B64: &str =\s*")[^"]*(";)',
             base64.b64encode(outputs['wallet']).decode()),
            ('sdk/js/packages/wallets/src/codes.ts',
             r'(export const WALLET_V5R1_CODE\s*=\s*")[^"]*(";)',
             outputs['wallet'].hex()),
        ]
        stale = []
        for relative, pattern, value in replacements:
            path = ROOT / relative
            text = path.read_text()
            updated, count = re.subn(pattern, lambda m: m[1] + value + m[2], text)
            if count != 1:
                raise SystemExit(f'{relative}: expected exactly one embedding, got {count}')
            if updated != text:
                stale.append(relative)
                if not args.check:
                    path.write_text(updated)
        if args.check and stale:
            raise SystemExit('Stale authentication bytecode: ' + ', '.join(stale))
        print('Authentication bytecode is current.' if args.check else 'Updated: ' + ', '.join(stale))


if __name__ == '__main__':
    main()
