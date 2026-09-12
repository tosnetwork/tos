"""Test-only continuation from real Native Deposits; no assumed funding path."""
import subprocess


def run(build, fixture, wallet, advance_pair, initial_only=False, initial_principal=1000000000,
        initial_collection=None):
    def node(mode):
        subprocess.run([str(build / 'test-m3-live'), mode, str(fixture)], check=True)

    def fields(path):
        return dict(line.split('=', 1) for line in path.read_text().splitlines())

    def write(name, values):
        (fixture / name).write_text(''.join(f'{k}={v}\n' for k, v in values.items()))

    def prove(mode, source, output):
        subprocess.run([str(wallet), mode, str(fixture / source), str(fixture / output)], check=True)

    def pair(number):
        subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
        advance_pair(number)
        # Exercise the existing full-ShardIdFull masterchain import path too.
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1',
                        '-M', str(fixture / f'{number}-enabled-top1.boc'),
                        '--export-candidate', str(fixture / 'm4-master.candidate'),
                        '--query-result', str(fixture / f'm4-operation-{number}-master.result')], check=True)
        node('--check-m4-master')

    node('--wallet-policy')
    policy = fields(fixture / 'wallet-policy.txt')
    send_fee, collect_fee = int(policy['send_fee']), int(policy['collect_fee'])
    limits = {key: policy[key] for key in ('max_balance', 'max_value')}

    def collect(owner, before, old_blind, new_blind, receipt, value, number):
        write('operation.wallet.txt', dict(owner=owner, selected=receipt, value=value))
        node('--collect-receipts')
        witness = dict(secret=101 if owner == 0 else 223, old_value=before, old_blind=old_blind,
                       new_blind=new_blind, aux_blind=83, auxiliaries='89',
                       **fields(fixture / 'operation.receipts.txt'))
        write('operation.request.txt', dict(witness, kind=2, fee=collect_fee, **limits))
        prove('points-receipts', 'operation.request.txt', 'operation.points.txt')
        node('--collect-request')
        statement = fields(fixture / 'operation.statement.txt')
        if set(statement) & set(witness):
            raise RuntimeError('wallet witness overwrites authenticated COLLECT statement')
        write('operation.request.txt', dict(witness, **statement))
        prove('prove-receipts', 'operation.request.txt', 'operation.proof.txt')
        node('--collect-finish')
        total = before + value
        if total > 2**64-1 or total < collect_fee:
            raise RuntimeError('COLLECT expectation arithmetic invalid')
        after = total - collect_fee  # checked above; no unsigned wraparound
        write('operation.expected.txt', dict(before=before, after=after))
        pair(number)
        return after

    if initial_collection is not None and not initial_only:
        raise RuntimeError('explicit initial collection is only a fixture continuation')
    first = (fixture / 'deposit-2.id').read_text()
    selection = initial_collection or (0, 0, 67, first, initial_principal, 3 if initial_only else 4)
    a1 = collect(0, *selection)
    if initial_only:
        return a1, selection[2], send_fee, collect_fee, limits
    retained = (fixture / 'deposit-3.id').read_text()
    a2 = collect(0, a1, 67, 71, retained, 1000000000, 5)
    # Section 10 closure requires available=0. The one SEND therefore spends
    # exactly the remaining available less its authenticated fee, not a later
    # cleanup operation and not a relaxed closure predicate.
    if a2 < send_fee:
        raise RuntimeError('fixed live sequence cannot fund SEND fee')
    amount = a2 - send_fee
    if not 1000000000 <= amount <= int(policy['max_value']):
        raise RuntimeError('fixed live sequence SEND principal outside admitted range')
    write('operation.wallet.txt', dict(owner=0))
    witness = dict(secret=101, receiver_secret=223, old_value=a2, old_blind=71,
                   value=amount, new_blind=73, transfer_blind=79, aux_blind=43)
    write('operation.request.txt', dict(witness, kind=1, fee=send_fee, **limits))
    prove('points', 'operation.request.txt', 'operation.points.txt')
    node('--send-request')
    statement = fields(fixture / 'operation.statement.txt')
    if set(statement) & set(witness):
        raise RuntimeError('wallet witness overwrites authenticated SEND statement')
    write('operation.request.txt', dict(witness, **statement))
    prove('prove', 'operation.request.txt', 'operation.proof.txt')
    node('--send-finish')
    write('operation.expected.txt', dict(before=a2, after=0))
    pair(6)
    received = (fixture / 'accepted-receipt.id').read_text()
    b = collect(1, 0, 0, 97, received, amount, 7)
    write('closure.expected.txt', dict(other=b))
    node('--closure-request')
    prove('close', 'closure.request.txt', 'closure.proof.txt')
    node('--closure-finish')
    pair(8)
    print(f'M4 sequence actors accepted: A=0 B={b}; SEND principal={amount}; '
          'this alone is not the full M4 acceptance checklist.', flush=True)
