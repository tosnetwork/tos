"""Separate real Native rejection cases; no assumed balances or second permit."""
import subprocess


def run(build, fixture, advance_pair):
    def node(*args):
        subprocess.run([str(build / 'test-m3-live'), *args, str(fixture)], check=True)

    def collate(wc, *args):
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', str(wc), *map(str, args)], check=True)

    # Two distinct admission failures, followed by non-bounceable input.
    # Native costs are observed, never assumed to equal principal or full value.
    for number, (principal, extra, bounce) in enumerate(
            [(999999999, 0, 1), (1000000000, 1, 1), (999999999, 0, 0)], 4):
        (fixture / 'deposit.request.txt').write_text(f'principal={principal}\n')
        (fixture / 'deposit.rejection.txt').write_text(f'extra={extra}\nbounce={bounce}\n')
        node('--deposit-request')
        collate(0, '-m', fixture / 'deposit.message.boc', '-s', fixture / f'reject-{number}-payer-top')
        collate(-1, '-M', fixture / f'reject-{number}-payer-top1.boc')
        node()
        advance_pair(number)
        collate(-1, '-M', fixture / f'{number}-enabled-top1.boc')
        if bounce:
            collate(0, '--export-candidate', fixture / 'bounce-recipient.candidate',
                    '-s', fixture / f'reject-{number}-recipient-top')
            node('--check-m4-bounce-received')
            collate(-1, '-M', fixture / f'reject-{number}-recipient-top1.boc')
    print('Three real rejection ON/OFF pairs completed; two sender receipts and one sender bucket.', flush=True)
