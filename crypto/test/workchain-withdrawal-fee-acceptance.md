# Withdrawal authenticated operation fee: host acceptance item

Normative basis: memo `d8c6b463`, specification SHA256 prefix
`cf7f0f4569e2638e`. This item is additional to, not a replacement for, B's
six sequence contracts. B owns its contract numbering; stable A identifier:
`FEE-ADMISSION`.

Required default CTest name: `test-workchain-withdrawal-host-authenticated-fee`.
Readiness command:

```
python3 crypto/test/workchain-withdrawal-fee-handoff.py --build BUILD_DIRECTORY
```

## Fixture, path and observation

Use explicit authenticated Withdrawal tariff configuration with a positive
required operation fee. Per memo 6f440f8d, billing units are 1; W-state fee is
an explicit authenticated test parameter, not a frozen value or SEND slot fee.
Do not substitute proof-work units or supply local defaults for missing
configuration. This supersedes the earlier zero-state-fee wording. Keep x, outward fee
and reserve fixed: their checked sum T is distinct from operation fee f.

Run real Withdrawal prepare admission through the registered host. Use valid
identities, nonce, predecessor account and a proof matching the submitted f;
fund the account sufficiently so range/cryptographic failure cannot mask the
tariff check. First admit the exact required fee. Then submit required_fee - 1
(checked subtraction). Observe CandidateInvalid (-7200) at the authenticated
tariff admission check, with its specific diagnostic, not at decoding, proof
verification, unavailable configuration, or unsupported operation dispatch.
Read committed Native/account/coordinator outputs: rejected admission must not
publish a payout, a W record, a balance debit, or a state successor.

## Red and oracle controls

In an isolated implementation remove only the host tariff comparison. The same
underpayment test must now fail because the designated rejection disappears;
another rejection is not the required red. Restore the comparison and rerun.
In a separate isolated oracle disable its underpayment verdict assertion while
retaining the producer mutation: the mutation driver must fail because its
expected red disappeared. Do not regenerate proof/vector expectations to fit
an implementation error. B's independent criterion remains independent.

## Status and limits

The host prepare adapter and this actual negative test are not installed.
The readiness runner currently exits 1 naming the missing test. That demonstrates
missing coverage is not silently counted as success; it does NOT demonstrate
low-fee rejection. No placeholder passing CTest is registered. A kernel accepting
the provided operation_fee is not evidence of host tariff validation.
