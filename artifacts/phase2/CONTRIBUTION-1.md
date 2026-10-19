# Contribution 1 — tosman

Status: **accepted contribution to an open ceremony; not final parameters**.
Execution and publication are delegated to an agent on the operator's machine.
The contributor is registered as not independent of the operator.

| Field | Value |
|---|---|
| Contributor | tosman, https://github.com/gtosnetwork-dotcom |
| Built from | `49ef58c0ab98f62b76ae3c61a510980dae131235` |
| Initial register revision | `49ef58c0ab98f62b76ae3c61a510980dae131235` |
| Register SHA-256 | `abc6532e7aeaade754babd485d943f161093ed3921b4730a24cc69ea3190ebc7` |
| Starting-parameters publication commit | `81a893e25051890f0ccd7171daaaf5250b96f4f4` |
| Contribution digest | `65cbe4db248743a1cca1b49414f4d98a0b882529a7da3b4593df2951b8312198` |
| Transcript after contribution | `551ba6e7b91b32169f1f44c42aea1fbd7216da783e4543628ccb3cb3fcb9dbeb` |
| Resulting key.bin SHA-256 | `d6164dd01b8c3725d618483fdec439bab319dac66cbd84a5831af713789ce586` |

## Publication order

1. Public signing key: commit `f5a45898fa810f1bea5bbcaf4f0803be0b2bfb4b`.
2. Open-participation policy and initial register: the revision above.
3. [Announcement release](https://github.com/tosnetwork/tos/releases/tag/shielded-pool-phase2-announcement-v2),
   server-published at **2026-09-22T10:30:56Z**. Its downloaded attachment
   matched the local announcement byte for byte before opening. See
   [publication-receipt.json](publication-receipt.json).
4. Starting parameters published in the separate commit above.
5. This contribution, signed attestation and verification evidence published
   separately. The release publication receipt is retained after upload.

Both Bitcoin witnesses returned height 968132 before opening and again after
contributing, below the announced close at 970141 and beacon at 970285.
These are observations; server publication metadata provides the independent
hosting timestamp. No archive.org capture is claimed.

## Validation performed

- `cargo build --release --locked --bins` against the ceremony manifest at the
  announced code revision succeeded. Later commits changed documentation and
  artifacts; the ceremony and circuit sources remained identical.
- `phase2-begin` reproduced the announced starting key and transcript.
- `phase2-contribute` rebuilt the starting key and produced exactly one entry.
- `phase2-verify` exited 0 and reported `the chain audits: 1 contribution(s)`.
  It also reported `NOT FINISHED`, as expected before the beacon.
- `ssh-keygen -Y verify`, namespace `file`, verified tosman's signature against
  the public key from `roster.json`. A separate record comparison checked the
  attestation header, code revision, starting key, contribution and transcript;
  the key binary's SHA-256 also matched the record.
- No Python script was run in this operation, at the operator's request.
  The repository's Python attestation verifier and its regression suite were
  not rerun. The direct SSH check and record comparison above are the checks
  actually performed, not a claimed pass of that suite.
- Documentation links, shell syntax and whitespace were checked. The
  attestation verifier's executable logic is unchanged by the policy update.

Logs are in [evidence](evidence); the signed statement is
[attestation-1.txt](attestation-1.txt), with
[its SSH signature](attestation-1.txt.sig). The signing private key is not in
this repository or the release archive. No contribution scalar was exposed or
saved by the execution workflow; the statement explains the limits of that claim.

## Next contribution

Download the ceremony directory and register your public key and identity
under the open-participation rules. Extend this exact chain, publish your
signed attestation and the register revision used for acceptance. Newly
created signing keys are allowed. Do not replace the previous contribution.

Final acceptance still awaits independent participation, closing at the
announced height, the future beacon, and outside verification. No deployment
or address freeze has been performed.
