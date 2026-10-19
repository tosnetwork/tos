# Operator acceptance — contribution 4, BmswapProtocol

**Accepted 2026-09-23T06:15:38Z**, at Bitcoin height **968,230** on both
announced witnesses — below the announced close at 970,141 and the beacon at
970,285, neither of which had been reached.

This is the first contribution to this ceremony from a party outside the
operator, and it is what the final attestation gate has been waiting for. It
is **not** the end of the ceremony: registration stays open until the close,
the beacon has not been applied, and these are not final parameters.

## What the operator verified, independently

The participant's own checks are in their bundle and are worth reading, but
none of what follows is taken from them. Their data, our tools.

| | |
|---|---|
| Bundle SHA-256 | `f3065f74d72f50f7a6e5da3a685fe0804a8fa1a3cbf52d87b331d0851c3ca3e1`, as published |
| Archive shape | 35 regular files, no symlinks, no absolute paths, no `..`, no executable bits, normalised owner and timestamps |
| Inherited files | 15 files **byte-identical** to this branch: the announcement, the signed privacy provenance and its signature, `CONTRIBUTION-1..3.md`, the three earlier attestations and signatures, and the three earlier public keys |
| Chain growth | the official `contributions.bin` (2,016 bytes) is an **exact prefix** of theirs (2,688). The chain was appended to, not rewritten |
| Register | their `roster.json` is byte-identical to the published register at `424597fe05830222e4b43dd16b02d6cd75753674`, whose SHA-256 is `554b2ad454bbc67bcdb55858d286a5499002fe34c5e5c49899cd293866ce9372` — the value their attestation states |
| Mathematics | `phase2-verify` rebuilt the starting key from the committed phase-1 slice and matched the announced `018853105392e4e0…`; circuit 18,107 constraints, 19 instance variables; **the chain audits, 4 contributions** |
| Attestations | all four verified against the published register, each one's `contribution`, `transcript` and `starting key` bound to the record's own entry |
| Identity | the participant's gist publishes the key, the attestation and the signature **byte-identical** to the bundle's, and was created before the release |
| Key fingerprint | `SHA256:uzShqE56Dj55ta2LjFffVSISz9Lqrl2mILSxjhKXIsk`, matching the registered key and the attestation's own claim |

Resulting verifying key after four contributions:
`0a97861be68ae5c658badd95a3ee9451c0f75616840ed40adc1f10866454871a`.
Ceremony key file: `d44d89c01a2c18581018826d1a21e9bc37ab8641ffe00262bc3d8d7235806dc1`.

### Both instruments were made to fail first

A check that has not been seen to refuse is not evidence that anything was
checked.

- the contribution digest in `attestation-4.txt` was replaced with zeroes:
  `REFUSED: attestation-4.txt attests to contribution 0000000000000000 and the
  record's entry 4 is 246b9d7406a6b349`, exit 1;
- **one bit** was flipped in the middle of `key.bin`:
  `REFUSED: structure: reading key.bin: the input buffer contained invalid
  data`, exit 1.

Both refusals were produced against copies. The accepted artifacts are the
downloaded ones, unmodified.

## The independence declaration, and what it rests on

`verify-attestations.py` reports `independent participants: BmswapProtocol`,
and that sentence is worth reading carefully: the tool reads
`independent_of_operator` out of the register. **It reports a declaration; it
does not verify one.** No tool can.

What the participant disclosed themselves, unprompted, in the signed
attestation:

- independence is a participant declaration, not external verification;
- the account had repository administrator access at the time of signing;
- execution was delegated to an automated agent over SSH on a
  participant-designated VPS;
- the statement makes no claim of forensic proof that the scalar is absent
  from operating-system memory or provider snapshots. Swap was disabled and
  core dumps were disabled for the process; swap was restored afterwards and
  reported zero bytes used.

`CONTRIBUTION-4.md` records that access changed between the registration push
and the contribution push: the registration reached this branch, the
contribution push was refused with HTTP 403, and a permissions query then
showed read-only upstream access. The contribution was published in the
participant's fork for acceptance rather than pushed here. The signed bytes
were not altered to match the change, which is the correct handling: an
attestation describes what was true when it was signed.

**The operator has confirmed that BmswapProtocol is outside the TOS operating
team**, and the register's `independent_of_operator: true` is accepted on that
basis together with the disclosures above. A reader who does not take the
operator's word for it has everything needed to form their own view: the
declaration, the disclosures, the published identity, and this record.

What is still true of every contribution here, including this one, and is not
established by any artifact: that the participant drew their scalar
unpredictably and destroyed it. That rests on what they published about
themselves.

## Still outstanding

- the announced close at height 970,141, then the beacon at 970,285;
- registration remains open — a further independent contribution would
  strengthen the ceremony, and the count is not what the soundness argument
  turns on, but breadth of independence is;
- the deployment acceptance gate, which deploys a pool carrying exactly these
  bytes and requires it to accept a real transfer;
- `tosdev2` and `tosdev3` still carry no `published_at`, so their signatures
  verify but trace to nobody who can be asked. That is reported on every run
  and is not fixed by this acceptance.

The next participant continues from **this** result.
