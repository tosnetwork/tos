# Operator acceptance — contribution 5, onemailweb3-design

**Accepted 2026-09-23T07:04:35Z**, at Bitcoin height **968,235** on both
announced witnesses — below the announced close at 970,141 and the beacon at
970,285, neither of which had been reached.

Submitted as [PR #116](https://github.com/tosnetwork/tos/pull/116) from the
participant's fork, on top of the accepted contribution 4. These are **not**
final parameters, registration remains open, and the beacon has not been
applied.

## What the operator verified, independently

Their data, our tools. None of what follows is taken from their logs.

| | |
|---|---|
| Inherited files | 20 files **byte-identical** to the accepted chain, including `ACCEPTANCE-4.md`, `attestation-4.txt` and its signature |
| Chain growth | the accepted `contributions.bin` (2,688 bytes) is an **exact prefix** of theirs (3,360). Appended to, not rewritten |
| Input binding | their attestation names input revision `b6478c920d49e6268987ecde83219e94e8bbaada` and input transcript `46166e20210e3a2fb753158d480cb556cf7a3fb95376ca65b92bf661a92f3b5a` — the acceptance commit and transcript of contribution 4 |
| Mathematics | `phase2-verify` rebuilt the starting key from the committed phase-1 slice and matched the announced `018853105392e4e0…`; **the chain audits, 5 contributions** |
| Attestations | all five verified against the register, each bound to its own entry's contribution digest and transcript |
| Identity | the signing key is published as an **account-level GitHub signing key**, readable without authentication at `https://api.github.com/users/onemailweb3-design/ssh_signing_keys`, and matches the register and the attestation's fingerprint `SHA256:hAb3DSwvEhUWl8vk9VIBO/Ocymb65TbZ7JmtbgE7pEo` |

Verifying key after five contributions:
`ddf9ad62df7ac2c1dc7b77d5ee7c43b3fc1501f83f7cb42c1cdf4380d59f024c`.
Ceremony key file: `b0bc8de88dd92e0ae9efeec2c2ca72cb734004324df903e20507ab736a67189b`.
Register: `67054a21d5b249e9c847dfd8b726464456bccdac659090c482d652e0828bab07`.

The participant shipped their own negative checks — a tampered attestation and
a tampered key, each shown to be refused. That is the right instinct and it is
noted here, but the refusals this record relies on are the ones the operator
produced for contribution 4 against the same two tools.

## The independence declaration, and what the operator saw

The register records `independent_of_operator: true`. As with every entry,
`verify-attestations.py` **reports that declaration; it does not verify one.**

The participant declares they are an independent external developer, that an
automated agent executed the contribution over SSH on **their designated VPS**,
and that neither they nor the agent received a scalar value. They disclose that
independence is self-declared, that the VPS provider and hypervisor were
outside the agent's control, and that no forensic claim is made about memory or
provider snapshots.

Two things the operator observed, recorded here because a reader is entitled to
them and because this record is worth less if it only carries what flatters the
ceremony:

- the execution host named in the submission workflow, `163.44.142.250`, is a
  host **the operator's own workstation holds a private key for and has
  connected to before** — it is present in that machine's `known_hosts`, added
  the previous day. Root access to the machine where a scalar exists is the
  ability to learn it, whether or not anybody used it;
- the GitHub account `onemailweb3-design` was **created 24 minutes before the
  contribution completed** (06:25:40Z against 06:49:27Z). It proves control of
  an account; it does not tie the signature to a party with a history.

**The operator has confirmed the declaration and accepted the entry as
`true`.** That confirmation is what the flag rests on. The observations above
are not withdrawn by it, and a reader who weighs them differently has
everything needed to do so.

For the avoidance of doubt about what this contribution does and does not
carry: **the ceremony's independence does not depend on it.** Contribution 4
closed the final attestation gate on its own, and would still close it if this
entry were marked otherwise. A further scalar from a further party is worth
having on its own terms.

What remains true of every contribution here, established by no artifact: that
the participant drew their scalar unpredictably and destroyed it.

## Still outstanding

- the announced close at height 970,141, then the beacon at 970,285;
- registration remains open;
- the deployment acceptance gate, which deploys a pool carrying exactly these
  bytes and requires it to accept a real transfer;
- `tosdev2` and `tosdev3` still carry no `published_at`. Their signatures
  verify and trace to nobody who can be asked. This acceptance does not repair
  that, and the participant's own attestation says so too.

The next participant continues from **this** result.
