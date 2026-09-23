# Replacement phase-2 ceremony preparation — 2026-09-22

Base revision: `eb29e119f7f6ee19e74f9171dffcf17947a231a5` on
`feat/shielded-pool`. This check includes the local changes described below.
It is preparation for the first contribution, not a participant attestation
or production acceptance.

## Current state

The upstream branch has withdrawn the earlier ceremony and removed its files
from the working tree. Its artifacts remain in Git history. The replacement
has an announcement draft and roster template; no production ceremony has
been opened and no contribution is carried over.

The prior review's R1, R2 and R3 fixes are present: final transcript comparison,
reconstructed provenance/dimension checks, and digest-format validation before
display. The proof-point binding regression remains present. Secret input
buffers now use `Zeroizing` so ordinary error returns also wipe them. This
does not prove absence of compiler temporaries, process-memory copies or swap.

## Corrections made during preparation

1. **Resolve GPG before restricting the child environment.** The original
   verifier and test scaffolding searched only `/usr/bin:/bin` inside the
   isolated keyring environment. On this machine GPG is already installed at
   `/opt/homebrew/bin/gpg`, so the PGP cases failed with `FileNotFoundError`.
   Both now use the resolved executable path while retaining the isolated
   keyring. A missing verifier produces an explicit refusal. Test directory
   prefixes were shortened to accommodate the agent's Unix socket names on
   long system temporary paths.
2. **Require an actual boolean independence declaration.** The unmodified
   tool accepted the JSON string `"false"` as independent. A regression first
   demonstrated that an all-dependent control was refused, then showed that
   changing only the declaration's type made the verdict succeed. The roster
   loader now requires a JSON boolean, and the new test passes. This validates
   the declaration's type; it cannot establish whether the person is actually
   independent.
3. **Correct the announcement's timing claims.** The draft now distinguishes
   a scheduled height gap from a proof of unpredictability. The record has no
   timestamps and the CLI does not enforce a Bitcoin deadline. Publication
   evidence, a closed pre-beacon transcript, and external timing checks are
   explicitly required. Debug-formatting descriptions now accurately say that
   it prints a placeholder, rather than claiming all logging fails to compile.
   The code revision to build is also separated from the announcement's own
   publication commit, avoiding a self-referential commit-ID requirement.

## Validation

| Boundary | Check | Result |
|---|---|---|
| Ceremony crate and real phase-1 slice | `cargo test --release --locked --no-fail-fast --manifest-path tools/shielded-pool-ceremony/Cargo.toml` | 122 passed, 0 failed, 2 ignored |
| Formatting | `cargo fmt --all --check --manifest-path tools/shielded-pool-ceremony/Cargo.toml` | passed |
| Library lint gates | CI's strict `cargo clippy --locked --lib` invocation | passed |
| SSH/PGP signatures and roster independence | `python3 test/shielded-pool/verify-attestations-tests.py` | 23/23 passed |
| Participant instructions | `python3 test/shielded-pool/ceremony-docs-tests.py` | 4/4 passed |
| Mutation source anchors | `python3 test/shielded-pool/mutations-ceremony.py --check-anchors` | 45 anchors matched; this is not a mutation execution |
| Python syntax and whitespace | `py_compile`, `git diff --check` | passed |
| CLI rehearsal and R1–R3 rejection paths | `python3 test/shielded-pool/review-phase2-cli.py` | passed; all three malformed records refused; temporary artifacts removed |

The two ignored full-circuit tests were exercised in the earlier review; they
were not rerun by this default-suite invocation and are not counted as new
passes here. No secret-formatting mutation was run. Signing tests use temporary
keys under automatically cleaned temporary directories, never production
identity keys. No signing key material is retained in this report.

## Fixed schedule and remaining inputs (historical snapshot)

The prerequisites below describe the earlier fixed-roster draft. The operator
has since adopted open participation: new keys and later registration are
allowed, and outside verifiers need not be named before opening. See the
current announcement and runbook; these old prerequisites are not active gates.

The existing operator-confirmed schedule is unchanged: contributions close at
**970141**, beacon at **970285**. During this preparation, both Blockstream and
mempool.space returned tip **968129**, leaving 2012 and 2156 blocks respectively.
This is a point-in-time observation, not a calendar guarantee. Recheck both
sources before publication and before opening intake.

Still needed before a real first contribution:

- The first contributor's identity and at least one participant independent
  of the operator, with their existing public signing keys and provenance.
- The complete roster and its pinned digest, plus named outside verifiers.
- A clean, published code revision containing the preparation fixes; the
  draft's code-commit placeholder cannot safely name a dirty working tree.
- The announcement's publication destination and independent archive/receipt.
  The complete announcement must be publicly observable before production
  `phase2-begin` and contribution 1.

These inputs have been requested from the operator. No identities, signatures,
publication dates or archive URLs have been invented. The existing draft is
the reviewable announcement; its unresolved fields remain marked `TO FIX`.
No production contribution, finalisation, deployment or address freeze has
been performed.
