# CI roadmap

TOS is a public chain, so its CI is judged by what a defect can cost:
- a split chain or a crashed network first;
- then memory and concurrency faults that ordinary tests miss;
- then the integrity of what is released and the reviewability of the evidence;
- process hygiene last.

This roadmap orders the work by that cost. Platform coverage, the first step, is in
place: every platform builds and tests each relevant change through the platform matrix
(see `doc/ci-platform-scope.md`).

Every item ships the same way:
- a written plan agreed with the reviewer;
- an implementation whose new checks are each shown to fail when the thing they check is
  broken;
- verification on the exact commit;
- a draft pull request. The owner decides the merge.

## 1. Merge discipline

- `platform-gate` becomes a required check once it meets its promotion bar: ten
  consecutive green runs on `main`, over at least three days, counting only full-platform
  runs. This is an owner decision.
- A merge queue (`merge_group`) comes only after every workflow's checkout and
  event-specific script has been audited for its semantics, and the required checks are
  stable.
- **Quarantine policy.** A failing test may be quarantined only through a registry entry
  that carries:
  - a narrow scope;
  - an owner;
  - a tracking issue;
  - an expiry date;
  - the owner's explicit approval.

  A quarantined test still runs, and its result is still reported. An expired entry fails
  the workflow policy guard. Quarantine never applies to:
  - consensus correctness or deterministic-output failures;
  - sanitizer findings;
  - security regressions.

  A harness timing defect is told apart from a production failure before quarantine is
  considered. Retrying until green is not evidence.

## 2. Cross-platform consensus determinism

- Every node must compute identical consensus results on every supported platform.
  Each platform member records the canonical outputs of deterministic consensus-relevant
  computations, using the existing fixtures:
  - block and transaction execution of a frozen fixture chain;
  - cell and BOC serialisation round trips;
  - fee and storage functions over their vector files;
  - post-quantum signature verdicts over their vector files.
- Each manifest records the tested commit, the fixture hashes, the build configuration
  and a schema version.
- A committed **coverage table** names the computations each platform must report.
  Windows clients cover the VM and verification fixtures, without claiming validator
  coverage.
- The gate fails when a manifest is missing, duplicated, stale or incomplete. It also
  fails when any platform's output differs.
- It also fails when every platform agrees on a wrong answer: known expected results
  are checked, not only agreement.
- The gate keeps diagnostic output, not only hashes. A failure names the computation,
  the platforms, and the first divergent value.

## 3. Whole-tree sanitizers

- Nightly ASan + UBSan over the full CTest registry.
- A manifest of built and executed tests proves that "full" hides no missing binary and
  no exclusion. Every exclusion is listed with its reason.
- Instrumentation gaps across C, C++ and Rust dependencies are documented.
- The existing scoped sanitizer jobs stay per change.

## 4. Fuzzing of untrusted inputs

- **Ingress first:**
  - the HTTP and JSON-RPC parsers;
  - BOC and cell deserialisation;
  - ADNL, RLDP2, overlay and QUIC frame envelopes.

  TL schemas and stateful protocol sequences follow.
- Each target has a committed seed corpus. Each asserts resource limits and progress, not
  only the absence of crashes.
- Each run reports execution and coverage counts, so a target that does nothing cannot
  pass.
- Short sanitizer-instrumented runs per relevant change; longer nightly runs with the
  corpus carried forward.
- Every crash, timeout or memory blow-up is minimised and committed as a regression
  input. It is then replayed through the production path before the finding is closed.
- The existing Rust fuzz targets join the nightly lane.

## 5. Concurrency

- Focused ThreadSanitizer runs on representative actor, consensus and network workloads.
- Platform limitations are stated, and every suppression is narrow and justified.

## 6. Release integrity and supply chain

- **Reproducible builds:** each release platform and toolchain builds twice, on isolated
  clean builders with pinned inputs. The unsigned payloads are compared before signing,
  and the published payload is verified to match the reproduced one.
- The comparison receipt goes into the release provenance; an attestation alone does not
  prove reproducibility.
- A software bill of materials and dependency review for every release.

## 7. Coverage, static analysis and performance

- **Coverage:** an informational trend, reported separately for the consensus and ingress
  boundaries.
- **Static analysis:** clang-tidy and CodeQL analyse whole translation units, and new
  findings are filtered against a recorded baseline.
- **Benchmarks:** a stored trend that alerts on a regression beyond a noise band.
