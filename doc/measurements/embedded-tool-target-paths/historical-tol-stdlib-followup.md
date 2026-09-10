# Tol standard-library discovery: coordinator follow-up

This note supplements the historical build report without changing its logs or
recorded exit statuses. The coordinator supplied the following source review
on 2026-09-10:

- The test-tol CTest environment sets TOL_EXECUTABLE, FIFT_EXECUTABLE and
  FIFTPATH, but not TOL_STDLIB. The coordinator found no historical CMake
  registration of TOL_STDLIB.
- tol-tester.py invokes the compiler without handling standard-library discovery.
- tol/tol-main.cpp uses TOL_STDLIB when supplied; otherwise it searches relative
  to the launched executable. The reported failure means both routes failed.
- The repository library is crypto/smartcont/tol-stdlib, including common.tol;
  the executable-relative discovery does not resolve that repository layout.

Classification: an existing standard-library path-discovery defect, not a change
introduced by the Rust codec migration or the coordinator's earlier symlink-path
CMake invocation. The earlier phrase "standard-library discovery dependency"
describes the observed stop, not an unresolved attribution to operator error.
This attribution is the coordinator's source review, not a new historical search
performed by B.

For test-tol, the proposed repair is to add
TOL_STDLIB=${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/tol-stdlib to its existing
CTest ENVIRONMENT. That repair has not been made or validated in this unit.
Changing the CTest environment alone would not repair the separate default-all
Tol contract generation commands that failed in build attempt 2.

The isolated merged build completed only after explicit tool and standard-library
paths were supplied, as recorded in report.json. It is not evidence that the
unqualified default build or the unmodified test-tol registration is repaired.

The coordinator's next merged-regression checklist contains eleven tests: the
former nine Counter entries and the two config-presence-* entries. Every entry
must be re-evaluated on the actual merged tree, with zero deferred entries;
this build-only measurement did not execute that regression checklist.
