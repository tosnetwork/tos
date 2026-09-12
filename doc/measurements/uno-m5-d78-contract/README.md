# D78 handoff runner controls

Anchor a131b9bb / 187dbc79290d6816. Runner selftest 13/13, restored.log.
Isolated copies, not production edits:
- delete only bucket-disposition from TESTS: drop-bucket.log, exit1 at the
  independently named mandatory-item assertion;
- change only the required marker back to the prelock prefix: old-marker.log,
  exit1 at test_prelock_markers_do_not_certify_d78 (0 != 1).
The real runner against /home/tomi/tos/build exits1 HANDOFF_NOT_READY and names
missing current contracts (readiness.log). This is NOT a host verification pass.
The mocks in selftests establish runner behavior only, never actual execution
of custody/validator paths. Prior shortfall control is retired by design change,
not counted as newly passing or quietly omitted under an unchanged contract.
