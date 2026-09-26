# A03 recoverable citations, not new runtime receipts

This data-only extension of `a03-known-unproven-state.json` adds N01/N03/N04/E05
from the fixed memo snapshot `ae2be260e355277893453d4883407d2b1feb06b6` and
Mac's minimum-mapping review. It preserves `accepted_ids=[]`.

Each new row distinguishes a cited original from a file verified today. No
historical raw file was replayed or rehashed by this edit. In particular N04's
empty old extraction lists are a recoverable mapping gap, not evidence that
the report's source/patch/binary/raw identities never existed. N03's flag-only
and direct missing-file controls remain separate. E05's actual argv and console
exit marker are available citations, while a separately frozen executable is
not asserted. N01's inferred shell/child exit is not promoted into a wrapper.

The earlier e61 schema receipt remains 23 tests/exit0 for control-source
validation only. This edit has only `git diff --check`; a finite data-validation
ticket must check row identities, citation existence and snapshot scope before
it can be called validated. It does not repeat the schema suite, generate
retrospective receipts or close A03/G-1. All 72-ID classification and unique
control reconstruction/actual absence remain the next bounded mapping work.
