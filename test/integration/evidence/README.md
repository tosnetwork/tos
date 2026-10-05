# Integration evidence

| File | What it records |
| --- | --- |
| [wc0-index-apply-latency.json](wc0-index-apply-latency.json) | Apply and hook latency with the wallet index off, on, and slow, on a live local chain (runner: `../wc0_index_apply_latency.py`). **Read with [the handoff addendum](wc0-index-apply-readback-addendum.md):** this run did not cover an apply without block data in hand; the addendum does. |
| [wc0-index-apply-readback-addendum.md](wc0-index-apply-readback-addendum.md) | An apply without block data in hand: ApplyBlock makes no read for the index; the worker reads. Claim, scope, command and result index. |
| [wc0-index-apply-readback-968992c50.json](wc0-index-apply-readback-968992c50.json) | The complete raw output behind the addendum's current measurement. |
| [wc0-index-apply-readback-b8a3f5350.json](wc0-index-apply-readback-b8a3f5350.json) | Raw output of the earlier measurement, when ApplyBlock still read the block back and waited for it; kept as the record of that run. |
