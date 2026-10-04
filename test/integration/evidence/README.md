# Integration evidence

| File | What it records |
| --- | --- |
| [wc0-index-apply-latency.json](wc0-index-apply-latency.json) | Apply and hook latency with the wallet index off, on, and slow, on a live local chain (runner: `../wc0_index_apply_latency.py`). **Qualified by [the read-back addendum](wc0-index-apply-readback-addendum.md):** when ApplyBlock lacks block data, apply completion waits for one block-data read, and this run did not measure that path. |
| [wc0-index-apply-readback-addendum.md](wc0-index-apply-readback-addendum.md) | The block-data read-back path: claim, scope, command and result index. |
| [wc0-index-apply-readback-b8a3f5350.json](wc0-index-apply-readback-b8a3f5350.json) | The complete raw output behind the addendum. |
