# X02 545d4fb9b: directed 100% local isolation run

Fixed tracked source: `545d4fb9b4e2f831dff1f968630444ebc2087de6`.
One four-validator Stage A network was started at 2026-09-25 22:30:26 UTC
with `uv run python -u scripts/validator-election-stage-a.py --mode experiment
--stage a --base-port 26600 --rpc-base-port 27600 --duration-seconds 900
--output-root test/integration/.x02-stage-a-545d4fb9b-20260925`.
Run root: `test/integration/.x02-stage-a-545d4fb9b-20260925/20260925T223026Z/`.
The first `python3` attempt failed at import before a validator started because
that interpreter lacked `bitarray`; its raw console is
`test/integration/.x02-stage-a-545d4fb9b-20260925-console.log` (SHA-256
`304cd4a5429e87942dd1d8a592a25a8ea6acd318429a6f2de36dc7f7be140222`).
It is not a chain or fault-window result. The `uv` retry used the same commit.

Readiness was emitted at 22:34:09 UTC with a 22:49:09 primary deadline.
`readiness-manifest.json` SHA-256 is
`707fb627c6d88840a6658fadb5c3c95f536cabcf32c8028d3e632c7be9889909`.
Before any tc install, `x02_prepare_policy.py` froze `x02-policy.json` at
SHA-256 `72810eff6c07ff417743f4455cda79abbe54c9a8ee92709c7d93684afb380cec`.
It binds four distinct node DBs/PIDs/start ticks and 20 exact directed ADNL+QUIC
UDP edges. Initial PIDs were 2679801/2679803/2679805/2679807; each process
owned its ADNL UDP 26602/26605/26608/26611 and QUIC UDP
27602/27605/27608/27611 respectively. The pre-cut raw `ss -uapn` is
`x02-udp-precut.raw` (SHA-256
`15d0dda513c7beb59c30b4252e00bc15dc585b5490626610e23eae2a9d58976f`).
The frozen validator-engine executable SHA-256 is
`186fef777bba20168fb48efb43fd78d2945cb16a565a10630e165dc1bbabaa3a`;
the artifact snapshot manifest SHA-256 is
`94131aea8ee5d1e32e99207b2eee2404101d798187c49b6f1ad42fd1deed816b`.
`lo` initially had root `noqueue` and no egress filters.

The root runner used the frozen policy SHA and wrote `x02-directed/`;
its raw `result.json` reports `status=passed`,
42 events, nine snapshots, no error (SHA-256
`487560a202e75766600944f118663df2b6220a6445b41a4905b011f7012860c5`).
All 20 installs and 20 typed `flower` removals exited 0; no fallback cleanup
commands were needed. In the separate during-2/4 `tc -j -s` capture, all 20
handled rules had positive drops; `x02-filters-two-cut.raw` and the runner's
per-event pre/post tc bytes preserve exact counters. The post-run `lo` was
again root `noqueue` with empty egress filters; `cleanup.json` SHA-256 is
`8479425179ced46c8c97ca10dcbf8598505578bcd93cc0eca9da739443f60d01`.

Raw common heights: baseline H44; 3/4 H44→H47; after the predetermined
30-second drain, four 2/4 samples remained H48; recovery H47→H50. The
measured last-install-completion to first-2/4-start interval is 30.224713977 s.
The last remove completion to last raw recovery completion is 14.62274884 s.
At H49 all four raw headers agree on root
`4b4b76e42bf1cef119a728c8ea81347cb544782409caed566bb015a1aa54a96c`
and file `d2ab79957380b95fa48fd9824a796f274d30023bece43031cc17674f55b777ea`;
at H50 they agree on root
`f2364cbefa3fbd879d747a8f5a59bf09da84d0e5a836cb446b78ac6425eeb61f`
and file `862c692cc52a4ae388565ec0f2c7ac870a7edc9c5632e1f226d6f36275b4d329`.
The production-source verifier checks each raw RPC/header/native marker and
full-ID match; its independent invocation from the retained 56 directed files
returned `exit 0 / passed:true`, raw `x02-offline-recheck.raw` SHA-256
`116276daa7f2c63e6b579806f79c1354e71a2ed76a9118c20d068d62d3e07662`.
The 56-file `x02-directed-SHA256SUMS` SHA-256 is
`081300a868bb2be33b2e8b97a2cfb23f7d53d521a536a1a7a9f9e4940fc3be33`
and `sha256sum -c` passed for every file.

An independent read-only packet capture started before the first cut and was
stopped after recovery: `x02-oncut-dual-udp.pcap`, SHA-256
`3a9ab6b69558cdce30bd9d24d4468aca8f8be354c23287958625aecbd52d10a2`.
The capture command reported 288,028 captured packets and zero kernel drops;
the pcap file itself does not independently encode that kernel-drop count. This pcap is a
packet-head provenance witness; tc per-rule drop counters establish injection.

The enclosing Stage A 900-second experiment naturally reached
`validator_experiment_passed` at 23:04:09 UTC with zero outstanding allocations,
four elections, and twelve recoveries. Its `report.json` has `status=pass`,
`failures=[]`, and the same source commit (SHA-256
`628eb61ca24fc321301b9b7235fa9b666d75faea5dd7e7d07038972e1cf98ea9`).
The retry console SHA-256 is
`74eee1b9d80a38c5272c8830dfbae7802bb4782bcf4a4975dd566da8cd3e09fd`.
The enclosing process exit code was **not captured** after the session disconnected;
neither its report nor the runner's `status=passed` substitutes for a raw exit
receipt. No validator or runner process remains.

CC independently rehashed the originals and re-ran the fixed-source verifier
and eight positive controls: `/home/tomi/memo/pq-native/N6-CC-X02-545-INDEPENDENT-RAW-REVIEW-20260925.md`
(report SHA-256 `1d80defccdb4bb4c051b330007190f8c71dde866324d9aa51171b98ef757972e`).
That review supports only the single-host, four-validator, 100% directed-loss
slice. Mac's independent raw review and the supervisor's scope decision are
separate; partial packet loss, multi-host operation, and release-scale G-2
remain unproven. **X02 as a whole remains OPEN.**
