# Real payout recipient / return checkpoint

Specification at start: memo `17a7af4e`, SHA256 prefix `21bc8334ac1213b6`.
No independent prediction was read. This is not Failed settlement acceptance.

The prior x=137/q=100/b=23 accepted payout was delivered from a copy of its
accepted DB to a real wc0 block. Decoding the transaction matched the exact
payout hash and found Native **bounce nofunds**, with zero out_msgs. An overdue
masterchain block initially skipped the new top descriptor; the next actual
masterchain import supplied wc2 block 5. A successful empty recipient block was
not mistaken for receipt of the payout.

New explicit fixture: `test/uno-m3-live.py --m5-return-route --build BUILD`.
It retains the earlier mode/parameters and uses x=10000000, b=4000000 only for
this new route; q is still quoted from Native configuration (observed 100).
Prepare ON/OFF passed, then the accepted descriptor was imported into masterchain
and the real wc0 receiving block was produced and validated.

Observed fixture `/tmp/uno-m3-live-soe0qlkz`, log `/tmp/uno-m5-funded-route.log`:

- available 1000000000 -> 985999643; f=257.
- R_actual=R_book=989999643; N_hidden=985999643; P=10000000; W=14000000.
- payout `307C1D8830645D23C9088CF408B7DFD78C9FD4C52E322BB703794AAC86C3EEE9`.
- bounce `069445329E02EE497B4E49E875B655B9522202BD594E0216A7B9337726F7A2CF`.
- actual returned value **9996070**, original created_lt **16000002**.
- payout flags=3; rich original_body exactly matches the payout body;
  source/destination reversed. The bounce is read from serialized wc0 out_msgs,
  not synthesized for the helper.

The observation path checks block root/file hashes, exact input message identity,
transaction out_msgs, rich body and original LT. An unrelated actual payout was
substituted into an isolated observation fixture: the exact-message matcher
rejects instead of treating that block as a receipt. This is a routing/recipient
observation, not a custody final-import or atomic-settlement assertion. No split
wc0 claim is made. The funded route explicitly fails if no bounce is emitted.

Remaining integration blockers: the authenticated prepare record is phase 0;
the funded Failed helper currently accepts only phase 1, and no authenticated
queue-removal transition is installed. Owner clarification was requested about
direct matching Failed in phase 0 versus installing D73 queue observation first.
The test business codec also currently prohibits combining prepare and Failed
profiles. No phase/config state was forged to bypass either gap.

No production code or guard was changed. No Failed root publication, W/P release
or sequence advance is claimed. Contracts remain unfulfilled; unknown-source
counter is absent/unmeasured. D76 arrived during this checkpoint and takes
priority before continuing Failed.
