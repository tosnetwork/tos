# Authenticated absent-account import refusal

This bounded public corpus was captured from a fresh isolated VM16 chain with
source-bound f2d node tools. The same-target account proof establishes absence
and zero balance. The exact deployment message contains the original StateInit
and a public hexadecimal11 fixture signature. It was never broadcast.

The local recorded policy clock makes this replay deterministic. The current
one-shot simulator must return import_rejected with no transaction, fees, VM
exit code or post-state; exists=false and observed balance0 are derived from
authenticated absence, and no Account cell hash is invented. This case reaches
-701 because this address cannot pay import, but -701 generally is not a promise
of insufficient funds. No key material or node database is included.
