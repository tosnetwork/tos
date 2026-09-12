exec(open('/tmp/b-d78-new/build.py').read().split('h.compile')[0])
p=h.root/'crypto/block/workchain-withdrawal-codec.h';p.parent.mkdir(parents=True,exist_ok=True)
original=(h.repo/'crypto/block/workchain-withdrawal-codec.h').read_text()
old='  TRY_RESULT(total, workchain_withdrawal_total({value.principal, value.costs.outward_fee_paid, 0})); (void)total;'
assert original.count(old)==1
p.write_text(original.replace(old,'  // Isolated mutation: omit record x+q overflow validation.'))
h.compile(h.repo/'crypto/test/test-workchain-withdrawal-codec.cpp','test-workchain-block.cpp',h.root/'record-mutant.o');h.link(h.root/'record-mutant.o',h.root/'record-mutant',h.root/'block-auto.o')
r=h.run(h.root/'record-mutant','RecordRoundtripAndPaidOutwardFee','record-mutant')
assert r.returncode!=0 and 'encode_workchain_withdrawal_record(value).is_error()' in r.stdout
p.unlink()
r=h.run(h.root/'test','WithdrawalCodec','restored-codec');assert r.returncode==0
