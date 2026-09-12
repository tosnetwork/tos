import sys,pathlib,re,subprocess
sys.path.insert(0,'/tmp')
import b_d75_helpers as h
r=pathlib.Path('/tmp/b-shortfall-review');h.root=r;h.repo=pathlib.Path('/home/tomi/tos-m2')
h.cmds=[re.sub(r'/home/tomi/tos/(?!build(?:/|\s))','/home/tomi/tos-m2/',c) if ' -c ' in c else c for c in h.cmds]
h.cmds[-1]=h.cmds[-1].replace('uno/crypto/cargo-target/release/libtos_uno_crypto_prototype.a','/tmp/uno-merge-6ea2fbf80-tL5Uih/uno/crypto/cargo-target/release/libtos_uno_crypto_prototype.a')
header=r/'crypto/block/workchain-failed-funded.h'
original=subprocess.check_output(['git','show','82b53c675:crypto/block/workchain-failed-funded.h'],cwd=h.repo,text=True)
header.write_text(original)
s=pathlib.Path('/tmp/b-failed-review/parameter.cpp').read_text().replace('uno-m3-live-8x3sz5uk','uno-m3-live-6igzl00b')
s=s.replace('auto record=w0.control.withdrawals.front();','auto record=w0.control.withdrawals.front(); CHECK(record.costs.original_reserve==1000000);')
s=s.replace('auto receipt=w1.origin_pending.front();','auto receipt=w1.origin_pending.front(); CHECK(receipt.amount < record.principal);')
(r/'probe.cpp').write_text(s)
for mode in ['normal','remove-bound','old-rejection','restored']:
 changed=original
 if mode=='remove-bound':
  changed=changed.replace('if (cost > record.costs.original_reserve && (refundable_reserve != 0 || amount >= record.principal))','if (false)')
 if mode=='old-rejection':
  changed=changed.replace('__builtin_add_overflow(loss, fee, &cost) ||','__builtin_add_overflow(loss, fee, &cost) || cost > record.costs.original_reserve ||')
 header.write_text(changed)
 h.compile(r/'probe.cpp','test-workchain-block.cpp',r/'probe.o');h.link(r/'probe.o',r/mode,pathlib.Path('/tmp/b-fee-admission/backend.o'))
 p=h.run(r/mode,'FailedActualComponents',mode)
 if mode=='old-rejection':assert p.returncode!=0 and 'outcome.is_ok()' in p.stdout
 else:assert p.returncode==0
header.write_text(original)
