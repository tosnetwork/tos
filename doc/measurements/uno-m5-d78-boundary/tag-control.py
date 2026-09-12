import sys,pathlib,subprocess
sys.path.insert(0,'/tmp');import b_d75_helpers as h
h.root=pathlib.Path('/tmp/b-d78-boundary');h.repo=pathlib.Path('/home/tomi/tos')
p=h.root/'crypto/block/workchain-proof-work.h'
old=subprocess.check_output(['git','show','5f034af0f:crypto/block/workchain-proof-work.h'],cwd=h.repo,text=True)
assert old.count('uno-v2/withdrawal-statement/v2')==1
for mode in ('tag-good','tag-mutant','tag-restored'):
 p.write_text(old if mode!='tag-mutant' else old.replace('uno-v2/withdrawal-statement/v2','uno-v2/withdrawal-statement/v1'))
 h.compile(h.repo/'crypto/test/test-workchain-proof-work.cpp','test-workchain-block.cpp',h.root/'tag.o');h.link(h.root/'tag.o',h.root/mode)
 r=h.run(h.root/mode,'WithdrawalV2MatchesVersionedStatementBytes',mode)
 if mode=='tag-mutant':assert r.returncode==1 and 'bytes.substr(0, tag.size()) is not equal to tag' in r.stdout
 else:assert r.returncode==0
p.unlink()
