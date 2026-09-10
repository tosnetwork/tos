from pathlib import Path
import subprocess,os,json,hashlib
source=Path('/tmp/tos-tol-stdlib-source');build=Path('/tmp/tos-tol-stdlib-build');repo=Path('/home/tomi/tos-m2')
out=Path('/tmp/tos-tol-stdlib-evidence/control');out.mkdir(exist_ok=False)
p=source/'CMakeLists.txt'; original=p.read_bytes();h=lambda b:hashlib.sha256(b).hexdigest()
assert source.resolve()!=repo.resolve() and original==(repo/'CMakeLists.txt').read_bytes()
assert original==subprocess.check_output(['git','show','HEAD:CMakeLists.txt'],cwd=source)
assert not (source/'build').exists()
needle=b'                "TOL_STDLIB=${CMAKE_CURRENT_SOURCE_DIR}/crypto/smartcont/tol-stdlib"\n'
assert original.count(needle)==1
mutant=original.replace(needle,b'')
env=os.environ.copy()
for n in ['FUNC_BIN','FIFT_BIN','TOL_STDLIB']:env.pop(n,None)
def run(name,cmd):
 with (out/(name+'.stdout')).open('wb') as so,(out/(name+'.stderr')).open('wb') as se:
  r=subprocess.run(cmd,stdout=so,stderr=se,env=env)
 raw=(out/(name+'.stdout')).read_text()+(out/(name+'.stderr')).read_text()
 return r.returncode,raw
names=['jetton-minter-tol.boc','jetton-wallet-tol.boc','wallet-v5-tol.boc','slice5-receive-context-tol.boc','tos-report-bond-oracle.boc']
files=[build/'slice1-gas-parity'/n for n in names]
baseline={str(f):h(f.read_bytes()) for f in files}
report={'original_sha256':h(original),'mutant_sha256':h(mutant),'targets':[],'baseline_outputs':baseline}
try:
 p.write_bytes(mutant)
 rc,_=run('mutant-configure',['cmake','-S',str(source),'-B',str(build),'-DUNO_CRYPTO_BUILD_JOBS=32']);assert rc==0
 for f in files:f.unlink()
 for t in ['slice1_gas_parity_contracts','slice5_receive_context_contract','tos_report_bond_oracle_contract']:
  rc,raw=run(t+'-mutant',['cmake','--build',str(build),'--target',t,'-j32'])
  assert rc!=0 and 'Failed to discover Tol stdlib.' in raw
  assert 'required compiler is unavailable' not in raw
  report['targets'].append({'name':t,'exit':rc,'exact_failure':'Failed to discover Tol stdlib.'})
finally:
 p.write_bytes(original)
 rc,_=run('restore-configure',['cmake','-S',str(source),'-B',str(build),'-DUNO_CRYPTO_BUILD_JOBS=32']);assert rc==0
 rc,raw=run('restored-targets',['cmake','--build',str(build),'--target','slice1_gas_parity_contracts','slice5_receive_context_contract','tos_report_bond_oracle_contract','-j32']);assert rc==0,raw[-2000:]
assert p.read_bytes()==original==(repo/'CMakeLists.txt').read_bytes()
assert all(h(f.read_bytes())==baseline[str(f)] for f in files)
report.update(restored_sha256=h(p.read_bytes()),restored_exit=rc,all_five_outputs_byte_identical=True)
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: removed stdlib path fails all three generation targets; restored targets and five BOC hashes match')
