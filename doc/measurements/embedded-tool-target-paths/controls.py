from pathlib import Path
import os,subprocess,json,hashlib
source=Path('/tmp/uno-embedded-tool-path-source'); build=Path('/tmp/uno-embedded-tool-path-build')
repo=Path('/home/tomi/tos-m2');out=Path('/tmp/uno-embedded-tool-path-evidence/controls');out.mkdir(exist_ok=False)
p=source/'crypto/CMakeLists.txt'; original=p.read_bytes()
assert source.resolve()!=repo.resolve()
assert original==(repo/'crypto/CMakeLists.txt').read_bytes()
assert original==subprocess.check_output(['git','show','HEAD:crypto/CMakeLists.txt'],cwd=source)
assert not (source/'build').exists()
env=os.environ.copy()
for key in ['FUNC_BIN','FIFT_BIN','TOL_STDLIB']:env.pop(key,None)
h=lambda b:hashlib.sha256(b).hexdigest()
report={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),'cases':[]}
def run(label,cmd):
 with (out/(label+'.stdout')).open('wb') as so,(out/(label+'.stderr')).open('wb') as se:
  r=subprocess.run(cmd,env=env,stdout=so,stderr=se)
 return r.returncode,(out/(label+'.stdout')).read_text()+(out/(label+'.stderr')).read_text()
items=[('native-registry-v1','gen_fif_smartcont_auto_native_registry_code','native-registry-code.cpp'),('stablecoin-escrow-v1','gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v1','tos-service-stablecoin-escrow-v1.cpp'),('stablecoin-escrow-v2','gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v2','tos-service-stablecoin-escrow-v2.cpp')]
for label,target,cpp in items:
 artifact=build/'crypto/smartcont/auto'/cpp
 assert artifact.exists(),str(artifact)
 baseline=h(artifact.read_bytes())
 for variable,binary in [('FUNC_BIN','func'),('FIFT_BIN','fift')]:
  name=label+'-'+binary
  suffix='scripts/embed-tos-service-'+label+'.sh'
  # Alter only the tool argument in this script's own command, not its peers.
  text=original.decode();end=text.index(suffix);start=text.rindex('    COMMAND ',0,end)
  needle='"'+variable+'=$<TARGET_FILE:'+binary+'>"'
  fragment=text[start:end];assert fragment.count(needle)==1
  mutant=(text[:start]+fragment.replace(needle,'')+text[end:]).encode()
  p.write_bytes(mutant)
  try:
   rc,_=run(name+'-configure',['cmake','-S',str(source),'-B',str(build),'-DUNO_CRYPTO_BUILD_JOBS=32']);assert rc==0
   # Force this generation consumer; no stale output can satisfy the target.
   artifact.unlink(missing_ok=True)
   rc,raw=run(name+'-mutant',['cmake','--build',str(build),'--target',target,'-j32'])
   expected='required compiler is unavailable: '+str(source/'build/crypto'/binary)
   assert rc!=0 and raw.count(expected)==1,(name,rc,raw[-3000:])
   report['cases'].append({'name':name,'mutation_sha256':h(mutant),'original_sha256':h(original),'target':target,'exit':rc,'exact_diagnostic':expected})
  finally:
   p.write_bytes(original)
   rc,_=run(name+'-restore-configure',['cmake','-S',str(source),'-B',str(build),'-DUNO_CRYPTO_BUILD_JOBS=32']);assert rc==0
   rc,raw=run(name+'-restored',['cmake','--build',str(build),'--target',target,'-j32']);assert rc==0,raw[-3000:]
  assert h(artifact.read_bytes())==baseline
  report['cases'][-1].update(restored_sha256=h(p.read_bytes()),restored_artifact_sha256=baseline,restored_exit=rc)
  (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
assert p.read_bytes()==original==(repo/'crypto/CMakeLists.txt').read_bytes()
# Only command-generating CMake was mutated, not C++ or scripts. Actual consumers
# func/fift ran each time; each embedded CPP regeneration target was rebuilt.
print('PASS: six isolated tool-argument removals failed at their exact missing tool; all restored outputs equal baseline')
