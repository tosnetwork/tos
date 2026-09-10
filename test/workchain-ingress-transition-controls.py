#!/usr/bin/env python3
"""Isolated exact-source controls for ingress continuity and activation."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

p=argparse.ArgumentParser()
p.add_argument('--build',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args();a.build=a.build.resolve();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=False)
repo=Path(__file__).resolve().parents[1]
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'commit':commit,'controls':[],'commands':[], 'scope':'Production predicates and real scoped resolver; no genesis, live validator, transactions or candidate exporter are simulated. Each replacement object precedes the original archive at link time; repository sources remain immutable.'}
def save(): (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,cmd,cwd=None):
 r=subprocess.run(cmd,cwd=cwd or a.build,capture_output=True)
 (a.out/(name+'.stdout.log')).write_bytes(r.stdout);(a.out/(name+'.stderr.log')).write_bytes(r.stderr)
 report['commands'].append({'name':name,'argv':cmd,'cwd':str(cwd or a.build),'exit':r.returncode});save();return r
specs=[
 ('remove-table-check','crypto/block/block.cpp','return td::Status::Error("native ingress table removed without an explicit migration rule");','return td::Status::OK();','test-workchain-ingress-transition',1231),
 ('remove-entry-check','crypto/block/block.cpp','return td::Status::Error("native ingress destination changed without an explicit migration rule");','return td::Status::OK();','test-workchain-ingress-transition',1232),
 ('remove-minimum-version','crypto/block/workchain-execution-dispatch.cpp','configuration.get_global_version() < kBlockTransitionMinGlobalVersion ||\n      !configuration.has_capability(tos::capBlockTransition)','false ||\n      !configuration.has_capability(tos::capBlockTransition)','test-workchain-activation-control','old-version'),
 ('remove-capability','crypto/block/workchain-execution-dispatch.cpp','configuration.get_global_version() < kBlockTransitionMinGlobalVersion ||\n      !configuration.has_capability(tos::capBlockTransition)','configuration.get_global_version() < kBlockTransitionMinGlobalVersion ||\n      false','test-workchain-activation-control','missing-capability')]
prefix = 'td::Status validate_workchain_block_activation(const block::Config& configuration) {\n  if ('
specs = [(name, source, prefix+before if source.endswith('dispatch.cpp') else before,
          prefix+after if source.endswith('dispatch.cpp') else after, target, expected)
         for name, source, before, after, target, expected in specs]
entries=json.loads((a.build/'compile_commands.json').read_text())
for name,source,before,after,target,expected in specs:
 original=subprocess.check_output(['git','show',f'{commit}:{source}'],cwd=repo)
 assert (repo/source).read_bytes()==original and original.count(before.encode())==1
 baseline=run(name+'-baseline',[str(a.build/target)])
 assert baseline.returncode==0
 directory=a.out/name;directory.mkdir();copy=directory/Path(source).name;copy.write_bytes(original)
 assert copy.read_bytes()==original
 mutant=original.replace(before.encode(),after.encode());copy.write_bytes(mutant)
 entry=next(x for x in entries if Path(x['file']).resolve()==repo/source)
 compile=shlex.split(entry['command']);compile[compile.index('-o')+1]=str(directory/'mutant.o');compile[compile.index('-c')+1]=str(copy);compile.append('-I'+str((repo/source).parent))
 assert run(name+'-compile',compile,Path(entry['directory'])).returncode==0
 line=subprocess.check_output(['ninja','-t','commands',target],cwd=a.build,text=True).splitlines()[-1]
 link=shlex.split(line.split('&&')[1].strip());link[link.index('-o')+1]=str(directory/target)
 # Definitions supplied by this single object prevent the archive's original
 # member from being selected, without rewriting any archive or build output.
 index=next(i for i,arg in enumerate(link) if arg.endswith('.a'))
 link.insert(index,str(directory/'mutant.o'))
 assert run(name+'-link',link).returncode==0
 observations={}
 if isinstance(expected,int):
  result=run(name+'-run',[str(directory/target)])
  rows=[list(map(int,line.split('\t'))) for line in result.stdout.decode().splitlines()]
  assert len(rows)==13 and result.returncode==1
  failures=[row[0] for row in rows if row[3]==0]
  assert failures==[expected]
  observations={'failed_assertions':failures,'passed_assertions':[row[0] for row in rows if row[3]==1]}
 else:
  for mode,args in [('missing-capability',[]),('old-version',['--old-version'])]:
   result=run(name+'-'+mode,[str(directory/target),*args])
   baseline_mode=run(name+'-'+mode+'-original',[str(a.build/target),*args])
   assert baseline_mode.returncode==0 and result.returncode==0
   original_rows=baseline_mode.stdout.decode().splitlines()
   mutant_rows=result.stdout.decode().splitlines()
   assert len(original_rows)==len(mutant_rows)==4
   # Only the registered/disabled final typed result can change. Other later
   # checks can still reject; the shared classifier must distinguish the site.
   changed=[i for i,(old,new) in enumerate(zip(original_rows,mutant_rows)) if old!=new]
   assert changed==([2] if mode==expected else [])
   observations[mode]={'exit':result.returncode,'changed_typed_rows':changed}
   consumer=run(name+'-'+mode+'-consumer',['python3',str(repo/'crypto/test/workchain-genesis-activation.py'),'--repo',str(repo),'--probe',str(directory/target),'--mode',mode,'--evidence',str(directory/(mode+'-consumer'))])
   assert (consumer.returncode != 0)==(mode==expected)
 copy.write_bytes(original)
 assert copy.read_bytes()==original and (repo/source).read_bytes()==original
 report['controls'].append({'name':name,'source':source,'from':before,'to':after,'original_sha256':sha(original),'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha(copy.read_bytes()),'restore_audit_sha256':sha(copy.read_bytes().replace(before.encode(),after.encode())),'observations':observations,'binary_sha256':sha((directory/target).read_bytes())});save()
# None of the production archives was overwritten. Explicitly rebuild every
# executable exercised above nevertheless; no aggregate-target assumption.
targets=['test-workchain-ingress-transition','test-workchain-activation-control']
assert run('restored-build',['cmake','--build',str(a.build),'--target',*targets,'-j32']).returncode==0
assert run('restored-ctest',['ctest','-R','^(test-workchain-ingress-transition|test-counter-activation-.*)$','--output-on-failure','--output-junit',str(a.out/'restored.xml')]).returncode==0
report['restored_targets']=targets;save()
print('PASS: independent table, entry, minimum-version and capability controls')
