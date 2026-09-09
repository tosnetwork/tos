from pathlib import Path
import subprocess,json,hashlib,os,shutil,tempfile
repo=Path('/home/tomi/tos-m2'); owner=Path('/home/tomi/tos'); helper=owner/'crypto/test/workchain-activation-rejection.py'
helper_commit=subprocess.check_output(['git','log','-1','--format=%H','--','crypto/test/workchain-activation-rejection.py'],cwd=owner,text=True).strip()
assert helper_commit, 'shared helper must be committed before final evidence'
helper_blob=subprocess.check_output(['git','show',helper_commit+':crypto/test/workchain-activation-rejection.py'],cwd=owner)
assert helper.read_bytes()==helper_blob, 'shared helper working bytes differ from committed source'
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
out=repo/'doc/measurements'/('uno-m1-activation-consumer-'+commit[:9]);out.mkdir(exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'source_commit':commit,'helper_commit':helper_commit,'helper_path':str(helper),'helper_sha256':sha(helper_blob),'events':[],'scope':'Shared-helper integration and schema-consumer calibration with real resolver statuses. No live transaction/export or I13e acceptance claim.'}
def save(): (out/'measurement.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,args):
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
 with (out/(label+'.stdout.log')).open('wb') as stdout,(out/(label+'.stderr.log')).open('wb') as stderr:
  p=subprocess.run([str(a) for a in args],cwd=repo,env=env,stdout=stdout,stderr=stderr)
 report['events'].append({'label':label,'argv':[str(a) for a in args],'exit':p.returncode});save();return p.returncode
build=Path('/tmp/uno-publication-build')
assert run('configure',['cmake','-S',repo,'-B',build,'-DCMAKE_PROJECT_TOS_INCLUDE='+str(repo/'crypto/test/workchain-activation-control.cmake'),'-DWORKCHAIN_ACTIVATION_HELPER='+str(helper)])==0
assert run('build',['cmake','--build',build,'--target','test-workchain-activation-control','-j32'])==0
argv=['python3',repo/'crypto/test/workchain-activation-control-check.py','--probe',build/'test-workchain-activation-control','--repo',repo,'--shared-helper',helper]
assert run('baseline',argv)==0
# Only the consumer's required shared-classifier decision is removed. Both
# upstream classifier self-checks and real resolver observations remain unchanged.
work=Path(tempfile.mkdtemp(prefix='uno-activation-consumer-shadow-'))
report['sources']={}
for name in ['workchain-activation-context.py','workchain-activation-context-selftest.py','workchain-activation-control-check.py']:
 path='crypto/test/'+name;blob=subprocess.check_output(['git','show',commit+':'+path],cwd=repo)
 assert blob==(repo/path).read_bytes();(work/name).write_bytes(blob)
 report['sources'][path]={'sha256':sha(blob),'git_blob_oid':subprocess.check_output(['git','rev-parse',commit+':'+path],cwd=repo,text=True).strip()}
shadow=work/'workchain-activation-context.py';original=shadow.read_bytes()
before=b"    require(is_activation_rejection(closed['status_code'], closed['status_message'], boundary=boundary), 315)\n"
after=b'    require(True, 315)\n'
assert original.count(before)==1
mutant=original.replace(before,after)
control={'path':'crypto/test/workchain-activation-context.py','original_sha256':sha(original),'copy_before_sha256':sha(shadow.read_bytes()),'from':before.decode(),'to':after.decode(),'offset':original.index(before),'mutant_sha256':sha(mutant)}
try:
 shadow.write_bytes(mutant)
 assert run('mutant-compile',['python3','-m','py_compile',shadow])==0
 mutant_argv=argv.copy();mutant_argv[1]=work/'workchain-activation-control-check.py'
 assert run('mutant',mutant_argv)==1
 last=(out/'mutant.stderr.log').read_text().splitlines()[-1]
 assert json.loads(last)=={'guard':341},last
 control['failure_identity']=341
finally:
 shadow.write_bytes(original)
 assert shadow.read_bytes()==original==(repo/control['path']).read_bytes()
control['restored_sha256']=sha(shadow.read_bytes());control['restore_audit_sha256']=sha(shadow.read_bytes().replace(before,after))
assert control['restore_audit_sha256']==control['mutant_sha256'];report['control']=control;save()
assert run('restored',argv)==0
# Actual CTest dependency propagation: helper path is absent, but Python runs.
assert run('missing-helper-configure',['cmake','-S',repo,'-B',build,'-DWORKCHAIN_ACTIVATION_HELPER='+str(work/'missing-helper.py')])==0
assert run('missing-helper-ctest',['ctest','--test-dir',build,'-R','^test-workchain-activation-control-gates$','--output-on-failure','--output-junit',out/'missing-helper.xml'])!=0
import xml.etree.ElementTree as ET
cases=list(ET.parse(out/'missing-helper.xml').iter('testcase'))
assert len(cases)==1 and cases[0].find('failure') is not None and cases[0].find('skipped') is None
assert run('restore-configure',['cmake','-S',repo,'-B',build,'-DWORKCHAIN_ACTIVATION_HELPER='+str(helper)])==0
assert run('ctest',['ctest','--test-dir',build,'-R','^test-workchain-activation-control-gates$','--output-on-failure','--output-junit',out/'ctest.xml'])==0
cases=list(ET.parse(out/'ctest.xml').iter('testcase'));assert len(cases)==1 and cases[0].find('failure') is None and cases[0].find('skipped') is None
assert helper.read_bytes()==helper_blob
report['helper_unchanged']=True;report['original_source_unchanged']=(repo/control['path']).read_bytes()==original
report['binary_sha256']=sha((build/'test-workchain-activation-control').read_bytes());save()
shutil.copy2(build/'CMakeCache.txt',out/'CMakeCache.txt');shutil.copy2(__file__,out/'reproduce-controls.py')
manifest={p.name:{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(out.iterdir()) if p.is_file()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(out)
