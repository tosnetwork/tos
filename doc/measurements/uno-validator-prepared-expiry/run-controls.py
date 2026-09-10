from pathlib import Path
import subprocess,json,hashlib,re,xml.etree.ElementTree as ET,tempfile
repo=Path('/home/tomi/tos-m2');out=Path(tempfile.mkdtemp(prefix='uno-prepared-expiry-'));copy=out/'source';build=out/'ctest'
build.mkdir()
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
subprocess.run(['git','worktree','add','--quiet','--detach',str(copy),commit],cwd=repo,check=True)
path='validator/impl/validate-query.cpp';original=subprocess.check_output(['git','show',commit+':'+path],cwd=repo)
assert original==(repo/path).read_bytes()==(copy/path).read_bytes()
reg=json.loads(Path('/tmp/b-expiry-registration.json').read_text());assert len(reg['tests'])==1
base=reg['tests'][0]['command'];command=[x.replace(str(repo),str(copy)) for x in base]
assert command[command.index('--probe')+1]==base[base.index('--probe')+1]
(build/'CTestTestfile.cmake').write_text('add_test(test-workchain-validator-local-visitors '+ ' '.join(json.dumps(x) for x in command)+')\nset_tests_properties(test-workchain-validator-local-visitors PROPERTIES TIMEOUT 60)\n')
sha=lambda x:hashlib.sha256(x).hexdigest()
r={'source_commit':commit,'path':path,'original_sha256':sha(original),'git_blob_oid':subprocess.check_output(['git','rev-parse',commit+':'+path],cwd=repo,text=True).strip(),'original_registered_command':base,'isolated_registered_command':command,'native_probe_sha256':sha(Path(base[base.index('--probe')+1]).read_bytes()),'scope':'Source expiry guard via registered test command relocated to isolated committed source; no production execution reachability or compiled mutant claim. The production cpp is read as text only. No native executable consumes mutated cpp; no mutant native target exists to restore. The unchanged private executable was explicitly rebuilt before the baseline.','controls':[]}
def run(name):
 xml=out/(name+'.xml');cmd=['ctest','--test-dir',str(build),'--output-on-failure','--output-junit',str(xml)]
 p=subprocess.run(cmd,capture_output=True)
 (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
 rows=list(ET.parse(xml).getroot().iter('testcase'));assert len(rows)==1 and rows[0].find('skipped') is None
 text=rows[0].findtext('system-out','')
 ids=[json.loads(line)['failure_identity'] for line in text.splitlines() if line.startswith('{"failure_identity":')]
 return p.returncode,ids,rows[0].find('failure') is not None
assert run('baseline')==(0,[],False)
s=original.decode()
for name,identity,replacement in [('custom',1350,'return false;'),('ready',1351,'return td::Status::OK();')]:
 start=s.index(f'auto {name} = std::visit(td::overloaded(')
 arm=s.index('[](const block::ResolvedWorkchainAccountBinding&)',start)
 a=s.index('{',arm)+1;b=s.index('}',a)
 old=s[a:b];assert 'WorkchainExecutionFailure::LocalUnavailable' in old
 new='\n            '+replacement+'\n          '
 mutant=(s[:a]+new+s[b:]).encode()
 try:
  (copy/path).write_bytes(mutant)
  result=run(name+'-removed-refusal')
  assert result==(8,[identity],True),result
 finally:(copy/path).write_bytes(original)
 assert run(name+'-restored')==(0,[],False)
 r['controls'].append({'name':name,'offset':a,'from':old,'to':new,'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha((copy/path).read_bytes()),'restore_audit_sha256':sha((copy/path).read_bytes()[:a]+new.encode()+(copy/path).read_bytes()[b:]),'ctest_exit':8,'failure_identity':identity,'restored_ctest_exit':0})
assert original==(repo/path).read_bytes()
r['main_source_unchanged']=True
(out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
print(out)
print('PASS: baseline 0; custom removal 1350 only; ready removal 1351 only; each restored 0')
