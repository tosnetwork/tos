from pathlib import Path
import subprocess,hashlib,json
root=Path('/home/tomi/tos-m2'); build=Path('/tmp/uno-publication-build')
out=Path('/tmp/uno-d40-postzero/callsite-control');out.mkdir(exist_ok=False)
fixture=Path('/tmp/uno-d40-postzero/callsite')
sha=lambda b:hashlib.sha256(b).hexdigest()
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
source=root/'validator/impl/validate-query.cpp'; original=source.read_bytes()
assert original==subprocess.check_output(['git','show',commit+':'+str(source.relative_to(root))],cwd=root)
frm=b'auto delta = block::check_workchain_instance_ledger_delta(\n          expected.move_as_ok(), new_extra.r1.workchain_instances);'
to=b'auto delta = td::Status::OK();'
assert original.count(frm)==1
report={'commit':commit,'source':str(source.relative_to(root)),'from':frm.decode(),'to':to.decode(),'original_sha256':sha(original),'mutant_sha256':sha(original.replace(frm,to)),'scope':'Production check_mc_state_extra method with seeded private predecessor/candidate context and actual terminal typed-result handlers. Not full-block or live installation acceptance.'}
def run(name,args,cwd=root):
 r=subprocess.run(args,cwd=cwd,capture_output=True)
 (out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 return {'command':list(map(str,args)),'exit_status':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),'stdout':r.stdout.decode()}
def cases(label):
 result={}
 for mode in ['unchanged','corrupt']:
  errors=out/(label+'-'+mode+'-errors');errors.mkdir()
  result[mode]=run(label+'-'+mode,[str(build/'crypto/test-workchain-instance-callsite'),str(fixture/'zerostate.boc'),mode,str(errors)])
 return result
report['baseline']=cases('baseline');assert all(x['exit_status']==0 for x in report['baseline'].values())
try:
 source.write_bytes(original.replace(frm,to))
 report['mutant_build']=run('mutant-build',['cmake','--build',str(build),'--target','test-workchain-instance-callsite','-j32'])
 assert report['mutant_build']['exit_status']==0
 report['replacement']=cases('replacement')
 assert report['replacement']['unchanged']['exit_status']==0
 assert report['replacement']['corrupt']['exit_status']==1
 assert report['replacement']['corrupt']['stdout']=='final_typed_kind=0\n'
 assert b'failure_identity=931\n' in (out/'replacement-corrupt.stderr.log').read_bytes()
finally:
 source.write_bytes(original)
 report['restored_sha256']=sha(source.read_bytes())
 report['restore_audit_sha256']=sha(source.read_bytes().replace(frm,to))
 assert report['restored_sha256']==report['original_sha256']
 assert report['restore_audit_sha256']==report['mutant_sha256']
 # The explicit mutant binary and the production disk runner are rebuilt;
 # all-tests is deliberately not used as a substitute.
 report['restored_build']=run('restored-build',['cmake','--build',str(build),'--target','test-workchain-instance-callsite','test-tos-collator','-j32'])
 assert report['restored_build']['exit_status']==0
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
report['restored']=cases('restored');assert all(x['exit_status']==0 for x in report['restored'].values())
report['executable_leaves']=['crypto/test-workchain-instance-callsite','test-tos-collator']
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: only corrupt wc=3 case fails when production delta call is removed; restored')
