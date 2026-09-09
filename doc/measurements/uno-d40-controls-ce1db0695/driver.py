import pathlib,subprocess,hashlib,json,os
repo=pathlib.Path('/home/tomi/tos-m2'); source=repo/'crypto/block/workchain-instance-identity.cpp'; build='/tmp/uno-publication-build'
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(); original=subprocess.check_output(['git','show',commit+':crypto/block/workchain-instance-identity.cpp'],cwd=repo); assert source.read_bytes()==original
out=repo/'doc/measurements'/('uno-d40-controls-'+commit[:9]);out.mkdir(exist_ok=False)
h=lambda b:hashlib.sha256(b).hexdigest()
env=os.environ.copy();env.update(FUNC_BIN=build+'/crypto/func',FIFT_BIN=build+'/crypto/fift',TOL_STDLIB=str(repo/'crypto/smartcont/tol-stdlib'),CARGO_BUILD_JOBS='32')
cmd=['cmake','--build',build,'--target','tos_block','tos_validator','test-workchain-instance-identity','-j32']
binary=build+'/crypto/test-workchain-instance-identity'
def run(name,args):
 with (out/(name+'.stdout.log')).open('wb') as so,(out/(name+'.stderr.log')).open('wb') as se:
  code=subprocess.run(args,cwd=repo,env=env,stdout=so,stderr=se).returncode
 return dict(command=args,exit_code=code,stdout=name+'.stdout.log',stderr=name+'.stderr.log')
controls=[
 ('remove-full-root-check','if (expected->get_hash() != candidate->get_hash()) {','if (false) {',[(4,804),(5,805),(7,848)]),
 ('accept-missing-ledger','if (root.is_null()) return error(InstanceIdentityError::MissingLedger, "instance ledger is missing");','if (root.is_null()) { TRY_RESULT(empty, make_initial_workchain_instance_ledger()); return read_workchain_instance_ledger(empty); }',[(0,803)]),
 ('overwrite-issued-entry','value, vm::Dictionary::SetMode::Add)','value, vm::Dictionary::SetMode::Set)',[(0,846)]),
 ('use-current-descriptor','derive_workchain_instance_id(authenticated_genesis, workchain, *record)','derive_workchain_instance_id(authenticated_genesis, workchain, gen::WorkchainInstanceRecord::Record{record->instance_seq, descriptor->get_hash().bits()})',[(0,814)]),
 ('leak-failed-staging','if (instance_id != claimed_id) return error(InstanceIdentityError::IdentityMismatch, "instance identity differs");','if (instance_id != claimed_id) { const_cast<td::Ref<vm::Cell>&>(predecessor_ledger) = next; return error(InstanceIdentityError::IdentityMismatch, "instance identity differs"); }',[(0,808)]),
 ('reject-all-first-installations','return staged.ledger;','return error(InstanceIdentityError::SuccessorUnsupported, "first installation disabled");',[(0,840)]),
]
report=dict(source_commit=commit,source_path=str(source.relative_to(repo)),git_blob_oid=subprocess.check_output(['git','rev-parse',commit+':'+str(source.relative_to(repo))],cwd=repo,text=True).strip(),original_sha256=h(original),scope='Private configuration reconstruction/ledger controls. Not actual ValidateQuery invocation or collator installation acceptance. Root-check cases 4/5/7 exercise one shared guard. No deployment activation or successor support.',controls=[])
report['baseline']=run('baseline',[binary]);assert report['baseline']['exit_code']==0
for name,frm,to,cases in controls:
 assert original.count(frm.encode())==1
 mutant=original.replace(frm.encode(),to.encode()); c=dict(name=name,**{'from':frm,'to':to},original_sha256=h(original),mutant_sha256=h(mutant),runs=[])
 print('control',name,flush=True)
 try:
  source.write_bytes(mutant);c['build']=run(name+'-build',cmd);assert c['build']['exit_code']==0
  for case,identity in cases:
   r=run(name+'-case-'+str(case),[binary,str(case)]);r['case']=case;r['expected_failure_identity']=identity;c['runs'].append(r)
   assert r['exit_code']!=0
   assert ('failure_identity='+str(identity)+'\n').encode() in (out/r['stderr']).read_bytes()
 finally:
  source.write_bytes(original); c['restored_sha256']=h(source.read_bytes());c['restore_audit_sha256']=h(source.read_bytes().replace(frm.encode(),to.encode()));assert c['restored_sha256']==h(original) and c['restore_audit_sha256']==h(mutant)
  c['explicit_restored_targets']=['tos_block','tos_validator','test-workchain-instance-identity'];c['restore_build']=run(name+'-restore-build',cmd);assert c['restore_build']['exit_code']==0
  c['restored_run']=run(name+'-restored',[binary]);assert c['restored_run']['exit_code']==0
  report['controls'].append(c);(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS',len(report['controls']),'isolated source controls',flush=True)
