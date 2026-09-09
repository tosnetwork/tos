from pathlib import Path
import subprocess,json,hashlib,os,re,time
root=Path('/home/tomi/tos-m2');build=Path('/tmp/uno-publication-build');out=root/'doc/measurements/uno-m1-cadence-7008e8a40';out.mkdir(exist_ok=False)
env=dict(os.environ,FUNC_BIN=str(build/'crypto/func'),FIFT_BIN=str(build/'crypto/fift'))
source=root/'crypto/block/workchain-resource-policy.h';rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();original=source.read_bytes();assert original==subprocess.check_output(['git','show',rev+':crypto/block/workchain-resource-policy.h'],cwd=root)
hash=lambda b:hashlib.sha256(b).hexdigest()
def run(name,cmd):
 with (out/(name+'.stdout.log')).open('wb') as so,(out/(name+'.stderr.log')).open('wb') as se:r=subprocess.run(cmd,cwd=root,env=env,stdout=so,stderr=se)
 return {'command':cmd,'exit_code':r.returncode,'stdout':name+'.stdout.log','stderr':name+'.stderr.log'}
controls=[('omit-wire-field',b'  if (!tlb::pack_cell(result, record)) return td::Status::Error("cannot encode engine configuration");',b'  result = vm::CellBuilder().store_long(0x6e1fa05f, 32).store_ref(record.resource_policy).store_ref(record.parameters).finalize();',402),('discard-decoded-value',b'return WorkchainEngineParameters{record.k_accepted_target_rate_ms, std::move(resources), std::move(record.parameters)};',b'return WorkchainEngineParameters{0, std::move(resources), std::move(record.parameters)};',405)]
report={'source_commit':rev,'source_path':'crypto/block/workchain-resource-policy.h','original_sha256':hash(original),'controls':[],'current_cadence_substitution':{'status':'not constructible as a local substitution with the existing encoder inputs','reason':'Encoder accepts only explicitly supplied acceptance interval, resource policy and opaque business Cell. It has no Config/Param30/current-cadence parameter or lookup. No new current-config input is introduced for a mutation. Caller provenance/truthfulness is outside this guarantee.'}}
base=run('baseline',[str(build/'test-workchain-block'),'--filter','EngineConfigurationAcceptedCadence','--verbosity','0']);assert base['exit_code']==0;report['baseline']=base
for name,before,after,identity in controls:
 assert source.read_bytes()==original;assert original.count(before)==1;mutant=original.replace(before,after);record={'name':name,'from':before.decode(),'to':after.decode(),'original_sha256':hash(original),'mutant_sha256':hash(mutant),'expected_failure_identity':identity};targets=['tos_block','test-workchain-block']
 try:
  source.write_bytes(mutant)
  record['build']=run(name+'-build',['cmake','--build',str(build),'--target',*targets,'-j32']);assert record['build']['exit_code']==0,'build failure is not behavioral evidence'
  built=(out/record['build']['stdout']).read_text();targets=sorted(set(targets)|set(re.findall(r'CMakeFiles/([^/]+)\.dir/',built)))
  record['run']=run(name+'-run',[str(build/'test-workchain-block'),'--filter','EngineConfigurationAcceptedCadence','--verbosity','0']);combined=(out/record['run']['stdout']).read_text()+(out/record['run']['stderr']).read_text();assert record['run']['exit_code']!=0;assert re.search(r'\b'+str(identity)+r'\b',combined)
 finally:
  source.write_bytes(original);assert source.read_bytes()==original
  record['restored_sha256']=hash(source.read_bytes());assert source.read_bytes().count(before)==1
  record['restore_audit_sha256']=hash(source.read_bytes().replace(before,after));assert record['restore_audit_sha256']==record['mutant_sha256']
  record['explicit_restored_targets']=targets
  record['restore_build']=run(name+'-restore-build',['cmake','--build',str(build),'--target',*targets,'-j32']);assert record['restore_build']['exit_code']==0
  record['restore_run']=run(name+'-restore-run',[str(build/'test-workchain-block'),'--filter','EngineConfigurationAcceptedCadence','--verbosity','0']);assert record['restore_run']['exit_code']==0
  report['controls'].append(record);(out/'controls.json').write_text(json.dumps(report,indent=2)+'\n')
 print(name,'behavioral red',identity,'restored and explicitly rebuilt',targets,flush=True)
print('PASS: isolated controls and restoration audits',flush=True)
