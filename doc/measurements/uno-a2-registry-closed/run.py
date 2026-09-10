import hashlib,json,os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent
binary=R/'bin/test-tos-collator'
symbols=[line.split()[-1] for line in subprocess.check_output(['nm',str(binary)],text=True).splitlines() if len(line.split())==3]
def one(pred):
    found=[s for s in symbols if pred(s)]
    assert len(found)==1,found
    return "*'"+found[0]+"'"
sites={
 'registry':one(lambda s:s.startswith('_ZNK') and '28validate_required_workchains' in s and '$_' not in s),
 'account_variant':one(lambda s:s.startswith('_ZZ') and '28validate_required_workchains' in s and s.endswith('clERKNS_31ResolvedWorkchainAccountBindingE')),
}
for key,owner,method in [('collator','Collator','do_collate_inner'),('validator_config','ValidateQuery','fetch_config_params'),('validator_ready','ValidateQuery','check_this_shard_mc_info'),('validator_transactions','ValidateQuery','check_transactions')]:
    sites['downstream_'+key]=one(lambda s:s.startswith('_ZZ') and owner in s and method in s and s.endswith('clERKN5block31ResolvedWorkchainAccountBindingE'))
source=R/'source/crypto/block/workchain-execution-dispatch.cpp'
lines=source.read_text().splitlines()
start=next(i for i,s in enumerate(lines) if 'td::Status WorkchainExecutionRegistry::validate_required_workchains(' in s)
line=next(i+1 for i in range(start,len(lines)) if '"multi-account admission and replay are not connected"' in lines[i])
sites['account_refusal']=str(source)+':'+str(line)
(R/'sites.json').write_text(json.dumps(sites,indent=2))
fixture=R/'fixture';fixture.mkdir();(fixture/'.counter-managed-v1').write_text('A-2 retained acceptance run; no lifecycle cleanup\n')
os.chmod(R/'wrapper.py',0o755)
cmd=['cmake','-DCOUNTER_FIXTURE_CHILD=ON','-DCOUNTER_FIXTURE_PATH='+str(fixture),'-DACCOUNT_BINDING_ONLY=ON','-DCREATE_STATE='+str(R/'bin/create-state'),'-DCOLLATOR='+str(R/'wrapper.py'),'-DSOURCE_DIR='+str(R/'source'),'-DBUILD_DIR='+str(R/'generated'),'-P',str(R/'source/test/test-counter-disk-integration.cmake')]
provenance={'tree':'63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8','a':'33af64ee8775e89035c5c364615ff6e3ada853a8','b':'203354611ba872d84687a1787bfdebf2cab5c730','binary_hashes':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary,R/'bin/create-state')},'command':cmd,'retention':'Explicit direct child execution in a unique directory outside lifecycle-managed build root; no default lifecycle code change. All successful and failed outputs retained.'}
provenance['generated_inputs']={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (R/'generated').rglob('*') if p.is_file()}
(R/'provenance.json').write_text(json.dumps(provenance,indent=2))
with (R/'driver.log').open('xb') as f:
    rc=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=240).returncode
print('driver exit',rc,flush=True)
raise SystemExit(rc)
