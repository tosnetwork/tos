import hashlib,json,pathlib,shutil,subprocess,tempfile,os,runpy
repo=pathlib.Path('/home/tomi/tos-m2'); out=pathlib.Path(tempfile.mkdtemp(prefix='uno-rust-codec-controls-'));copy=out/'source';copy.mkdir()
# Only the Rust workspace and the complete input set of the static guard are copied.
shutil.copytree(repo/'tosctl/src',copy/'tosctl/src',ignore=shutil.ignore_patterns('target','.git'))
for p in ['crypto/block/block-auto.h','crypto/block/block.tlb','crypto/test/workchain-wire-representations.json','crypto/test/workchain-handwritten-tags.py','test/test-counter-disk-integration.cmake','test/tostester/src/pytosiq_core/tlb/block.py']:
 q=copy/p;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(repo/p,q)
p='tosctl/src/block/src/master.rs';orig=(repo/p).read_bytes();commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();assert subprocess.check_output(['git','show',commit+':'+p],cwd=repo)==orig
sha=lambda b:hashlib.sha256(b).hexdigest()
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(out/'target')
# Reuse compiled dependency artifacts only; Cargo explicitly rebuilds the changed test target each time.
shutil.copytree(repo/'tosctl/src/target',out/'target')
report={'commit':commit,'path':p,'original_sha256':sha(orig),'source_copy':str(copy),'build_targets':['chain_block library and unit-test executable'], 'controls':[]}
def run(label,args,cwd):
 r=subprocess.run(args,cwd=cwd,env=env,capture_output=True);(out/(label+'.stdout.log')).write_bytes(r.stdout);(out/(label+'.stderr.log')).write_bytes(r.stderr);return r
cargo=['cargo','test','--manifest-path',str(copy/'tosctl/src/Cargo.toml'),'-p','chain_block','-j32','test_mc_state_extra']
def guard():
 try:runpy.run_path(str(copy/'crypto/test/workchain-handwritten-tags.py'))['check'](copy);return 0
 except Exception as e:
  if hasattr(e,'code'):return e.code
  raise
assert guard()==0
assert run('baseline',cargo,copy).returncode==0
mutations=[('retired-tag','const MC_STATE_EXTRA_TAG: u32 = 0x3214e578;','const MC_STATE_EXTRA_TAG: u32 = 0xcc26;',975),('omit-ledger-read','        self.workchain_instances = WorkchainInstanceLedger::construct_from_cell(cell1.checked_drain_reference()?)?;','        // Isolated control: leave the ledger unread.',977),('omit-ledger-write','        builder1.checked_append_reference(self.workchain_instances.serialize()?)?;','        // Isolated control: omit the ledger reference.',977)]
for name,old,new,expected in mutations:
 assert orig.count(old.encode())==1;mut=orig.replace(old.encode(),new.encode());(copy/p).write_bytes(mut)
 g=guard();assert g==expected,(name,g)
 build=run(name+'-build',cargo+['--no-run'],copy);assert build.returncode==0,name
 r=run(name,cargo,copy);assert r.returncode==101,name
 failed=[l.strip() for l in r.stdout.decode().splitlines() if l.startswith('    master::tests::')]
 assert any('test_mc_state_extra_instances_native_fixture' in l for l in failed),(name,failed)
 (copy/p).write_bytes(orig);assert (copy/p).read_bytes()==orig
 restored=run(name+'-restored',cargo,copy);assert restored.returncode==0
 assert guard()==0
 report['controls'].append({'name':name,'from':old,'to':new,'copy_before_sha256':sha(orig),'mutant_sha256':sha(mut),'restored_sha256':sha((copy/p).read_bytes()),'restore_audit_sha256':sha((copy/p).read_bytes().replace(old.encode(),new.encode())),'guard_failure_code':g,'compile_exit':build.returncode,'behavior_exit':r.returncode,'failed_tests':failed,'restored_exit':restored.returncode,'explicit_rebuild_command':cargo})
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
assert (repo/p).read_bytes()==orig
print(out)
