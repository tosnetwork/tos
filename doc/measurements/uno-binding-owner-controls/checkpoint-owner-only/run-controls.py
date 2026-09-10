import hashlib, json, pathlib, subprocess, tempfile

repo = pathlib.Path('/home/tomi/tos')
out = pathlib.Path(tempfile.mkdtemp(prefix='uno-binding-owner-controls-'))
paths = ['crypto/block/workchain-account-binding-owner.h',
         'validator/impl/collator-impl.h', 'validator/impl/collator.cpp',
         'crypto/test/test-workchain-settlement-continuation.cpp']
originals = {p:(repo/p).read_bytes() for p in paths}
digest = lambda b: hashlib.sha256(b).hexdigest()
binary = repo/'build/test-workchain-settlement-continuation'
tool = subprocess.check_output(['which','apply_patch'],text=True).strip()
def patch(before,after):
    p = paths[0]
    assert (repo/p).read_bytes().count(before.encode()) == 1
    lines = '\n'.join('-'+x for x in before.splitlines())+'\n'+ '\n'.join('+'+x for x in after.splitlines())
    text = '*** Begin Patch\n*** Update File: '+str(repo/p)+'\n@@\n'+lines+'\n*** End Patch\n'
    subprocess.run([tool],input=text,text=True,check=True,capture_output=True)
def run(args, stem):
    with (out/(stem+'.stdout')).open('wb') as stdout, (out/(stem+'.stderr')).open('wb') as stderr:
        return subprocess.run(args,cwd=repo,stdout=stdout,stderr=stderr).returncode
build = ['cmake','--build','build','--target','test-workchain-settlement-continuation','test-tos-collator','-j32']
controls = [
 ('adapter-release','    owner->adapter_.reset();','    // mutation: omit adapter release', 'owner.release_adapter_before_binding'),
 ('always-reject','    TRY_RESULT(adapter, ConfiguredWorkchainAccountEngine::bind(binding));',
  '    return td::Status::Error("mutation: reject every binding");\n    TRY_RESULT(adapter, ConfiguredWorkchainAccountEngine::bind(binding));', 'owner.bind_positive')]
records=[]
print(out,flush=True)
for name,before,after,assertion in controls:
    assert all((repo/p).read_bytes()==v for p,v in originals.items())
    record=dict(name=name,path=paths[0],before=before,after=after,expected_assertion=assertion,
        base_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        original_sha256={p:digest(v) for p,v in originals.items()},build_command=build,
        run_command=[str(binary)],actual_executables=['test-workchain-settlement-continuation','test-tos-collator'])
    try:
        patch(before,after)
        assert (repo/paths[0]).read_bytes()==originals[paths[0]].replace(before.encode(),after.encode())
        record['mutant_sha256']=digest((repo/paths[0]).read_bytes())
        record['build_exit']=run(build,name+'.build'); assert record['build_exit']==0
        record['mutant_binary_sha256']=digest(binary.read_bytes())
        record['run_exit']=run([str(binary)],name+'.run')
        assert record['run_exit']==1
        assert assertion in (out/(name+'.run.stderr')).read_text()
    finally:
        if (repo/paths[0]).read_bytes()!=originals[paths[0]]:
            patch(after,before)
        assert all((repo/p).read_bytes()==v for p,v in originals.items())
        record['restored_sha256']={p:digest((repo/p).read_bytes()) for p in paths}
        record['restore_build_exit']=run(build,name+'.restore-build')
        assert record['restore_build_exit']==0
        record['restored_binary_sha256']=digest(binary.read_bytes())
        record['restored_run_exit']=run([str(binary)],name+'.restored-run')
        assert record['restored_run_exit']==0
        (out/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    records.append(record)
    print(name,'red and restored',flush=True)
(out/'restore-audit.json').write_text(json.dumps(records,indent=2)+'\n')
