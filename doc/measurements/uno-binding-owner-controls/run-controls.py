import hashlib, json, pathlib, subprocess, tempfile

repo = pathlib.Path('/home/tomi/tos')
out = pathlib.Path(tempfile.mkdtemp(prefix='uno-binding-owner-controls-'))
paths = ['crypto/block/workchain-account-binding-owner.h',
         'validator/impl/collator-impl.h', 'validator/impl/collator.cpp',
         'crypto/test/test-workchain-settlement-continuation.cpp',
         'crypto/block/workchain-account-candidate.h','validator/validator.h','validator/fabric.h']
originals = {p:(repo/p).read_bytes() for p in paths}
digest = lambda b: hashlib.sha256(b).hexdigest()
binary = repo/'build/test-workchain-settlement-continuation'
tool = subprocess.check_output(['which','apply_patch'],text=True).strip()
def patch(p,before,after):
    assert (repo/p).read_bytes().count(before.encode()) == 1
    lines = '\n'.join('-'+x for x in before.splitlines())+'\n'+ '\n'.join('+'+x for x in after.splitlines())
    text = '*** Begin Patch\n*** Update File: '+str(repo/p)+'\n@@\n'+lines+'\n*** End Patch\n'
    subprocess.run([tool],input=text,text=True,check=True,capture_output=True)
def run(args, stem):
    with (out/(stem+'.stdout')).open('wb') as stdout, (out/(stem+'.stderr')).open('wb') as stderr:
        return subprocess.run(args,cwd=repo,stdout=stdout,stderr=stderr).returncode
def force_objects(source, stem):
    # Remove only compiler-produced objects known by Ninja to depend on the
    # changed source. A concurrent earlier compiler can otherwise finish after
    # a header edit and make its stale output look newer than that header.
    deps=subprocess.check_output(['ninja','-C','build','-t','deps'],cwd=repo,text=True)
    obj=None; affected=[]
    for line in deps.splitlines():
        if ': #deps ' in line:
            obj=line.split(': #deps ',1)[0]
        elif obj and line.strip()==str(repo/source):
            affected.append(obj)
    assert affected, source
    affected=sorted(set(affected))
    for obj in affected:
        target=(repo/'build'/obj).resolve()
        assert target.is_relative_to((repo/'build').resolve()) and target.suffix=='.o', target
        if target.exists(): target.unlink()
    (out/(stem+'.forced-objects.json')).write_text(json.dumps(affected,indent=2)+'\n')
build = ['cmake','--build','build','--target','test-workchain-settlement-continuation','test-tos-collator','-j32']
controls = [
 ('adapter-release',paths[0],'    owner->adapter_.reset();','    // mutation: omit adapter release', 'owner.intermediate_count_sample'),
 ('always-reject',paths[0],'    TRY_RESULT(adapter, ConfiguredWorkchainAccountEngine::bind(binding));',
  '    return td::Status::Error("mutation: reject every binding");\n    TRY_RESULT(adapter, ConfiguredWorkchainAccountEngine::bind(binding));', 'owner.bind_positive')]
controls += [
 ('carrier-swap',paths[4],
  '      : candidate_(std::move(candidate)), declarations_(std::move(declarations)) {}',
  '      : candidate_(std::move(declarations)), declarations_(std::move(candidate)) {}', 'carrier.original_candidate'),
 ('carrier-declaration-default',paths[4],
  '      : candidate_(std::move(candidate)), declarations_(std::move(declarations)) {}',
  '      : candidate_(std::move(candidate)), declarations_(declarations.is_null() ? candidate_ : std::move(declarations)) {}','carrier.missing_declarations_preserved'),
 ('carrier-candidate-default',paths[4],
  '      : candidate_(std::move(candidate)), declarations_(std::move(declarations)) {}',
  '      : candidate_(candidate.is_null() ? declarations : std::move(candidate)), declarations_(std::move(declarations)) {}','carrier.missing_candidate_preserved')]
records=[]
print(out,flush=True)
for name,path,before,after,assertion in controls:
    assert all((repo/p).read_bytes()==v for p,v in originals.items())
    record=dict(name=name,path=path,before=before,after=after,expected_assertion=assertion,
        base_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        original_sha256={p:digest(v) for p,v in originals.items()},build_command=build,
        run_command=[str(binary)],actual_executables=['test-workchain-settlement-continuation','test-tos-collator'])
    try:
        patch(path,before,after)
        assert (repo/path).read_bytes()==originals[path].replace(before.encode(),after.encode())
        record['mutant_sha256']=digest((repo/path).read_bytes())
        force_objects(path,name+'.build')
        record['build_exit']=run(build,name+'.build'); assert record['build_exit']==0
        record['mutant_binary_sha256']=digest(binary.read_bytes())
        record['run_exit']=run([str(binary)],name+'.run')
        assert record['run_exit']==1
        assert assertion in (out/(name+'.run.stderr')).read_text()
    finally:
        if (repo/path).read_bytes()!=originals[path]:
            patch(path,after,before)
        assert all((repo/p).read_bytes()==v for p,v in originals.items())
        record['restored_sha256']={p:digest((repo/p).read_bytes()) for p in paths}
        force_objects(path,name+'.restore-build')
        record['restore_build_exit']=run(build,name+'.restore-build')
        assert record['restore_build_exit']==0
        record['restored_binary_sha256']=digest(binary.read_bytes())
        record['restored_run_exit']=run([str(binary)],name+'.restored-run')
        assert record['restored_run_exit']==0
        (out/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    records.append(record)
    print(name,'red and restored',flush=True)
(out/'restore-audit.json').write_text(json.dumps(records,indent=2)+'\n')
