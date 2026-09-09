import pathlib, subprocess, re, json, hashlib
root=pathlib.Path('/home/tomi/tos-m2')
out=pathlib.Path('/tmp/uno-b-sync-1422c3d2e')
build=pathlib.Path('/tmp/uno-publication-build')
binary=build/'test-workchain-block'
source=(root/'crypto/test/test-workchain-block.cpp').read_text()
names=['Test_WorkchainBlock_'+n for n in re.findall(r'TEST\(WorkchainBlock,\s*(\w+)\)',source)]
pair=['Test_WorkchainBlock_AggregateFeeSettlement','Test_WorkchainBlock_NativeDisposalEntry']
assert len(names)==len(set(names)) and all(n in names for n in pair)
report={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(), 'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'scope':'Existing regression rerun after reverse merge; no new guard or live I13e acceptance claim.', 'runs':{}}
base=[str(binary),'--filter','WorkchainBlock','--verbosity','0']
commands={'pair':base+sum((['--filter','-'+n] for n in names if n not in pair),[]),'full':base}
for label,argv in commands.items():
    with (out/(label+'.stdout.log')).open('wb') as stdout,(out/(label+'.stderr.log')).open('wb') as stderr:
        rc=subprocess.run(argv,cwd=build,stdout=stdout,stderr=stderr).returncode
    log=(out/(label+'.stderr.log')).read_text()
    running=re.findall(r'Running test (\S+)\.\.\.',log)
    passed=re.findall(r'(\d+) tests? passed',log)
    expected=pair if label=='pair' else names
    report['runs'][label]={'argv':argv,'cwd':str(build),'exit_code':rc,'running':running,'expected':expected,'passed_summary':passed}
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    assert rc==0,(label,rc)
    assert running==expected,(label,len(running),len(expected))
    assert passed and int(passed[-1])==len(expected),(label,passed)
    print(label,rc,len(running),flush=True)
(out/'CMakeCache.txt').write_bytes((build/'CMakeCache.txt').read_bytes())
for args,name in [(['git','status','--porcelain'],'source-status'),(['git','submodule','status'],'submodules'),(['/usr/bin/clang++','--version'],'compiler')]:
    p=subprocess.run(args,cwd=root,capture_output=True)
    (out/(name+'.stdout.log')).write_bytes(p.stdout)
    (out/(name+'.stderr.log')).write_bytes(p.stderr)
    assert p.returncode==0
