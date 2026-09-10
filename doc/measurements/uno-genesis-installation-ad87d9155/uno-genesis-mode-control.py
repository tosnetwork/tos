import hashlib,json,shlex,subprocess,tempfile
from pathlib import Path
repo=Path('/home/tomi/tos-m2');build=Path('/tmp/uno-publication-build');out=Path('/tmp/uno-genesis-mode-control-3');out.mkdir(exist_ok=False)
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
source='crypto/test/test-workchain-activation-control.cpp';original=subprocess.check_output(['git','show',f'{commit}:{source}'],cwd=repo)
assert (repo/source).read_bytes()==original
before='const bool old_version = argc == 2 && std::string(argv[1]) == "--old-version";'
after='const bool old_version = false;'
# Preserve argument acceptance separately: changing it too would prevent the
# probe from running. Instead change only the configured old version number.
before='old_version && !enabled ? 14 : 16';after='old_version && !enabled ? 16 : 16'
assert original.count(before.encode())==1
mutant=original.replace(before.encode(),after.encode());sha=lambda b:hashlib.sha256(b).hexdigest()
def run(name,cmd):
 r=subprocess.run(list(map(str,cmd)),cwd=build,capture_output=True)
 (out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
 return r
with tempfile.TemporaryDirectory(prefix='uno-mode-copy-') as temporary:
 temp=Path(temporary);copy=temp/Path(source).name;copy.write_bytes(original);assert copy.read_bytes()==original;copy.write_bytes(mutant)
 command_line=subprocess.check_output(['ninja','-C',str(build),'-t','commands','CMakeFiles/test-workchain-activation-control.dir/crypto/test/test-workchain-activation-control.cpp.o'],text=True).splitlines()[-1]
 cmd=shlex.split(command_line);oldobj=cmd[cmd.index('-o')+1];obj=temp/'probe.cpp.o';cmd[cmd.index('-o')+1]=str(obj)
 for flag in ['-MF','-MT']:
  if flag in cmd:cmd[cmd.index(flag)+1]=str(temp/('probe.d' if flag=='-MF' else 'probe.cpp.o'))
 cmd=[str(copy) if x==str(repo/source) else x for x in cmd];cmd+=['-I',str((repo/source).parent)]
 assert run('compile',cmd).returncode==0
 parts=shlex.split(subprocess.check_output(['ninja','-C',str(build),'-t','commands','test-workchain-activation-control'],text=True).splitlines()[-1]);assert parts[:2]==[':','&&'] and parts[-2:]==['&&',':'];link=parts[2:-2];binary=temp/'probe';link[link.index('-o')+1]=str(binary);assert oldobj in link;link=[str(obj) if x==oldobj else x for x in link];assert run('link',link).returncode==0
 r=run('mutant',['python3',repo/'crypto/test/workchain-genesis-activation.py','--repo',repo,'--probe',binary,'--mode','old-version','--evidence',out/'run'])
 # The controlled old-version configuration is now activated; the probe's
 # disabled-success stop 323 fires before any classifier can mislabel it.
 observation=json.loads('{}')
 assert r.returncode!=0
 raw=subprocess.run([str(binary),'--old-version'],cwd=build,capture_output=True)
 (out/'probe.stdout.log').write_bytes(raw.stdout);(out/'probe.stderr.log').write_bytes(raw.stderr)
 assert raw.returncode==323%256
 copy.write_bytes(original);assert copy.read_bytes()==original
 report={'commit':commit,'source':source,'from':before,'to':after,'original_sha256':sha(original),'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha(copy.read_bytes()),'restore_audit_sha256':sha(copy.read_bytes().replace(before.encode(),after.encode())),'compile_command':cmd,'link_command':link,'probe_stop_identity':323,'process_exit':raw.returncode,'scope':'Changing only the old-version input to version 16 makes it resolve successfully and trips the pre-existing disabled-success stop. It is an intentional mutation, not an unexpected baseline release.'}
restore=['cmake','--build',build,'--target','test-workchain-activation-control','-j32'];assert run('restored-target',restore).returncode==0
report['restored_target_command']=list(map(str,restore));report['source_unchanged']=(repo/source).read_bytes()==original;assert report['source_unchanged']
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
