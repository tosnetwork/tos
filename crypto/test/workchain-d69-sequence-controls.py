from pathlib import Path
import subprocess, shlex, tempfile, argparse
parser = argparse.ArgumentParser()
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
args = parser.parse_args()
repo=args.repo.resolve(); build=args.build.resolve()
source=repo/'crypto/test/test-workchain-withdrawal-codec.cpp'
header=repo/'crypto/block/workchain-system-origin.h'
commands=subprocess.check_output(['ninja','-t','commands','crypto/test-workchain-withdrawal-codec'],cwd=build,text=True).splitlines()
compile_cmd=next(shlex.split(c) for c in commands if ' -c '+str(source) in c)
link_cmd=shlex.split(commands[-1])[2:-2]; oldobj=compile_cmd[compile_cmd.index('-o')+1]
removed='    if (workchain_system_origin_sequence(origin) == 0)\n      return td::Status::Error("system origin requires issued sequence");\n'
assert header.read_text().count(removed)==1
with tempfile.TemporaryDirectory(prefix='d69-sequence-controls-') as directory:
 d=Path(directory); (d/'block').mkdir(); (d/'block'/header.name).write_text(header.read_text().replace(removed,''))
 for index, name in enumerate(['Deposit','Settlement','Sweep']):
  copied=d/source.name
  copied.write_text(source.read_text().replace('for (auto origin : origins)',f'for (auto origin : std::vector<WorkchainSystemOrigin>{{origins[{index}]}})'))
  obj=str(d/(name+'.o')); binary=str(d/name)
  cmd=[str(copied) if x==str(source) else obj if x==oldobj else x for x in compile_cmd]
  cmd.insert(next(i for i, arg in enumerate(cmd) if arg.startswith('-I')), '-I'+str(d)); cmd[cmd.index('-MF')+1]=str(d/(name+'.d'))
  subprocess.run(cmd,cwd=build,check=True,stdout=subprocess.DEVNULL)
  cmd=[obj if x==oldobj else x for x in link_cmd]; cmd[cmd.index('-o')+1]=binary
  subprocess.run(cmd,cwd=build,check=True,stdout=subprocess.DEVNULL)
  r=subprocess.run([binary,'--filter','ThreeMembersRequireSequence'],cwd=d,text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  Path('/tmp/d69-'+name+'-sequence-removal.log').write_text(r.stdout)
  assert r.returncode != 0 and 'missing.is_error()' in r.stdout, r.stdout
  print(name+': remove required sequence => exit '+str(r.returncode),flush=True)
