"""Isolated removal controls for the complete Withdrawal account codec."""
from pathlib import Path
import argparse, shlex, subprocess, tempfile
parser = argparse.ArgumentParser()
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
args = parser.parse_args(); repo=args.repo.resolve(); build=args.build.resolve()
source=repo/'crypto/test/test-workchain-withdrawal-codec.cpp'
header=repo/'crypto/block/workchain-withdrawal-account.h'
commands=subprocess.check_output(['ninja','-t','commands','crypto/test-workchain-withdrawal-codec'],cwd=build,text=True).splitlines()
compile_cmd=next(shlex.split(c) for c in commands if ' -c '+str(source) in c)
link_cmd=shlex.split(commands[-1])[2:-2]; oldobj=compile_cmd[compile_cmd.index('-o')+1]
mutations={
 'CombinedCapacity': '    if (account.schema_version != 3 || account.system_pending.size() + value.origin_pending.size() > 4)\n      return td::Status::Error("invalid Withdrawal account schema or system capacity");\n',
 'AccountBinding': '      if (record.source.workchain_id != account.address.workchain_id || record.source.account != account.address.account ||\n          record.source.instance != account.address.instance)\n        return td::Status::Error("Withdrawal record account binding mismatch");\n',
}
with tempfile.TemporaryDirectory(prefix='withdrawal-account-controls-') as directory:
 d=Path(directory); (d/'block').mkdir(); copied=d/source.name; copied.write_text(source.read_text())
 for name, removed in mutations.items():
  assert header.read_text().count(removed)==1
  (d/'block'/header.name).write_text(header.read_text().replace(removed,''))
  obj=str(d/(name+'.o')); binary=str(d/name)
  cmd=[str(copied) if x==str(source) else obj if x==oldobj else x for x in compile_cmd]
  cmd.insert(next(i for i,arg in enumerate(cmd) if arg.startswith('-I')), '-I'+str(d))
  cmd[cmd.index('-MF')+1]=str(d/(name+'.d'))
  subprocess.run(cmd,cwd=build,check=True,stdout=subprocess.DEVNULL)
  cmd=[obj if x==oldobj else x for x in link_cmd]; cmd[cmd.index('-o')+1]=binary
  subprocess.run(cmd,cwd=build,check=True,stdout=subprocess.DEVNULL)
  result=subprocess.run([binary,'--filter','AuthenticatedEnvelope'],cwd=d,text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  Path('/tmp/withdrawal-account-'+name+'-removal.log').write_text(result.stdout)
  expected='invalid Withdrawal account schema or system capacity' if name=='CombinedCapacity' else 'encode_workchain_withdrawal_account(value, 2).is_error()'
  assert result.returncode != 0 and expected in result.stdout, result.stdout
  print(name+': removed check => exit '+str(result.returncode),flush=True)
