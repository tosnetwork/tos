from pathlib import Path
import subprocess,shutil,hashlib,re,json,sys
r=Path('/tmp/b-unknown-review');base=Path('/tmp/uno-m3-live-v909pwpk')
idtext=(r/'id.log').read_text();seq,root=re.search(r'PREDECESSOR seqno=(\d+) root=([A-F0-9]+)',idtext).groups()
filehash=hashlib.sha256((base/'debit-authenticated-block.boc').read_bytes()).hexdigest().upper()
previous=f'(2,8000000000000000,{seq}):{root}:{filehash}'
for mode,binary in [('normal','normal'),('no-count','no-count'),('restored','normal')]:
 if len(sys.argv)>1 and mode!=sys.argv[1]:continue
 f=r/('fixture-'+mode);f.mkdir()
 for name in ['prepare.cmake','.counter-managed-v1','zerostate.boc','operation.candidate.boc','operation.declarations.boc','global.json']:
  shutil.copyfile(base/name,f/name)
 (f/'accepted-block.id').write_text(previous)
 subprocess.run(['cp','-a','--reflink=auto',str(base/'unknown-enabled-db'),str(f/'db')],check=True)
 p=subprocess.run([str(r/binary),'--failed-unknown-control',str(f)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=120)
 (r/(mode+'-live.log')).write_text(p.stdout)
 print(mode,'exit',p.returncode,flush=True)
 for line in p.stdout.splitlines():
  if any(s in line for s in ['WORKCHAIN_UNKNOWN_ORIGIN','Check `','UNKNOWN_ORIGIN_CONTROL','observed unknown-origin']):print(line,flush=True)
 if mode=='no-count':assert p.returncode!=0 and 'unknowns ==' in p.stdout
 else:assert p.returncode==0
 assert (f/'unknown-enabled.result').read_text()=='collate -7201\n'
 assert (f/'unknown-enabled.result.message').read_text()=='unclassified workchain execution failure'
 assert 'transactions=0\n' in (f/'unknown-enabled.result.stats').read_text()
 assert not (f/'unknown-enabled.candidate').exists()
 assert (f/'unknown-enabled.calls.unknown-origin').read_text()==('0\n' if mode=='no-count' else '1\n')
 assert 'WORKCHAIN_UNKNOWN_ORIGIN boundary=collator-account-batch code=0 cause=injected unclassified failure after real Failed execution' in p.stdout
