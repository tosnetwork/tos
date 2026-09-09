from pathlib import Path
import hashlib, json, subprocess, os, tempfile, shutil
repo=Path('/home/tomi/tos-m2'); out=repo/'doc/measurements/uno-m1-activation-context-43a0dc35e'
out.mkdir(exist_ok=False)
source='crypto/test/workchain_activation_control.py'; original=(repo/source).read_bytes()
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
blob=subprocess.check_output(['git','show',commit+':'+source],cwd=repo)
assert blob==original
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'source_commit':commit,'path':source,'git_blob_oid':subprocess.check_output(['git','rev-parse',commit+':'+source],cwd=repo,text=True).strip(),'original_sha256':sha(original),'scope':'Context schema unit controls only. Shared activation classification and its self-check remain pending. No live observations are synthesized as evidence.','events':[],'controls':[]}
def save(): (out/'measurement.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,argv):
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
 with (out/(label+'.stdout.log')).open('wb') as stdout,(out/(label+'.stderr.log')).open('wb') as stderr:
  p=subprocess.run([str(x) for x in argv],cwd=repo,env=env,stdout=stdout,stderr=stderr)
 report['events'].append({'label':label,'argv':[str(x) for x in argv],'exit':p.returncode});save();return p.returncode
runner=repo/'crypto/test/workchain-activation-context-selftest.py'
assert run('baseline',['python3',runner])==0
work=Path(tempfile.mkdtemp(prefix='uno-activation-shadow-'))
for identity in range(303,315):
 lines=[line for line in original.splitlines(keepends=True) if line.rstrip().endswith(f', {identity})'.encode())]
 assert len(lines)==1
 before=lines[0];after=f'    require(True, {identity})\n'.encode()
 assert original.count(before)==1
 mutant=original.replace(before,after)
 shadow=work/f'control-{identity}.py';shadow.write_bytes(original)
 assert shadow.read_bytes()==blob
 record={'identity':identity,'from':before.decode(),'to':after.decode(),'offset':original.index(before),'copy_before_sha256':sha(shadow.read_bytes()),'mutant_sha256':sha(mutant)}
 try:
  shadow.write_bytes(mutant)
  assert run(f'{identity}-compile',['python3','-m','py_compile',shadow])==0
  assert run(f'{identity}-mutant',['python3',runner,shadow])==1
  observed=json.loads((out/f'{identity}-mutant.stdout.log').read_text())
  assert observed['failures']==[identity],observed
  record['failed_vectors']=observed['failures']
 finally:
  shadow.write_bytes(original)
  assert shadow.read_bytes()==original==(repo/source).read_bytes()
 record['restored_sha256']=sha(shadow.read_bytes())
 record['restore_audit_sha256']=sha(shadow.read_bytes().replace(before,after))
 assert record['restore_audit_sha256']==record['mutant_sha256']
 assert run(f'{identity}-restored',['python3',runner])==0
 report['controls'].append(record);save()
assert run('probe',['/tmp/uno-publication-build/test-workchain-activation-control'])==0
rows=[line.split('\t') for line in (out/'probe.stdout.log').read_text().splitlines()]
assert [(r[0],r[1]) for r in rows]==[('0','0'),('0','1'),('1','0'),('1','1')]
assert [int(r[2]) for r in rows]==[-7201,-7201,-7201,0]
assert rows[0][4]==rows[2][4] and rows[1][4]==rows[3][4] and rows[0][4]!=rows[1][4]
report['probe']={'raw_rows':rows,'scope':'Production resolver result only; activation identity intentionally not classified until shared helper arrives. No transaction/export claims.'}
report['binary_sha256']=sha(Path('/tmp/uno-publication-build/test-workchain-activation-control').read_bytes())
report['original_source_unchanged']=(repo/source).read_bytes()==original
save()
shutil.copy2('/tmp/uno-publication-build/CMakeCache.txt',out/'CMakeCache.txt')
shutil.copy2(__file__,out/'reproduce-controls.py')
manifest={p.name:{'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(out.iterdir()) if p.is_file()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('12 isolated context controls restored; resolver observations recorded; shared classification pending')
