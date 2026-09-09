import hashlib,json,pathlib,subprocess,tarfile
root=pathlib.Path(__file__).resolve().parents[3];base=root/'doc/measurements/uno-m1-publication-recovery'
h=lambda b:hashlib.sha256(b).hexdigest()
summary={}
for directory in sorted(base.iterdir()):
 if not directory.is_dir() or not (directory/'artifact-manifest.json').exists():continue
 manifest=json.loads((directory/'artifact-manifest.json').read_text());seen=set()
 archive=directory/'logs.tar.zst'
 proc=subprocess.Popen(['zstd','-q','-d','-c',str(archive)],stdout=subprocess.PIPE)
 with tarfile.open(fileobj=proc.stdout,mode='r|') as tf:
  for member in tf:
   assert member.isfile();data=tf.extractfile(member).read();entry=manifest[member.name]
   assert entry['member']==member.name and h(data)==entry['sha256'] and len(data)==entry['bytes']
   seen.add(member.name)
 proc.stdout.close();assert proc.wait()==0
 for name,entry in manifest.items():
  if 'artifact' in entry:
   data=(directory/entry['artifact']).read_bytes();assert h(data)==entry['sha256'] and len(data)==entry['bytes'];seen.add(name)
 assert seen==set(manifest)
 report=json.loads((directory/'measurement.json').read_text()) if (directory/'measurement.json').exists() else {};controls=[]
 for c in report.get('controls',[]):
  source=c['committed_source'];blob=subprocess.check_output(['git','show',source['commit']+':'+source['path']],cwd=root)
  assert h(blob)==source['blob_sha256']==c['original_sha256']==c['copy_before_sha256']==c['restored_sha256']
  assert subprocess.check_output(['git','rev-parse',source['commit']+':'+source['path']],cwd=root,text=True).strip()==source['git_blob_oid']
  before=c['from'].encode();after=c['to'].encode();assert blob.count(before)==1 and blob.index(before)==c['offset']
  assert h(blob.replace(before,after))==c['mutant_sha256']==c['restore_audit_sha256']
  controls.append(c['name'])
 for e in report.get('events',[]):
  for s in ('stdout','stderr'):assert manifest[e['label']+'.'+s+'.log']['sha256']==e[s+'_sha256']
 summary[directory.name]={'manifest_members':len(manifest),'empty_stderr_members':sum(k.endswith('.stderr.log') and v['bytes']==0 for k,v in manifest.items()),'control_restore_chains':controls,'recorded_complete':report.get('source_files_unchanged',report.get('production_sources_unchanged',False))}
registration=json.loads((base/'registration-control/measurement.json').read_text())
blob=subprocess.check_output(['git','show',registration['commit']+':'+registration['path']],cwd=root)
assert h(blob)==registration['original_sha256']==registration['restored_sha256']
assert blob.count(registration['from'].encode())==1 and blob.index(registration['from'].encode())==registration['offset']
assert h(blob.replace(registration['from'].encode(),registration['to'].encode()))==registration['mutant_sha256']==registration['restore_audit_sha256']
assert registration['failed'] and not registration['skipped']
final=json.loads((base/'final-898b86953/measurement.json').read_text());assert len(final['controls'])==26 and final['source_files_unchanged'] and set(final['baseline'].values())=={0}
provenance=json.loads((base/'content-provenance-6ee1eb684/measurement.json').read_text())
assert provenance['production_sources_unchanged']
assert [provenance[s]['exit'] for s in ('baseline','replacement','restored')]==[0,230,0]
for name in ('original-component.boc','replacement-component.boc','stored-record.bin'):
 assert len({provenance[s]['artifacts'][name] for s in ('baseline','replacement','restored')})==1
for stage in ('baseline','replacement','restored'):
 values=provenance[stage]['artifacts'];obs=provenance[stage]['observation']
 assert values['original-component.boc']!=values['replacement-component.boc']
 assert values['released-component.boc']==values['original-component.boc' if stage=='replacement' else 'replacement-component.boc']
 assert obs['executions']==obs['substitutions']==1 and obs['stored_matches_replacement'] and obs['bindings_and_other_fields_unchanged']
(base/'reconstruction-audit.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS',[(k,len(v['control_restore_chains'])) for k,v in summary.items()])
