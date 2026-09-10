import subprocess, pathlib, json, hashlib, xml.etree.ElementTree as ET, datetime
p=pathlib.Path('/tmp/uno-merged-eleven-audit'); b=pathlib.Path('/tmp/uno-merged-default-build'); s=pathlib.Path('/tmp/uno-merged-default-source')
cmd=['ctest','--test-dir',str(b),'-j1','-R',(p/'regex.txt').read_text(),'--output-on-failure','--output-junit',str(p/'results.xml')]
report={'a':'33af64ee8775e89035c5c364615ff6e3ada853a8','b':'203354611ba872d84687a1787bfdebf2cab5c730','merged_tree':subprocess.check_output(['git','write-tree'],cwd=s,text=True).strip(),'merge_commit_created':False,'build_targets':['create-state','test-tos-collator','test-workchain-activation-control'],'runtime_dependencies':['cmake (CTest driver and child fixture lifecycle)','create-state (executes Fift genesis scripts)','base64 (state identifier encoding)','test-tos-collator (disk node and typed result producer)','Python3 (activation driver imports shared classifier)','test-workchain-activation-control (real scoped resolver)','git (activation shared-helper provenance)'],'command':cmd,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
report['binary_sha256']={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in [b/'crypto/create-state',b/'test-tos-collator',b/'test-workchain-activation-control']}
with (p/'ctest.log').open('wb') as log: result=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
report['exit']=result.returncode
root=ET.parse(p/'results.xml').getroot(); rows=[]
for t in root.iter('testcase'):
 rows.append({'name':t.attrib['name'],'status':t.attrib.get('status'),'time':t.attrib.get('time'),'failure':t.find('failure') is not None,'error':t.find('error') is not None,'skipped':t.find('skipped') is not None,'output':t.findtext('system-out','')})
report['tests']=rows;report['ended_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(p/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'exit':result.returncode,'tests':[{k:v for k,v in r.items() if k!='output'} for r in rows]},indent=2))
assert len(rows)==11
assert result.returncode==0 and all(not(r['failure'] or r['error'] or r['skipped']) for r in rows)
