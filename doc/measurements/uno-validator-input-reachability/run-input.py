import json,os,shutil,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent
R=Path('/tmp/uno-a2-registry-jqOjoDbi')
shutil.copytree(R/'fixture/peer/db',P/'db')
prev='(2,8000000000000000,0):'+(R/'fixture/counter-state.rhash').read_bytes().hex()+':'+(R/'fixture/counter-state.fhash').read_bytes().hex()
cmd=['gdb','-q','-nx','--batch','--return-child-result','-x',str(R/'observe.gdb'),'--args',str(R/'bin/test-tos-collator'),'-C',str(R/'fixture/global.json'),'-D',str(P/'db'),'-w','2','-T',prev,'--counter-increment','1','--account-binding-probe',str(P/'calls.txt'),'--import-candidate',str(P/'candidate.bin'),'--query-result',str(P/'result'),'--export-candidate',str(P/'unexpected-export')]
(P/'argv.json').write_text(json.dumps(cmd,indent=2))
with (P/'run.log').open('xb') as f:
    rc=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,A2_ROOT=str(R),A2_TRACE=str(P/'trace.json')),timeout=90).returncode
print('exit',rc)
