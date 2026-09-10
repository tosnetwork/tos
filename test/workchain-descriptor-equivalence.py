#!/usr/bin/env python3
"""Compare library descriptors with their pinned predecessor constructors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p=argparse.ArgumentParser()
p.add_argument('--repo',type=Path,required=True)
p.add_argument('--create-state',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--library',type=Path)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
commit='a27ff2c77'
specs=[
 ('native-basic','crypto/fift/lib/Workchain.fif','add-std-workchain','a6','0xe000','-1',''),
 ('native-extended','test/tostester/src/tostester/zerostate.py','add-std-workchain-v2','a7','0xe000','-1',''),
 ('counter-basic','test/counter-masterchain-genesis.fif','add-counter-workchain','a6','0xe000','0x434e5431','variable counter_genesis_descriptor\n'),
 ('counter-extended','test/counter-network-config.fif','add-counter-network-workchain','a7','0xe000','0x434e5431','variable counter_network_descriptor\n'),
 ('uno-basic','crypto/smartcont/uno-genesis-config.fif','add-uno-genesis-workchain','a6','0xc000','uno_genesis_engine_key','uno-v2-engine-key constant uno_genesis_engine_key\nvariable uno_genesis_descriptor\n'),
]
report={'baseline_commit':commit,'create_state_sha256':hashlib.sha256(a.create_state.read_bytes()).hexdigest(),'cases':[]}
def execute(case,mode,body):
 script=a.out/(case+'.'+mode+'.fif');output=a.out/(case+'.'+mode+'.boc')
 script.write_text('4 setglobalid\ndictnew workchain-dict !\n'+body+'\n2 workchain-dict @ 32 idict@ 0= abort"missing descriptor"\ns>c 31 boc+>B "'+str(output)+'" B>file\n')
 includes=[a.repo/'crypto/fift/lib',a.create_state.parent/'smartcont',a.repo/'crypto/smartcont']
 if a.library and mode=='new':includes.insert(0,a.library)
 cmd=[str(a.create_state),'-I',':'.join(map(str,includes)),str(script)]
 r=subprocess.run(cmd,capture_output=True)
 (a.out/(case+'.'+mode+'.stdout.log')).write_bytes(r.stdout);(a.out/(case+'.'+mode+'.stderr.log')).write_bytes(r.stderr)
 assert r.returncode==0, f'1220: descriptor construction failed: {case}/{mode}'
 return output.read_bytes()
for name,source,word,tag,flags,key,prefix in specs:
 raw=subprocess.check_output(['git','show',f'{commit}:{source}'],cwd=a.repo)
 text=raw.decode()
 if source.endswith('.py'):text=text.replace('{{','{').replace('}}','}')
 start=text.index('{ <b x{'+tag+'}')
 end=text.index('} : '+word,start)+len('} : '+word)
 definition=text[start:end].replace('} : '+word,'} : baseline-constructor')
 old=execute(name,'old',prefix+definition+'\n1 2 1788656400 0 0 0 2 baseline-constructor')
 new=execute(name,'new',prefix+f'1 2 1788656400 0 0 0 2 {flags} {key} '+('add-basic-workchain-v2' if tag=='a7' else 'add-basic-workchain')+' drop')
 entry={'name':name,'baseline_source':source,'baseline_source_sha256':hashlib.sha256(raw).hexdigest(),'baseline_boc_sha256':hashlib.sha256(old).hexdigest(),'library_boc_sha256':hashlib.sha256(new).hexdigest(),'equal':old==new}
 if old!=new:report['failure_identity']=1221
 report['cases'].append(entry);(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 assert old==new,f'1221: descriptor bytes changed: {name}'
print('PASS: five descriptor encodings byte-identical to pinned predecessors')
