#!/usr/bin/env python3
"""Check dependency failure precedes cleanup using a non-destructive shell sandbox."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--out',type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
repo=Path(__file__).resolve().parents[1]
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
source='scripts/setup-testnet.sh'
original=subprocess.check_output(['git','show',f'{commit}:{source}'],cwd=repo)
assert (repo/source).read_bytes()==original
before='[ -f "$REPO_ROOT/test/tostester/src/tosapi/$module.py" ]'
after='true'
assert original.count(before.encode())==1
sha=lambda b:hashlib.sha256(b).hexdigest()
with tempfile.TemporaryDirectory(prefix='uno-setup-control-') as directory:
 root=Path(directory);script=root/'scripts/setup-testnet.sh';script.parent.mkdir();script.write_bytes(original)
 bin=root/'stubs';bin.mkdir();marker=root/'cleanup-called'
 def stub(path,body):
  path.parent.mkdir(parents=True,exist_ok=True);path.write_text('#!/bin/sh\n'+body+'\n');path.chmod(0o755)
 for name in ['validator-engine/validator-engine','dht-server/dht-server','validator-engine-console/validator-engine-console','lite-client/lite-client','utils/generate-random-id','crypto/create-state']:
  stub(root/'build'/name,'exit 0')
 stub(bin/'id','echo 0')
 stub(bin/'uv','exit 0')
 stub(bin/'rm','echo reached > "$CLEANUP_MARKER"; exit 79')
 env={**os.environ,'PATH':str(bin)+os.pathsep+os.environ['PATH'],'SUDO_USER':'','TOS_SETUP_LOCKFILE':str(root/'lock'),'CLEANUP_MARKER':str(marker)}
 def run(name):
  result=subprocess.run(['bash',str(script),'--clean'],env=env,capture_output=True)
  (a.out/(name+'.stdout.log')).write_bytes(result.stdout);(a.out/(name+'.stderr.log')).write_bytes(result.stderr)
  return result
 baseline=run('baseline');assert baseline.returncode==1 and not marker.exists(), '1210: cleanup preceded missing-schema rejection'
 mutant=original.replace(before.encode(),after.encode());script.write_bytes(mutant)
 failed=run('mutant');assert failed.returncode==79 and marker.exists(), '1211: removal did not expose cleanup'
 script.write_bytes(original);restored=script.read_bytes();assert restored==original
 marker.unlink();again=run('restored');assert again.returncode==1 and not marker.exists()
 report={'commit':commit,'source':source,'from':before,'to':after,'original_sha256':sha(original),'copy_before_sha256':sha(original),'mutant_sha256':sha(mutant),'restored_sha256':sha(restored),'restore_audit_sha256':sha(restored.replace(before.encode(),after.encode())),'scope':'Shell ordering/dependency control. id and uv are stubs; rm is an exit-79 sentinel. No actual service, data deletion or application guard result is claimed. Shell interpreted afresh for every run; no compiled targets.'}
 assert (repo/source).read_bytes()==original
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: missing generated schema blocks cleanup; removed check exposes cleanup sentinel')
