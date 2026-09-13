"""Exercise native framing against frozen binary fixtures; not service authorization."""
import argparse,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test/validator-auth-p0'))
import reference as r
import api

def main(driver):
 driver=str(Path(driver).resolve());objects=json.loads((ROOT/'test/validator-auth-p0/lifecycle-api-golden.json').read_text())['objects'];count=0
 with tempfile.TemporaryDirectory() as directory:
  directory=Path(directory)
  def run(raw,method,response=False,error=None):
   nonlocal count
   path=directory/'in';path.write_bytes(raw)
   p=subprocess.run([driver,str(method),'response' if response else 'request',str(path),str(directory/'out')],capture_output=True,text=True)
   if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
   assert p.returncode==(1 if error else 0),(method,error,p.returncode,p.stderr)
   if error:assert p.stderr.strip()==error,(error,p.stderr)
   else:assert json.loads((directory/'out').read_bytes())==json.loads(raw)
   count+=1
  for number,method in r.SCHEMA['methods'].items():
   number=int(number);value=r.decode(method['request'],bytes.fromhex(objects[method['request']]))
   raw=api.encode_transport(number,value);run(raw,number)
   obj=json.loads(raw)
   run(raw.replace(b'"api_version"',b'"\\u0061pi_version"'),number)
   run(raw[:-1]+b',"\\u0061pi_version":"1"}',number,error='duplicate-json-key')
   run(raw+b'\0',number,error='json-syntax')
   changed=dict(obj);changed['api_version']=1;run(json.dumps(changed).encode(),number,error='json-syntax')
   changed=dict(obj);changed['request_id']='00';run(json.dumps(changed).encode(),number,error='hex-width')
   changed=dict(obj);changed['request']=obj['request']+'00';run(json.dumps(changed).encode(),number,error='trailing')
   changed=dict(obj);changed['request_id']='ff'*32;run(json.dumps(changed).encode(),number,error='request-correlation')
   result=r.decode(method['result'],bytes.fromhex(objects[method['result']]))
   response=api.encode_transport(number,result,response=True,rid=bytes.fromhex(obj['request_id']));run(response,number,True)
   changed=json.loads(response);changed['error']=changed['result'];run(json.dumps(changed).encode(),number,True,'result-or-error')
   error=r.decode('error',bytes.fromhex(objects['error']));error.update(method=number,request_id=bytes.fromhex(obj['request_id']),code=10,retryable=int(number in (1,2,6,8,9,10,11,12,13,14,15)),request_state=4,message=b'unavailable')
   response=api.encode_transport(number,error,response=True,rid=error['request_id'],error=True);run(response,number,True)
   error['retryable']^=1;run(api.encode_transport(number,error,response=True,rid=error['request_id'],error=True),number,True,'error-retry')
  run(b' '*4194305,1,error='transport-bound')
  run(b'[]',1,error='json-syntax')
  print(json.dumps({'native_transport_cases':count,'success':True}))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--driver',required=True);args=parser.parse_args();main(args.driver)
