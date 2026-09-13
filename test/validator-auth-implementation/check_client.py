"""Run the Rust client against bounded adversarial local HTTP peers.

These peers supply semantic fixtures, not trusted chain evidence. The separate
native API test verifies real proofs and service receipts.
"""
import argparse,copy,json,os,socket,subprocess,tempfile,threading
from pathlib import Path
from check_api_semantics import fixtures,api,r,tr,h
MEDIA='application/vnd.tos.validator-auth.v1+json'
def main(driver,out,native=None,proofs=None):
 report=[];cases=fixtures()
 with tempfile.TemporaryDirectory(prefix='p0-client-',dir='/tmp') as tmp:
  tmp=Path(tmp)
  def run(label,method,q,result,*,error=None,body=None,status=200,media=MEDIA,count=1,objects=None,wire_error=False,context=None):
   q=copy.deepcopy(q);request=r.encode(api.METHODS[str(method)]['request'],q);rid=api.request_id(method,q)
   tmp.joinpath('request').write_bytes(request);tmp.joinpath('result').unlink(missing_ok=True)
   if body is None:body=api.encode_transport(method,result,True,rid,wire_error)
   path=tmp/'socket';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));os.chmod(path,0o600);listener.listen(4);listener.settimeout(.1)
   stop=threading.Event();calls=[];failures=[]
   def serve():
    try:
     while not stop.is_set():
      try:conn,_=listener.accept()
      except socket.timeout:continue
      with conn:
       conn.settimeout(5);header=b''
       while not header.endswith(b'\r\n\r\n'):
        part=conn.recv(1)
        if not part:raise RuntimeError('incomplete client header')
        header+=part
        if len(header)>8192:raise RuntimeError('oversized client header')
       rows=header.decode().split('\r\n');verb,route,version=rows[0].split(' ');fields=dict(row.split(': ',1) for row in rows[1:] if row)
       size=int(fields['Content-Length']);raw=b''
       if size>4194304:raise RuntimeError('oversized client body')
       while len(raw)<size:
        part=conn.recv(min(65536,size-len(raw)))
        if not part:raise RuntimeError('incomplete client body')
        raw+=part
       number=next(int(n) for n,spec in api.METHODS.items() if spec['path']==route)
       if version!='HTTP/1.1' or verb!=api.METHODS[str(number)]['http']:raise RuntimeError('client route contract')
       calls.append(number)
       if number==method:
        expected=b'' if method==1 else api.encode_transport(method,q)
        if raw!=expected:raise RuntimeError('client canonical request')
        reply=body;http_status=status;content_type=media
       elif number==14 and objects:
        _,chunk=api.decode_transport(raw,14);manifest=chunk['manifest'];anchor=q.get('anchor')
        if chunk['anchor']!=anchor:raise RuntimeError('client attachment anchor')
        data=objects[manifest['object_id']];start=chunk['index']*1048576
        value=dict(anchor=anchor,manifest_id=r.object_id('object_ref',manifest),index=chunk['index'],data=data[start:start+1048576])
        reply=api.encode_transport(14,value,True,api.request_id(14,chunk));http_status=200;content_type=MEDIA
       else:raise RuntimeError('unexpected automatic invocation')
       frame=f'HTTP/1.1 {http_status} Response\r\nContent-Type: {content_type}\r\nContent-Length: {len(reply)}\r\n\r\n'.encode()+reply
       try:conn.sendall(frame)
       except (BrokenPipeError,ConnectionResetError):pass
    except Exception as e:failures.append(repr(e))
   thread=threading.Thread(target=serve);thread.start()
   try:
    command=[str(driver),'http',str(path),str(os.geteuid()),str(method),str(tmp/'request'),str(tmp/'result')]
    if context:
     trusted,network=context;(tmp/'anchor').write_bytes(r.encode('anchor',trusted))
     command=[str(native),'http',str(path),str(os.geteuid()),str(method),str(tmp/'request'),str(tmp/'anchor'),str(network),str(tmp/'result')]
    process=subprocess.run(command,capture_output=True,text=True,timeout=15)
   finally:
    stop.set();thread.join(6);listener.close();path.unlink()
   if thread.is_alive() or failures or process.returncode not in (0,1) or process.stderr.startswith('fixture-'):raise RuntimeError((label,failures,process.returncode,process.stderr))
   assert len(calls)==count,(label,'call-count',calls)
   assert process.returncode==(1 if error else 0) and (not error or error=='*' or process.stderr.strip()==error),(label,error,process.returncode,process.stderr)
   if not error or wire_error:
    expected=r.encode('error' if wire_error else api.METHODS[str(method)]['result'],result)
    assert tmp.joinpath('result').read_bytes()==expected,(label,'result-bytes')
   report.append(dict(label=label,method=method,calls=calls,rejected=bool(error)))
  for n,(q,result) in cases.items():run(f'client-method-{n}',n,q,result)
  q,result=cases[2]
  for label,changes,error in [
   ('client-media',dict(media='application/json'),'http-response-contract'),
   ('client-status',dict(status=201),'http-response-contract'),
   ('client-success-status',dict(status=403),'http-success-status'),
   ('client-correlation',dict(body=api.encode_transport(2,result,True,h(250))),'response-correlation'),
   ('client-duplicate-json',dict(body=api.encode_transport(2,result,True,api.request_id(2,q)).replace(b'{',b'{"api_version":"1",',1)),'duplicate-json-key')]:
   run(label,2,q,result,error=error,**changes)
  changed=copy.deepcopy(result);changed['epoch']+=1
  run('client-response-association',2,q,changed,error='response-key')
  q,result=(copy.deepcopy(v) for v in cases[3]);q['epoch']=0
  run('client-request-admission',3,q,result,error='preparation',count=0)
  for code in range(1,15):
   q,_=cases[6];rid=api.request_id(6,q)
   error=dict(request_id=rid,method=6,code=code,retryable=int(code in (10,11,12)),request_state=4,message=b'')
   run('client-error-'+str(code),6,q,error,error='api-error',wire_error=True)
  q,result=(copy.deepcopy(v) for v in cases[8]);large=b'x'*70000;manifest=tr.manifest(large,5)
  result['proof']['proof_hash']=r.digest('proof',large);result['proof']['proof']=tr.value(large,5)
  run('client-referenced-proof',8,q,result,objects={manifest['object_id']:large},count=2)
  if native and proofs:
   manifests=sorted(proofs.glob('*.case'),key=lambda p:int(p.stem))
   assert len(manifests)==int((proofs/'complete').read_text())>0,'native-http-fixture-completeness'
   for meta in manifests:
    method,network,accepted=meta.read_text().split();method=int(method)
    q=r.decode(api.METHODS[str(method)]['request'],meta.with_suffix('.request').read_bytes())
    result=r.decode(api.METHODS[str(method)]['result'],meta.with_suffix('.response').read_bytes())
    trusted=r.decode('anchor',meta.with_suffix('.anchor').read_bytes())
    objects={}
    for ref in result['proof']['proof']['reference']:
     objects[ref['object_id']]=(proofs/ref['object_id'].hex()).read_bytes()
    chunks=sum(len(ref['chunk_hashes']) for ref in result['proof']['proof']['reference'])
    run('native-http-'+meta.stem,method,q,result,error=None if accepted=='1' else '*',objects=objects,count=1+chunks,context=(trusted,int(network)))
 out.write_text(json.dumps(dict(client_cases=len(report),cases=report,success=True),indent=2)+'\n');print('PASS:',len(report),'client cases')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--driver',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--native',type=Path);p.add_argument('--proofs',type=Path);a=p.parse_args();main(a.driver.resolve(),a.out,a.native.resolve() if a.native else None,a.proofs.resolve() if a.proofs else None)
