"""Exercise bounded native HTTP over real Unix sockets, including peer close."""
import argparse,json,os,socket,subprocess,tempfile,threading,time
from pathlib import Path
MAX=4194304
MEDIA=b'application/vnd.tos.validator-auth.v1+json'
def response(body=b'native-http',extra=b'',status=b'200 OK',length=None):
 return b'HTTP/1.1 '+status+b'\r\nContent-Type: '+MEDIA+b'\r\nContent-Length: '+str(len(body) if length is None else length).encode()+b'\r\n'+extra+b'\r\n'+body
def main(cpp,rust,out,only=None):
 report=[]
 with tempfile.TemporaryDirectory(prefix='p0-http-',dir='/tmp') as directory:
  root=Path(directory)
  cases=[('response-peer-uid',response(),False,None),('response-normal',response(),True,b'native-http'),('response-body-max',response(b'x'*MAX),True,b'x'*MAX),
   ('response-body-bound',response(b'x'*(MAX+1)),False,None),
   ('response-duplicate-header',response(extra=b'content-length: 11\r\n'),False,None),
   ('response-compression',response(extra=b'Content-Encoding: gzip\r\n'),False,None),
   ('response-transfer-encoding',response(extra=b'Transfer-Encoding: chunked\r\n'),False,None),
   ('response-upgrade',response(extra=b'Upgrade: h2c\r\n'),False,None),
   ('response-redirect',response(status=b'302 Found'),False,None),
   ('response-version',response().replace(b'HTTP/1.1',b'HTTP/1.0'),False,None),
   ('response-length-missing',b'HTTP/1.1 200 OK\r\n\r\n',False,None),
   ('response-length-sign',response().replace(b'Content-Length: 11',b'Content-Length: +11'),False,None),
   ('response-length-leading-zero',response().replace(b'Content-Length: 11',b'Content-Length: 011'),False,None),
   ('response-truncated',response(length=12),False,None),
   ('response-header-count',response(extra=b''.join(b'X-'+str(i).encode()+b': x\r\n' for i in range(15))),False,None)]
  for n in (8192,8193):
   base=response(extra=b'X-Pad: \r\n');pad=n-len(base.split(b'\r\n\r\n')[0])-4
   cases.append(('response-header-'+('max' if n==8192 else 'bound'),response(extra=b'X-Pad: '+b'x'*pad+b'\r\n'),n==8192,b'native-http'))
  for language,driver in [('cpp',cpp),('rust',rust)]:
   if driver is None:continue
   for name,raw,success,expected in cases:
    if only and only!=name:continue
    path=root/'socket'; result=root/'result';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));os.chmod(path,0o600);listener.listen(1);listener.settimeout(8)
    failures=[]
    def serve():
     try:
      conn,_=listener.accept();conn.settimeout(8)
      with conn:
       header=b''
       while not header.endswith(b'\r\n\r\n'):
        part=conn.recv(1)
        if not part:
         if name=='response-peer-uid':return
         raise RuntimeError('client did not send a request')
        header+=part
        if len(header)>8192:raise RuntimeError('client header overflow')
       if not header.startswith(b'GET /v1/capabilities HTTP/1.1\r\n'):raise RuntimeError('client route mismatch')
       try:conn.sendall(raw)
       except (BrokenPipeError,ConnectionResetError):pass
     except Exception as e:failures.append(repr(e))
    thread=threading.Thread(target=serve);thread.start()
    command=[str(driver), 'client' if language=='cpp' else 'http-raw', str(path),str(os.geteuid()+(name=='response-peer-uid')),str(result)]
    process=subprocess.run(command,capture_output=True,text=True,timeout=10);thread.join(9);listener.close();path.unlink()
    if thread.is_alive() or failures:raise RuntimeError((language,name,failures))
    if process.returncode not in (0,1):raise RuntimeError((language,name,process.returncode,process.stderr))
    assert process.returncode==(0 if success else 1),(language,name,process.returncode,process.stderr)
    if success:assert result.read_bytes()==expected,(language,name,'body mismatch')
    report.append(dict(language=language,case=name))
  if cpp:
   def request(body=b'hello',extra=b'',length=None):
    return b'POST /v1/sign HTTP/1.1\r\nHost: localhost\r\nContent-Length: '+str(len(body) if length is None else length).encode()+b'\r\n'+extra+b'\r\n'+body
   cases=[('request-normal',request(),True),('request-body-max',request(b'x'*MAX),True),
    ('request-body-bound',request(b'x'*(MAX+1)),False),('request-duplicate-header',request(extra=b'Content-Length: 5\r\n'),False),
    ('request-compression',request(extra=b'Content-Encoding: gzip\r\n'),False),('request-transfer-encoding',request(extra=b'Transfer-Encoding: chunked\r\n'),False),
    ('request-header-bound',request(extra=b'X-Pad: '+b'x'*8192+b'\r\n'),False),('request-get-body',request().replace(b'POST',b'GET',1),False),
    ('request-version',request().replace(b'HTTP/1.1',b'HTTP/2.0'),False),('request-host',request().replace(b'Host: localhost\r\n',b''),False)]
   for name,raw,success in cases:
    if only and only!=name:continue
    path=root/'socket';seen=root/'seen';seen.unlink(missing_ok=True)
    process=subprocess.Popen([str(cpp),'server',str(path),str(os.geteuid()),str(seen)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if process.stdout.readline().strip()!='READY':raise RuntimeError(('server startup',process.communicate(timeout=10)))
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
     conn.settimeout(8);conn.connect(str(path))
     try:conn.sendall(raw)
     except (BrokenPipeError,ConnectionResetError):pass
     try:
      while conn.recv(65536):pass
     except ConnectionResetError:pass
    stdout,stderr=process.communicate(timeout=10)
    if process.returncode not in (0,1):raise RuntimeError((name,process.returncode,stderr))
    assert seen.exists()==success,('cpp',name,seen.exists(),stderr)
    report.append(dict(language='cpp',case=name))
 out.write_text(json.dumps(dict(http_cases=len(report),cases=report,success=True),indent=2)+'\n');print('PASS:',len(report),'native HTTP cases')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cpp',type=Path);p.add_argument('--rust',type=Path);p.add_argument('--case');p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.cpp.resolve() if a.cpp else None,a.rust.resolve() if a.rust else None,a.out,a.case)
