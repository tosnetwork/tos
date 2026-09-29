#!/usr/bin/env python3
"""Exercise the production exporter actor through an isolated loopback fixture."""
import argparse,hashlib,http.client,json,re,socket,subprocess,tempfile,threading,time
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--write-fixtures',action='store_true');p.add_argument('--mode',choices=['fast','slow','disabled','gateoff','sources','lease','disconnect','concurrent','error','boundary']);args=p.parse_args()
subprocess.run([args.binary],check=True)
def parse_openmetrics(body):
 text=body.decode('utf-8')
 assert text.endswith('# EOF\n') and text.count('# EOF\n')==1
 helps={};types={};samples=[]
 for line in text.splitlines():
  if line.startswith('# HELP '):
   name=line.split(' ',3)[2];assert name not in helps,name;helps[name]=line
  elif line.startswith('# TYPE '):
   name=line.split(' ',3)[2];assert name not in types,name;types[name]=line
  elif line and not line.startswith('#'):
   assert re.fullmatch(r'[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^\n]*\})? [-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?',line),line
   samples.append(line)
 return helps,types,samples
def check(mode,padding=None):
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 with tempfile.TemporaryFile() as log:
  command=[args.binary,str(port),mode]
  if padding is not None:command.append(str(padding))
  proc=subprocess.Popen(command,stdout=log,stderr=subprocess.DEVNULL)
  def request(path,method='GET'):
   c=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
   try:
    c.request(method,path);r=c.getresponse();return r.status,dict(r.getheaders()),r.read()
   finally:c.close()
  def collections():
   log.seek(0);return [line for line in log.read().decode().splitlines() if line.startswith(('COLLECT ','COMPLETE '))]
  def source_work():
   log.seek(0);return [line for line in log.read().decode().splitlines() if line.startswith('SOURCE_WORK ')]
  try:
   until=time.monotonic()+5
   while True:
    try:status,_,_=request('/health-snapshot');break
    except (ConnectionError,OSError):
     assert time.monotonic()<until,'fixture not listening';time.sleep(.02)
   if mode=='disabled':
    assert status==404;assert request('/metrics')[0]==200;assert request('/health-snapshot')[0]==404;return
   assert status==503
   for _ in range(20):assert request('/health-snapshot')[0]==503
   time.sleep(.05);assert collections()==[],'typed read triggered collection'
   if mode=='disconnect':
    with socket.create_connection(('127.0.0.1',port),timeout=2) as abandoned:
     abandoned.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    time.sleep(.1);assert request('/metrics')[0]==503;assert collections()==['COLLECT 1']
    time.sleep(1.1);assert request('/health-snapshot')[0]==200;assert collections()==['COLLECT 1'];return
   if mode=='concurrent':
    barrier=threading.Barrier(8);results=[];lock=threading.Lock()
    def concurrent_request():
     barrier.wait();result=request('/metrics')[0]
     with lock:results.append(result)
    threads=[threading.Thread(target=concurrent_request) for _ in range(8)]
    for thread in threads:thread.start()
    for thread in threads:thread.join()
    assert results.count(200)==1 and results.count(503)==7,results
    assert collections()==['COLLECT 1'];return
   started=time.monotonic();status,headers,body=request('/metrics');elapsed=time.monotonic()-started
   if mode=='slow':
    assert status==503 and 1.8<=elapsed<3.0,(status,elapsed)
    for _ in range(20):assert request('/metrics')[0]==503;assert request('/health-snapshot')[0]==503
    time.sleep(1.6);assert request('/health-snapshot')[0]==503;assert collections()==['COLLECT 1'];return
   if mode=='error':
    assert status==503 and collections()==['COLLECT 1'];assert request('/health-snapshot')[0]==503;return
   if mode=='boundary':
    return status,headers,body
   assert status==200
   publisher_prepare_us=int(headers['X-TOS-Publisher-Prepare-Us'])
   assert 0<=publisher_prepare_us<2_000_000
   helps,types,samples=parse_openmetrics(body)
   if mode!='gateoff':
    assert b'_pq_operation_duration_seconds_bucket{' in body
    assert b'_pq_operation_duration_seconds__bucket' not in body
    assert b'tos_health_source_collection_completed_timestamp_seconds{source="fixture"}' in body
    assert b'tos_health_source_observed_timestamp_available{source="fixture"} 0.000000\n' in body
   else:
    assert b'tos_health_source_' not in body and b'tos_pq_operations_total' not in body
   if mode=='sources':
    assert b'tos_health_source_collection_completed_timestamp_seconds{source="second_fixture"}' in body
    assert b'tos_health_source_collection_completed_timestamp_seconds{source="exporter"}' in body
    assert b'tos_health_source_collection_completed_timestamp_seconds{source="exporter_internal"}' in body
    assert b'tos_exporter_health_source_collection_completed_timestamp_seconds{source="http_server"}' in body
    assert sum('tos_health_source_collection_completed_timestamp_seconds{' in line for line in samples)==4
    assert list(helps).count('tos_health_source_collection_completed_timestamp_seconds')==1
    assert list(types).count('tos_health_source_collection_completed_timestamp_seconds')==1
    assert list(helps).count('tos_exporter_health_source_collection_completed_timestamp_seconds')==1
    assert list(types).count('tos_exporter_health_source_collection_completed_timestamp_seconds')==1
   status,h,raw=request('/health-snapshot');assert status==200;assert h['Content-Type']=='application/json'
   value=json.loads(raw);assert value['generation']=='1' and headers['X-TOS-Snapshot-Generation']=='1'
   assert value['process_epoch']==headers['X-TOS-Process-Epoch']
   if mode=='gateoff':assert value['payload']['pq_sign'] is None
   else:assert value['payload']['pq_sign']['succeeded']=='9007199254740993'
   assert body.endswith(b'# EOF\n') and len(body)<=2*1024*1024
   assert value['payload']['bytes']==len(body)
   assert value['payload']['openmetrics_hash']==hashlib.sha256(body).hexdigest()
   assert value['content_hash']==hashlib.sha256(json.dumps(value['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
   Draft202012Validator(json.loads((ROOT/'contracts/source-envelope.schema.json').read_text())).validate(value)
   print('isolated_actual_publisher_prepare_us='+str(publisher_prepare_us),flush=True)
   if args.write_fixtures and mode=='fast':
    fixture=ROOT/'crates/health-core/tests/fixtures'
    (fixture/'native-core.json').write_bytes(raw)
    (fixture/'native-core.prom').write_bytes(body)
   initial_age=value.pop('source_age_ms')
   for _ in range(1000):
    status,_,raw=request('/health-snapshot');assert status==200
    current=json.loads(raw);assert current.pop('source_age_ms')>=initial_age;assert current==value
   assert request('/health-snapshot?force=true')[0]==404;assert request('/health-snapshot','POST')[0]==405
   for _ in range(50):
    status,repeated_headers,repeated_body=request('/metrics');assert status==200
    assert repeated_body==body and repeated_headers['X-TOS-Snapshot-Generation']=='1'
   expected_collections=(['COLLECT 1','COLLECT 1'] if mode=='sources' else
                         ['COLLECT 1','COMPLETE 1'] if mode=='lease' else ['COLLECT 1'])
   assert collections()==expected_collections
   if mode=='lease':
    time.sleep(max(0,started+15.05-time.monotonic()))
    second_started=time.monotonic()
    assert request('/metrics')[0]==503
    assert collections()==['COLLECT 1','COMPLETE 1','COLLECT 2']
    assert source_work()[-1]=='SOURCE_WORK ACTIVE 1 PEAK 1'
    status,h,cached=request('/metrics');assert status==200 and cached==body
    assert h['X-TOS-Snapshot-Generation']=='1' and hashlib.sha256(cached).hexdigest()==value['payload']['openmetrics_hash']
    assert json.loads(request('/health-snapshot')[2])['generation']=='1'
    time.sleep(max(0,second_started+15.05-time.monotonic()))
    probe_started=time.monotonic();status,_,_=request('/metrics');probe_elapsed=time.monotonic()-probe_started
    assert status==503 and probe_elapsed<0.5,(status,probe_elapsed)
    assert collections()==['COLLECT 1','COMPLETE 1','COLLECT 2']
    assert source_work()[-1]=='SOURCE_WORK ACTIVE 1 PEAK 1'
    time.sleep(max(0,second_started+16.7-time.monotonic()))
    assert collections()==['COLLECT 1','COMPLETE 1','COLLECT 2','COMPLETE 2']
    assert source_work()[-1]=='SOURCE_WORK ACTIVE 0 PEAK 1'
    assert request('/health-snapshot')[0]==503
  finally:
   proc.terminate()
   try:proc.wait(timeout=3)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
def check_boundary():
 status,_,body=check('boundary',0);assert status==200
 low=0;high=2*1024*1024-len(body)+4096
 assert high>0 and check('boundary',high)[0]==503
 while low+1<high:
  candidate=(low+high)//2
  if check('boundary',candidate)[0]==200:low=candidate
  else:high=candidate
 status,headers,body=check('boundary',low)
 assert status==200 and len(body)==2*1024*1024 and headers['X-TOS-Snapshot-Generation']=='1',(status,len(body),low)
 status,_,_=check('boundary',low+1);assert status==503
 print('boundary: passed',flush=True)
selected=[args.mode] if args.mode else ['fast','slow','disabled','gateoff','sources','lease','disconnect','concurrent','error','boundary']
for mode in selected:
 if mode=='boundary':check_boundary()
 else:check(mode);print(mode+': passed',flush=True)
