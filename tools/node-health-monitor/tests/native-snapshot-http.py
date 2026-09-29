#!/usr/bin/env python3
"""Exercise the production exporter actor through an isolated loopback fixture."""
import argparse,hashlib,http.client,json,socket,subprocess,tempfile,time
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--write-fixtures',action='store_true');p.add_argument('--mode',choices=['fast','slow','disabled','lease']);args=p.parse_args()
subprocess.run([args.binary],check=True)
def check(mode):
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 with tempfile.TemporaryFile() as log:
  proc=subprocess.Popen([args.binary,str(port),mode],stdout=log,stderr=subprocess.DEVNULL)
  def request(path,method='GET'):
   c=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
   try:
    c.request(method,path);r=c.getresponse();return r.status,dict(r.getheaders()),r.read()
   finally:c.close()
  def collections():
   log.seek(0);return log.read().decode().splitlines()
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
   started=time.monotonic();status,headers,body=request('/metrics');elapsed=time.monotonic()-started
   if mode=='slow':
    assert status==503 and 1.8<=elapsed<3.0,(status,elapsed)
    for _ in range(20):assert request('/metrics')[0]==503;assert request('/health-snapshot')[0]==503
    time.sleep(1.6);assert request('/health-snapshot')[0]==503;assert collections()==['COLLECT 1'];return
   assert status==200
   assert b'_pq_operation_duration_seconds_bucket{' in body
   assert b'_pq_operation_duration_seconds__bucket' not in body
   status,h,raw=request('/health-snapshot');assert status==200;assert h['Content-Type']=='application/json'
   value=json.loads(raw);assert value['generation']=='1' and headers['X-TOS-Snapshot-Generation']=='1'
   assert value['process_epoch']==headers['X-TOS-Process-Epoch'];assert value['payload']['pq_sign']['succeeded']=='9007199254740993'
   live=('_exporter_collection_inflight','_exporter_collection_skipped_total','_exporter_collection_failures_total')
   stable=''.join(line+'\n' for line in body.decode().splitlines() if not any(s in line for s in live)).encode()
   assert value['payload']['bytes']==len(stable)
   assert value['payload']['openmetrics_hash']==hashlib.sha256(stable).hexdigest()
   assert value['content_hash']==hashlib.sha256(json.dumps(value['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
   Draft202012Validator(json.loads((ROOT/'contracts/source-envelope.schema.json').read_text())).validate(value)
   if args.write_fixtures and mode=='fast':
    fixture=ROOT/'crates/health-core/tests/fixtures'
    (fixture/'native-core.json').write_bytes(raw)
    (fixture/'native-core.prom').write_bytes(body)
   initial_age=value.pop('source_age_ms')
   for _ in range(1000):
    status,_,raw=request('/health-snapshot');assert status==200
    current=json.loads(raw);assert current.pop('source_age_ms')>=initial_age;assert current==value
   assert request('/health-snapshot?force=true')[0]==404;assert request('/health-snapshot','POST')[0]==405
   assert collections()==['COLLECT 1']
   if mode=='lease':
    time.sleep(max(0,started+15.05-time.monotonic()))
    assert request('/metrics')[0]==503
    status,_,body=request('/metrics');assert status==200 and b'tos_exporter_collection_inflight 1.000000\n' in body
    assert json.loads(request('/health-snapshot')[2])['generation']=='1'
    time.sleep(1.6)
    status,_,body=request('/metrics');assert status==200 and b'tos_exporter_collection_inflight 0.000000\n' in body
    assert json.loads(request('/health-snapshot')[2])['generation']=='1'
  finally:
   proc.terminate()
   try:proc.wait(timeout=3)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
for mode in [args.mode] if args.mode else ['fast','slow','disabled','lease']:
 check(mode);print(mode+': passed',flush=True)
