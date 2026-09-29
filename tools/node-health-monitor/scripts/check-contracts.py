#!/usr/bin/env python3
import argparse,copy,hashlib,json,re,struct,subprocess,sys,tempfile
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
formats=FormatChecker()
@formats.checks('uint64')
def uint64(v): return isinstance(v,str) and re.fullmatch(r'0|[1-9][0-9]{0,19}',v) is not None and int(v)<=2**64-1

def closed(v):
 if isinstance(v,dict):
  if v.get('type')=='object':
   assert v.get('additionalProperties') is False and set(v['required'])==set(v['properties'])
  for child in v.values():closed(child)
 elif isinstance(v,list):
  for child in v:closed(child)
def validator(name):return Draft202012Validator(json.loads((ROOT/'contracts'/name).read_text()),format_checker=formats)
def check_metric_manifest(value):
 assert value['profile']=='c01_source_publisher_contract'
 assert value['max_series']<=value['r4_global_core_max_series']==2048
 assert value['max_openmetrics_bytes']==2_097_152
 assert value['registry_capacity_slots']==64 and value['registry_memory_bytes_max']==16_384
 names=[family['name'] for family in value['families']]
 assert len(names)==len(set(names))
 computed=0;tuple_bytes=0
 for family in value['families']:
  tuples=family['allowed_tuples']
  assert all(len(item)==len(family['label_names']) for item in tuples)
  encoded=[json.dumps(item,separators=(',',':')) for item in tuples]
  assert len(encoded)==len(set(encoded))
  computed+=len(tuples)*(len(family['finite_buckets'])+3 if family['semantic_type']=='histogram' else 1)
  tuple_bytes+=len(tuples)*family['bytes_per_tuple']
 assert computed==value['computed_max_series']==107 and computed<=value['max_series']==128
 assert tuple_bytes==value['declared_tuple_value_bytes']==874
 approved=value['approved_registry_metric_names']
 assert len(approved)==len(set(approved))<=value['registry_capacity_slots']
 assert set(approved)<=set(names)
 return True
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--runtime-output-dir',type=Path);args=parser.parse_args()
 files=list((ROOT/'contracts').rglob('*.schema.json'))
 for p in files:
  s=json.loads(p.read_text());Draft202012Validator.check_schema(s);closed(s)
 native=json.loads((ROOT/'crates/health-core/tests/fixtures/native-core.json').read_text())
 process=json.loads((ROOT/'crates/health-core/tests/fixtures/process-source.json').read_text())
 cgroup=json.loads((ROOT/'crates/health-core/tests/fixtures/host-cgroup.json').read_text())
 validator('source-envelope.schema.json').validate(native)
 validator('source-envelope.schema.json').validate(process)
 validator('source-envelope.schema.json').validate(cgroup)
 validator('edge-snapshot.schema.json').validate(dict(schema_version=1,status='partial',sources=[process,native,cgroup],anchors=[]))
 validator('edge-heartbeat.schema.json').validate(dict(schema_version=1,node_id='v1',edge_epoch='edge-fixture-1',state='available',guard='guarded',validator_epoch=native['process_epoch'],sources=[dict(source_id='process',age_ms='0',usable=True),dict(source_id='native_core',age_ms='0',usable=True),dict(source_id='host_cgroup',age_ms='0',usable=True)]))
 validator('edge-capabilities.schema.json').validate(dict(schema_version=1,node_id='v1',catalog_digest='a'*64,capabilities=[dict(name='basic_edge',value=dict(supported=True,enabled=True,contract_valid=True,performance_gate='not_run')),dict(name='validator_stats',value=dict(supported=False,enabled=False,contract_valid=False,performance_gate='not_run'))],sources=[dict(source_id='process',status='available'),dict(source_id='validator_stats',status='disabled')]))
 assert native['payload']['pq_sign']['succeeded']=='9007199254740993'
 assert native['content_hash']==hashlib.sha256(json.dumps(native['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
 for source in [process,cgroup]:
  assert source['content_hash']==hashlib.sha256(json.dumps(source['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
 common=validator('common.schema.json');common.validate('18446744073709551615')
 for bad in ['18446744073709551616','01','１','-1',True,1.0,9007199254740993]:assert not common.is_valid(bad),bad
 run='00000000-0000-4000-8000-000000000001';start='2026-09-29T00:00:00Z';end='2026-09-29T00:01:00Z'
 fixtures={
 'tos_get_capabilities':{},
 'tos_get_node_snapshot':dict(node_id='v1',as_of=end,max_age_seconds=30,components=['process']),
 'tos_get_metric_window':dict(node_ids=['v1'],metric_ids=['rss_bytes'],scope_id='node',start=start,end=end,step_seconds=15,mode='series',max_points_per_series=4),
 'tos_get_event_window':dict(node_ids=['v1'],scope_id='node',start=start,end=end,sources=['collector'],kinds=['warning'],correlation_id='',contains='',limit=10,cursor=''),
 'tos_get_change_history':dict(node_ids=['v1'],start=start,end=end,kinds=['restart'],limit=10,cursor=''),
 'tos_get_block_evidence':dict(node_ids=['v1'],reference_id='blk_'+'a'*16,ancestor_depth=0,max_events=10)}
 for name,fixture_args in fixtures.items():
  value=dict(run_id=run,**fixture_args);v=validator('tools/'+name+'.input.schema.json');v.validate(value)
  assert not v.is_valid(dict(value,force_refresh=True))
  bad=copy.deepcopy(value);bad['run_id']='not-a-uuid';assert not v.is_valid(bad)
  for k in ['start','end','as_of']:
   if k in value:
    bad=copy.deepcopy(value);bad[k]=bad[k].replace('Z','+00:00');assert not v.is_valid(bad)
  output=dict(schema_version=1,request_id='fixture',run_id=run,network_id='a'*64,generated_at=end,status='unavailable',data=None,evidence=[],missing_evidence=[dict(source_id='native',reason='not collected')],coverage=dict(status='unknown',missing_fields=['native'],gaps=[],sampling_policy='none'),pagination=dict(next_cursor=None,truncated=False,scan_complete=False),error=dict(code='CACHE_MISS',message='not collected',retryable=False,retry_after_seconds=None),budget=dict(remaining_calls=15,remaining_bytes=130000,expires_at=end))
  ov=validator('tools/'+name+'.output.schema.json');ov.validate(output)
  bad=copy.deepcopy(output);bad['budget']['fake']=True;assert not ov.is_valid(bad)
  bad=copy.deepcopy(output);bad['data']={'anything':'not a typed DTO'};assert not ov.is_valid(bad)
 for name in ['development-fixture.yaml','production.example.yaml']:
  value=json.loads((ROOT/'config'/name).read_text());validator('config.schema.json').validate(value)
 production=json.loads((ROOT/'config/production.example.yaml').read_text())
 missing=[k for k,v in production.items() if v is None];assert len(missing)>=8
 if args.runtime_output_dir:
  for name in fixtures:
   value=json.loads((args.runtime_output_dir/(name+'.json')).read_text())
   validator('tools/'+name+'.output.schema.json').validate(value)
   assert value['status']=='ok' and value['data'] is not None and value['error'] is None
   if name!='tos_get_capabilities': assert value['evidence'],name
   bad=copy.deepcopy(value);bad['runtime_only']=True
   assert not validator('tools/'+name+'.output.schema.json').is_valid(bad),name
  sample=json.loads((args.runtime_output_dir/'tos_get_metric_window.json').read_text())
  sample['evidence'][0]['quality']['producer_dropped']='18446744073709551616'
  assert not validator('tools/tos_get_metric_window.output.schema.json').is_valid(sample)
  boundary=json.loads((args.runtime_output_dir/'tos_get_metric_window.boundary.json').read_text())
  validator('tools/tos_get_metric_window.output.schema.json').validate(boundary)
  assert len(boundary['coverage']['missing_fields'])==64 and len(boundary['coverage']['gaps'])==32
  assert len(boundary['data']['series'][0]['coverage']['missing_fields'])==64
  assert len(boundary['data']['series'][0]['coverage']['gaps'])==32
  for name in ['edge-heartbeat','edge-capabilities','edge-snapshot']:
   value=json.loads((args.runtime_output_dir/(name+'.json')).read_text())
   validator(name+'.schema.json').validate(value)
  assert len((args.runtime_output_dir/'edge-heartbeat.json').read_bytes())<=4096
  assert len((args.runtime_output_dir/'edge-capabilities.json').read_bytes())<=32768
  assert len((args.runtime_output_dir/'edge-snapshot.json').read_bytes())<=262144
 catalog=json.loads((ROOT/'contracts/source-manifest.json').read_text())
 assert catalog['c00_contract_inventory_complete'] is True
 assert catalog['c01_source_publisher_inventory_complete'] is True
 assert catalog['complete_manifest'] is False and catalog['production_adapter_inventory_complete'] is False
 required_sources={'native_exporter','native_core','process','host_cgroup','readiness','guard','consensus_status','validator_stats','quic','vote_intent','vote_signed_commit','pq_sign','pq_verify','rocksdb','witness','diagnostic_trace'}
 assert required_sources=={source['source_id'] for source in catalog['sources']}
 for source in catalog['sources']:
  a=source['anchor'];raw=subprocess.check_output(['git','show',a['commit']+':'+a['path']],cwd=REPO)
  assert a['symbol'] in raw.decode() and hashlib.sha256(raw).hexdigest()==a['source_sha256']
  if source['fixture'] is None:
   assert not source['capability']['contract_valid'] and not source['capability']['enabled']
  else:
   fixture=ROOT/source['fixture'];assert fixture.is_file(),source['source_id']
   assert source['capability']['contract_valid']
   if source['fixture_schema']=='source-envelope.schema.json':
    value=json.loads(fixture.read_text());validator('source-envelope.schema.json').validate(value)
    expected=hashlib.sha256(json.dumps(value['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    assert value['content_hash']==expected,source['source_id']
   elif source['fixture_schema']=='openmetrics_text':
    assert fixture.stat().st_size<=2_097_152 and fixture.read_text().rstrip().endswith('# EOF')
   else: raise AssertionError(source['fixture_schema'])
 metric_manifest=json.loads((ROOT/'contracts/metric-manifest.json').read_text())
 assert check_metric_manifest(metric_manifest)
 bad_metric_manifest=copy.deepcopy(metric_manifest);bad_metric_manifest['computed_max_series']+=1
 try: check_metric_manifest(bad_metric_manifest)
 except AssertionError: pass
 else: raise AssertionError('faulty metric manifest count was accepted')
 dependencies=json.loads((ROOT/'contracts/dependency-lock.json').read_text())
 assert dependencies['rust']==(ROOT/'rust-toolchain.toml').read_text().split('channel = "',1)[1].split('"',1)[0]
 assert dependencies['rust_toolchain_sha256']==hashlib.sha256((ROOT/'rust-toolchain.toml').read_bytes()).hexdigest()
 assert dependencies['cargo_lock_sha256']==hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest()
 python_lock=dependencies['contract_python']
 assert python_lock['version']==(ROOT/'.python-version').read_text().strip()
 assert python_lock['requirements_lock_sha256']==hashlib.sha256((ROOT/python_lock['requirements_lock']).read_bytes()).hexdigest()
 assert dependencies['mcp']['enabled'] is False and dependencies['mcp']['runtime_gate']=='C08_not_run'
 assert dependencies['mcp']['version'] and dependencies['mcp']['crate_sha256']
 assert dependencies['prometheus']['enabled'] is False and dependencies['prometheus']['runtime_gate']=='C03_not_run'
 assert dependencies['prometheus']['version'] and dependencies['prometheus']['artifact_sha256']
 frozen=(ROOT/'tests/fixtures/diagnostic-v1.hex').read_text().strip()
 wire=struct.pack('<4sHHHHI16sQQQHHI',b'THD1',1,64,66,1,7,b'\x11'*16,9,10,0,2,0,0)+b'\x01\x02';assert wire.hex()==frozen
 with tempfile.TemporaryDirectory() as tmp:
  exe=Path(tmp)/'wire'
  subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(REPO),str(ROOT/'tests/native/diagnostic-wire.cpp'),'-o',str(exe)],check=True)
  assert subprocess.check_output([str(exe)],text=True).strip()==frozen
 runtime='; six actual handler successes' if args.runtime_output_dir else ''
 print(f'PASS: {len(files)} closed schemas; six tool input/error fixtures{runtime}; exact u64; source anchors; Python/C++ frozen IPC; production placeholders present')
if __name__=='__main__':main()
