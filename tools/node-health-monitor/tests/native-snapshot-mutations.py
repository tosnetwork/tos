#!/usr/bin/env python3
"""Build native mutants and require actual assertion failures, then restore source."""
import argparse,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
p=argparse.ArgumentParser();p.add_argument('build');p.add_argument('--cmake',default='cmake');args=p.parse_args()
B=Path(args.build).resolve();binary=B/'test-health-native-snapshot'
header='metrics/native-core-snapshot.h';exporter='metrics/prometheus-exporter.cpp'
CASES=[
('network-lowercase',header,'return td::hex_encode(root_hash);','return std::string(64, \'A\');',None),
('disabled-endpoint',exporter,'!loopback_ || !core_publisher_.configured()','!loopback_','disabled'),
('histogram-wire-name',exporter,'.suffix = "bucket"','.suffix = "_bucket"','fast'),
('exact-u64',header,'const auto g = std::to_string(generation);','const auto g = std::to_string(static_cast<double>(generation));',None),
('source-age',header,'|| now - sampled_at > 30','',None),
('identity-immutable',header,'(!node_.empty() && node_ != value)','false',None),
('typed-read-no-collection',exporter,'if (request->url() == "/health-snapshot") {','if (request->url() == "/health-snapshot") { td::actor::send_closure(main_collector_.get(), &metrics::MultiCollector::collect, td::make_promise([](td::Result<metrics::MetricSet>) {}));','fast'),
('owner-wait-deadline',exporter,'alarm_timestamp() = td::Timestamp::in(2.0);','alarm_timestamp() = td::Timestamp::never();','slow'),
('actual-lease-after-timeout',exporter,'// The actual-work lease remains held until every child completes.','admission_.finish(td::Timestamp::now().at(), false, 0);','lease'),
]
def build():
 r=subprocess.run([args.cmake,'--build',str(B),'--target','test-health-native-snapshot','-j2'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if r.returncode:raise RuntimeError('compile failed; not a killed mutant\n'+r.stdout)
def run(mode):
 cmd=[str(binary)] if mode is None else [sys.executable,str(ROOT/'tools/node-health-monitor/tests/native-snapshot-http.py'),str(binary),'--mode',mode]
 return subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
selected=os.environ.get('HEALTH_NATIVE_MUTATIONS','').split(',')
for name,file,old,new,mode in CASES:
 if selected!=[''] and name not in selected:continue
 path=ROOT/file;original=path.read_text()
 build();baseline=run(mode)
 if baseline.returncode:raise RuntimeError(name+' baseline failed\n'+baseline.stdout)
 if original.count(old)!=1:raise RuntimeError(name+' target not unique')
 try:
  path.write_text(original.replace(old,new));build();result=run(mode)
  if result.returncode==0 or not any(s in result.stdout for s in ('Check','AssertionError')):raise RuntimeError(name+' no assertion failure\n'+result.stdout)
  print(name+': compiled mutant killed',flush=True)
 finally:path.write_text(original)
build();print('native mutation source restored')
