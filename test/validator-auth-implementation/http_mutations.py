"""Compile native HTTP guard removals and demand the named behavioral failure."""
import argparse,json,shutil,subprocess,sys,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
CPP=[
 ('response-body-bound','parsed.length > max_http_body','false'),
 ('response-header-bound','head.size() >= max_http_head','head.size() >= 65536'),
 ('response-duplicate-header','parsed.fields.contains(name)','false'),
 ('response-compression','name == "content-encoding"','false'),
 ('response-transfer-encoding','name == "transfer-encoding"','false'),
 ('response-upgrade','name == "upgrade"','false'),
 ('response-header-count','parsed.fields.size() >= 16','false'),
 ('response-length-leading-zero',"(length->second.size() > 1 && length->second.front() == '0')",'false'),
 ('response-redirect','(status >= 300 && status < 400)','false'),
 ('response-version','h.line.substr(0, 9) != "HTTP/1.1 "','false'),
 ('response-peer-uid','credentials.value() != expected','false'),
 ('request-version','head.line.substr(second + 1) != "HTTP/1.1"','false'),
 ('request-get-body','request.verb == "GET" && head.length != 0','false'),
 ('request-host','!head.fields.contains("host") || head.fields.at("host").empty()','false'),
]
RUST=[
 ('response-body-bound','if size > MAX_BODY {','if false {'),
 ('response-header-bound','if header.len() >= MAX_HEAD {','if header.len() >= 65536 {'),
 ('response-duplicate-header',"fields.insert(name, value.trim_matches(' ')).is_some()","fields.insert(name, value.trim_matches(' ')).is_some() && false"),
 ('response-compression','"transfer-encoding" | "content-encoding" | "upgrade" | "expect"','"transfer-encoding" | "upgrade" | "expect"'),
 ('response-transfer-encoding','"transfer-encoding" | "content-encoding" | "upgrade" | "expect"','"content-encoding" | "upgrade" | "expect"'),
 ('response-upgrade','"transfer-encoding" | "content-encoding" | "upgrade" | "expect"','"transfer-encoding" | "content-encoding" | "expect"'),
 ('response-header-count','fields.len() >= 16','false'),
 ('response-length-leading-zero',"(length.len() > 1 && length.starts_with('0'))",'false'),
 ('response-redirect','(300..400).contains(&status)','false'),
 ('response-version','!line.starts_with("HTTP/1.1 ")','false'),
 ('response-peer-uid','authenticate(fd.as_raw_fd(), expected)?;','let _ = expected;'),
]
def main(args):
 report=[]
 with tempfile.TemporaryDirectory(prefix='p0-http-mut-') as tmp:
  tmp=Path(tmp)
  if args.language=='rust':
   shutil.copytree(ROOT/'tosctl/src/validator-auth',tmp/'crate')
   shutil.copytree(ROOT/'tosctl/src/validator-auth-crypto',tmp/'validator-auth-crypto')
   manifest=tmp/'crate/Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n')
   shutil.copy2(ROOT/'tosctl/src/Cargo.lock',tmp/'crate/Cargo.lock')
   source=tmp/'crate/src/unix_http.rs';binary=tmp/'crate/target/debug/conformance'
   command=['cargo','build','--offline','--manifest-path',str(manifest),'--bin','conformance']
   mutations=RUST
  else:
   folder=args.build.resolve()/'test/validator-auth-implementation';source=folder/'mutated-local-channel.cpp';binary=folder/'test-p0-http-mutant'
   command=['cmake','--build',str(args.build),'--target','test-p0-http-mutant','-j2'];mutations=CPP
  original=source.read_text()
  def build(text):
   source.write_text(text)
   result=subprocess.run(command,capture_output=True,text=True)
   if result.returncode:raise RuntimeError('mutation build failed: '+result.stdout+result.stderr)
  def test(case=None):
   command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_http.py'),'--'+args.language,str(binary),'--out',str(tmp/'http.json')]
   if case:command+=['--case',case]
   return subprocess.run(command,capture_output=True,text=True)
  build(original);base=test();assert base.returncode==0,base.stderr
  try:
   for case,before,after in mutations:
    build(replace_once(original,before,after));result=test(case)
    assert result.returncode==1 and 'AssertionError:' in result.stderr and repr(case) in result.stderr and 'RuntimeError' not in result.stderr,(case,'invalid kill',result.stderr)
    report.append(dict(language=args.language,guard=case,compiled=True,assertion_failed=True));print('KILLED:',args.language,case,flush=True)
  finally:
   build(original);base=test();assert base.returncode==0,base.stderr
 args.out.write_text(json.dumps(dict(http_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
