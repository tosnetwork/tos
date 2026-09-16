"""Compile native config/client/voting guard removals and run the actual test binaries."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
BLOCK='block/src/validators.rs'
PARSE='block-json/src/deserialize.rs'
SERIALIZE='block-json/src/serialize.rs'
CONTROL='node-control/control-client/src/config_params.rs'
JSON='node-control/control-client/src/config_json.rs'
SERVICE='node-control/service/src/voting/voting_provider.rs'
MUTATIONS=[
 ('control-zero-binding','control_client',BLOCK,'if id.is_zero() {','if false {'),
 ('control-uppercase-binding','control_client',BLOCK,"!text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))",'false'),
 ('control-binding-tail','control_client',BLOCK,'#[serde(deny_unknown_fields)]',''),
 ('json-binding-export','chain_block_json',SERIALIZE,'serialize_field(&mut map, "auth_binding", serde_json::to_value(binding)?);',''),
 ('json-native-roundtrip','chain_block_json',PARSE,'descr.auth_binding = Some(binding);',''),
 ('json-sequence-export','chain_block_json',SERIALIZE,'serialize_field(&mut map, "mc_seq_no_since", v.mc_seq_no_since);',''),
 ('json-native-roundtrip','chain_block_json',PARSE,'descr.mc_seq_no_since = p.get_num32("mc_seq_no_since")?;',''),
 ('json-committee-ceiling','chain_block_json',PARSE,'list.len() > 400','false'),
 ('json-count-binding','chain_block_json',PARSE,'usize::from(config.get_num16("total")?) != list.len()','false'),
 ('control-binding','control_client',CONTROL,'mc_seq_no_since, auth_binding,','mc_seq_no_since, auth_binding: None,'),
 ('control-missing-adnl','control_client',CONTROL,'adnl_addr.is_none() ||',''),
 ('control-sequence-conflict','control_client',CONTROL,'mc_seq_no_since != 0','false'),
 ('control-number-total','control_client',CONTROL,'usize::from(total) != json_list.len()','false'),
 ('control-committee-ceiling','control_client',CONTROL,'list.len() > 400','false'),
 ('control-sequence-preserved','control_client',CONTROL,'mc_seq_no_since, auth_binding,','mc_seq_no_since: 0, auth_binding,'),
 ('control-duplicate-json','control_client',JSON,'if values.contains_key(&key) { return Err(de::Error::custom("duplicate configuration JSON key")); }',''),
 ('control-json-byte-limit','control_client',JSON,'if bytes.len() > 4_194_304 { anyhow::bail!("configuration JSON byte limit"); }',''),
 ('control-json-value-limit','control_client',JSON,'*self.0 = self.0.checked_sub(1).ok_or_else(|| de::Error::custom("configuration JSON value limit"))?;',''),
 ('control-json-trailing','control_client',JSON,'decoder.end()?;',''),
 ('voting-binding','service',SERVICE,'control_client::config_params::parse_config_param_34(&bytes)','control_client::config_params::parse_config_param_34(String::from_utf8(bytes)?.replace("\\\"auth_binding\\\"", "\\\"ignored_binding\\\"").as_bytes())'),
]
for field,width in [('utime_since',32),('utime_until',32),('main',16),('total',16)]:
 prefix=f'let {field} = map .get("{field}") .and_then(|value| value.as_u64())'
 MUTATIONS.append(('control-number-'+field,'control_client',CONTROL,prefix+f' .and_then(|v| u{width}::try_from(v).ok())',prefix+f' .map(|v| v as u{width})'))
def main(args):
 with tempfile.TemporaryDirectory(prefix='p0-json-guards-') as tmp:
  root=Path(tmp);src=root/'tosctl/src';src.mkdir(parents=True)
  original=ROOT/'tosctl/src'
  for path in original.iterdir():
   if path.name in ('target','.DS_Store'):continue
   target=src/path.name
   if path.name in ('block','block-json'):
    shutil.copytree(path,target,ignore=shutil.ignore_patterns('target'))
   elif path.name=='node-control':
    target.mkdir()
    for child in path.iterdir():
     if child.name in ('control-client','service'):
      shutil.copytree(child,target/child.name,ignore=shutil.ignore_patterns('target'))
     else:(target/child.name).symlink_to(child,target_is_directory=child.is_dir())
   elif path.is_dir():target.symlink_to(path,target_is_directory=True)
   else:shutil.copy2(path,target)
  for name in ('common','config','crypto'):
   path=ROOT/'tosctl'/name
   if path.exists():(root/'tosctl'/name).symlink_to(path,target_is_directory=path.is_dir())
  build=['cargo','test','--locked','--manifest-path',str(src/'Cargo.toml'),'-p','chain_block_json','-p','control-client','-p','service','--lib','--no-run','--message-format=json']
  def compile_tests():
   result=subprocess.run(build,capture_output=True,text=True)
   if result.returncode:raise RuntimeError(result.stdout+result.stderr)
   binaries={}
   for line in result.stdout.splitlines():
    message=json.loads(line)
    if message.get('reason')=='compiler-artifact' and message.get('executable') and message.get('profile',{}).get('test'):
     binaries[message['target']['name']]=message['executable']
   assert {'chain_block_json','control_client','service'}<=binaries.keys()
   return binaries
  def execute(binary):return subprocess.run([binary,'validator_auth_','--nocapture'],capture_output=True,text=True)
  def baseline():
   for binary in compile_tests().values():
    result=execute(binary);assert result.returncode==0,result.stdout+result.stderr
  baseline();report=[]
  for label,package,file,before,after in MUTATIONS:
   path=src/file;original=path.read_text()
   try:
    path.write_text(replace_once(original,before,after))
    result=execute(compile_tests()[package]);log=result.stdout+result.stderr
    assert result.returncode==101 and 'panicked at' in log and label in log,(label,result.returncode,log)
    report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
   finally:path.write_text(original)
  baseline()
 args.out.write_text(json.dumps(dict(config_json_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
