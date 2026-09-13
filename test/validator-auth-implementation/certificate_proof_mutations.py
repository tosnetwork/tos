"""Compile certificate proof/response guard removals; require named assertions."""
import argparse,json,shutil,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
CPP=[
 ('verify-request-anchor','certificate-proof','if (request.anchor_ != anchor) return Error{"certificate-anchor"};',''),
 ('independent-genesis','certificate-proof','|| expected.genesis_root_ != chain.genesis_root',''),
 ('early-context-admission','certificate-proof','if (cert.value().duty_ != expected) return Error{"expected-context"};',''),
 ('policy-proof-authentication','certificate-proof','if (!policy.ok()) return policy.error();',''),
 ('get-request-anchor','certificate-proof','q.value().anchor_ != anchor ||',''),
 ('get-response-anchor','certificate-proof','|| r.value().anchor_ != anchor',''),
 ('get-era','certificate-proof','r.value().era_ != 1 ||',''),
 ('get-fingerprint','certificate-proof','|| r.value().interface_digest_ != interface_fingerprint',''),
 ('get-certificate-id','certificate-proof','if (verified.value().certificate().certificate_id() != q.value().certificate_id_) return Error{"certificate-id"};',''),
 ('claimed-weight','certificate-proof','if (r.value() != actual.value()) return Error{"verified-result"};',''),
 ('request-byte-admission','certificate-proof','request.size() > 2000000 ||',''),
 ('response-byte-admission','certificate-proof','|| response.size() > 2000000',''),
 ('native-signature-refusal','verify','if (!valid.value()) return Error{"signature"};',''),
 ('native-quorum-refusal','verify','if (quorum && signed_weight.value() < required_weight.value()) return Error{"quorum"};',''),
]
RUST=[
 ('verify-request-anchor','validator-auth-native/src/certificate_proof.rs','if request.anchor != *anchor { return Err(Error("certificate-anchor")); }',''),
 ('independent-genesis','validator-auth-native/src/certificate_proof.rs','|| expected.genesis_root != chain.genesis_root',''),
 ('early-context-admission','validator-auth-native/src/certificate_proof.rs','if certificate.duty != *expected { return Err(Error("expected-context")); }',''),
 ('policy-proof-authentication','validator-auth-native/src/certificate_proof.rs',')?; let certificate = snapshot.verify_certificate',').ok(); let certificate = snapshot.verify_certificate'),
 ('get-request-anchor','validator-auth-native/src/certificate_proof.rs','q.anchor != *anchor ||',''),
 ('get-response-anchor','validator-auth-native/src/certificate_proof.rs','|| r.anchor != *anchor',''),
 ('get-era','validator-auth-native/src/certificate_proof.rs','r.era != 1 ||',''),
 ('get-fingerprint','validator-auth-native/src/certificate_proof.rs','|| r.interface_digest != INTERFACE_FINGERPRINT',''),
 ('get-certificate-id','validator-auth-native/src/certificate_proof.rs','if *verified.certificate().certificate_id() != q.certificate_id { return Err(Error("certificate-id")); }',''),
 ('claimed-weight','validator-auth-native/src/certificate_proof.rs','if r != verified.result()? { return Err(Error("verified-result")); }',''),
 ('request-byte-admission','validator-auth-native/src/certificate_proof.rs','request.len() > 2_000_000 ||',''),
 ('response-byte-admission','validator-auth-native/src/certificate_proof.rs','|| response.len() > 2_000_000',''),
 ('native-signature-refusal','validator-auth/src/verify.rs','if !key.verify(&statement, signature) { return Err(Error("signature")); }',''),
 ('native-quorum-refusal','validator-auth/src/verify.rs','if quorum && signed_weight < required_weight { return Err(Error("quorum")); }',''),
]
def execute(command):
 p=subprocess.run(command,capture_output=True,text=True)
 if p.returncode:raise RuntimeError('mutation build failed: '+p.stdout+p.stderr)
def verify(result,label=None):
 if label is None:assert result.returncode==0,result.stderr
 else:
  assert result.returncode==1 and result.stderr.startswith('ASSERTION: '+label) and 'panicked at' not in result.stderr,(label,result.stderr)
def cpp(args):
 folder=args.build.resolve()/'test/validator-auth-implementation';report=[]
 for module in ('certificate-proof','verify'):
  source=folder/f'certificate-mutated-{module}.cpp';original=source.read_text()
  def run(text):
   source.write_text(text)
   execute(['cmake','--build',str(args.build.resolve()),'--target',f'test-p0-certificate-{module}-mutant','-j2'])
   return subprocess.run([str(folder/f'test-p0-certificate-{module}-mutant'),str(args.fixtures.resolve())],capture_output=True,text=True)
  verify(run(original))
  try:
   for label,part,before,after in CPP:
    if part!=module:continue
    verify(run(replace_once(original,before,after)),label)
    report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED: cpp',label,flush=True)
  finally:verify(run(original))
 return report
def rust(args,cases=RUST,binary="certificate-proof-conformance"):
 report=[]
 with tempfile.TemporaryDirectory(prefix='p0-certificate-mut-') as tmp:
  src=Path(tmp)/'src';src.mkdir()
  for part in ('validator-auth-native','validator-auth'):
   shutil.copytree(ROOT/'tosctl/src'/part,src/part,ignore=shutil.ignore_patterns('target'))
  for path in (ROOT/'tosctl/src').iterdir():
   if path.is_dir() and path.name not in ('target','validator-auth-native','validator-auth'):(src/path.name).symlink_to(path,target_is_directory=True)
  crate=src/'validator-auth-native';manifest=crate/'Cargo.toml';manifest.write_text(manifest.read_text()+'\n[workspace]\n');shutil.copy2(ROOT/'tosctl/src/Cargo.lock',crate/'Cargo.lock')
  def run():
   execute(['cargo','build','--offline','--manifest-path',str(manifest),'--bin',binary])
   return subprocess.run([str(crate/'target/debug'/binary),str(args.fixtures.resolve())],capture_output=True,text=True)
  verify(run())
  for label,file,before,after in cases:
   path=src/file;original=path.read_text();path.write_text(replace_once(original,before,after))
   try:
    verify(run(),label);report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED: rust',label,flush=True)
   finally:path.write_text(original)
  verify(run())
 return report
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--language',choices=['cpp','rust'],required=True);p.add_argument('--build',type=Path);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
 report=cpp(args) if args.language=='cpp' else rust(args)
 args.out.write_text(json.dumps(dict(language=args.language,certificate_proof_mutations=report,restored_baselines=True),indent=2)+'\n')
