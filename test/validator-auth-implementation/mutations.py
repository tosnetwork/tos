"""Compile isolated production guard mutations; crashes/build errors are never kills."""
import argparse,json,os,shlex,shutil,subprocess,sys,tempfile
from pathlib import Path
from mutation_support import replace_once
ROOT=Path(__file__).resolve().parents[2]
MUTATIONS=[
 ('chunk-hash','transfer','transfer.cpp','if(h.value()!=ref.chunk_hashes_[index])return Error{"chunk-hash"};',''),
 ('object-hash','transfer','transfer.cpp','if(id.value()!=ref.object_id_)return Error{"object-hash"};',''),
 ('storage-quota','transfer','transfer.cpp','ref.byte_length_>limit_-used_||',''),
 ('read-budget','transfer','transfer.cpp','if(size>remaining_)return Error{"attachment-budget"};',''),
 ('json-duplicate','transport','transport.cpp','if(fields.contains(key.value()))return Error{"duplicate-json-key"};',''),
 ('request-correlation','transport','transport.cpp','if(id.value()!=frame.request_id)return Error{"request-correlation"};',''),
 ('error-retry','transport','transport.cpp','if(error.retryable_!=static_cast<unsigned>(read&&error.code_>=10&&error.code_<=12))return Error{"error-retry"};',''),
 ('flags','core','codec.h','if (b[6] != 0 || b[7] != 0) fail("flags");',''),
 ('public-key-subgroup','core','crypto.cpp',' || crypto_core_ed25519_is_valid_point(bytes.data())!=1',''),
 ('signature-equation','core','crypto.cpp','return sodium_memcmp(left.data(),right.data(),32)==0;','return true;'),
 ('expected-duty','core','verify.cpp','if(duty!=expected)return Error{"expected-context"};',''),
 ('quorum','core','verify.cpp','if(quorum&&signed_weight.value()<required_weight.value())return Error{"quorum"};',''),
 ('all-signatures','core','verify.cpp','if(!valid.value())return Error{"signature"};',''),
 ('lifecycle-predecessor','lifecycle','lifecycle.cpp','if(update.previous_!=predecessor.value())return Error{"predecessor"};',''),
 ('consecutive-blocks','lifecycle','lifecycle.cpp','if(parent_coordinate>=max_coordinate-1||coordinate!=parent_coordinate+1)return Error{"block-gap"};',''),
]
def main(args):
 flags=shlex.split(subprocess.run(['pkg-config','--cflags','--libs','libsodium'],capture_output=True,text=True,check=True).stdout)
 results=[]
 with tempfile.TemporaryDirectory(prefix='p0-production-mutations-') as folder:
  folder=Path(folder);shadow=folder/'validator/auth';shadow.mkdir(parents=True)
  def build(suite):
   driver={'transfer':'transfer-test.cpp','transport':'transport-driver.cpp','core':'driver.cpp','lifecycle':'driver.cpp'}[suite]
   sources=['crypto.cpp']+(['transfer.cpp'] if suite=='transfer' else ['transport.cpp'] if suite=='transport' else ['verify.cpp','lifecycle.cpp'])
   binary=folder/'driver'
   command=[os.environ.get('CXX','c++'),'-std=c++20','-O1','-DTOS_AUTH_CORE_ONLY','-I'+str(folder),str(ROOT/'test/validator-auth-implementation'/driver),*[str(shadow/s) for s in sources],*flags,'-o',str(binary)]
   p=subprocess.run(command,capture_output=True,text=True)
   if p.returncode:raise RuntimeError('mutation did not compile: '+p.stderr)
   return binary
  def test(suite,binary):
   if suite=='transfer':command=[str(binary)]
   elif suite=='transport':command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_transport.py'),'--driver',str(binary)]
   elif suite=='lifecycle':command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check_lifecycle.py'),'--cpp',str(binary),'--out',str(folder/'lifecycle.json')]
   else:command=[sys.executable,str(ROOT/'test/validator-auth-implementation/check.py'),'--cpp',str(binary),'--rust',str(args.rust.resolve()),'--core-only','--out',str(folder/'core.json')]
   return subprocess.run(command,capture_output=True,text=True)
  for path in (ROOT/'validator/auth').glob('*'):
   if path.is_file():shutil.copy2(path,shadow/path.name)
  for suite in ('transfer','transport','core','lifecycle'):
   p=test(suite,build(suite));assert p.returncode==0,(suite,p.stderr)
   print('BASELINE:',suite,flush=True)
  for name,suite,file,before,after in MUTATIONS:
   path=shadow/file;original=path.read_text()
   path.write_text(replace_once(original,before,after))
   try:
    binary=build(suite);p=test(suite,binary)
    marker='ASSERTION:' if suite=='transfer' else 'AssertionError'
    # Only a test assertion caused by the successfully compiled mutant counts.
    if p.returncode!=1 or marker not in p.stderr or 'Traceback' in p.stderr and marker=='ASSERTION:':
     raise AssertionError((name,'survived or invalid failure',p.returncode,p.stderr))
    if any(token in p.stderr for token in ('Segmentation fault','AddressSanitizer','ImportError','SyntaxError','returncode=-')):
     raise AssertionError((name,'invalid mutation kill',p.stderr))
    results.append({'guard':name,'compiled':True,'assertion_failed':True});print('KILLED:',name,flush=True)
   finally:path.write_text(original)
  for suite in ('transfer','transport','core','lifecycle'):
   p=test(suite,build(suite));assert p.returncode==0,(suite,p.stderr)
 args.out.write_text(json.dumps({'production_cpp_mutations':results,'restored_baselines':True},indent=2)+'\n')
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--rust',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);main(parser.parse_args())
