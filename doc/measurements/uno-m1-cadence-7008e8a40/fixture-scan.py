import base64,collections,gzip,hashlib,io,json,lzma,pathlib,re,subprocess,tarfile,zipfile
ROOT=pathlib.Path('/home/tomi/tos-m2');TAG=bytes.fromhex('b7226bea');counts=collections.Counter();hits=[]
def scan(name,b):
 counts['streams']+=1;counts['bytes']+=len(b)
 for needle,label in ((TAG,'big-endian'),(TAG[::-1],'little-endian')):
  if needle in b:hits.append({'path':name,'encoding':label,'count':b.count(needle),'sha256':hashlib.sha256(b).hexdigest()})
 # BOC encodings in JSON, source literals and files. Whole-file folded base64
 # additionally covers line-wrapped base64 fixtures; no text-default decoding.
 tokens=re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}',b)
 if name.endswith(('.base64','.b64')):tokens.append(re.sub(rb'\s+',b'',b))
 for t in tokens:
  if len(t)%4:continue
  try:d=base64.b64decode(t,validate=True)
  except ValueError:continue
  if d.startswith((bytes.fromhex('b5ee9c72'),bytes.fromhex('68ff65f3'),bytes.fromhex('acc3a728'))):
   counts['base64_bocs']+=1
   if TAG in d:hits.append({'path':name,'encoding':'base64 BOC','count':d.count(TAG),'decoded_sha256':hashlib.sha256(d).hexdigest()})
def inspect(name,b):
 scan(name,b)
 if name.endswith(('.tar.gz','.tgz','.tar','.tar.xz','.tar.zst')):
  if name.endswith('.zst'):b=subprocess.check_output(['zstd','-dc'],input=b)
  with tarfile.open(fileobj=io.BytesIO(b),mode='r:*') as ar:
   for m in ar:
    if m.isfile():counts['archive_members']+=1;scan(name+'::'+m.name,ar.extractfile(m).read())
 elif name.endswith('.zip'):
  with zipfile.ZipFile(io.BytesIO(b)) as ar:
   for n in ar.namelist():counts['archive_members']+=1;scan(name+'::'+n,ar.read(n))
 elif name.endswith('.gz'):scan(name+'::gunzip',gzip.decompress(b))
 elif name.endswith('.xz'):scan(name+'::unxz',lzma.decompress(b))
# Calibrate detection of raw and encoded BOC bytes.
boc=bytes.fromhex('b5ee9c72010101010006000008')+TAG
scan('calibration.raw',boc);scan('calibration.base64',base64.b64encode(boc))
assert {h['path'] for h in hits}=={'calibration.raw','calibration.base64'}
calibration=hits[:];hits.clear();counts.clear()
paths=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0');manifest=hashlib.sha256()
for name in filter(None,paths):
 p=ROOT/name
 if not p.is_file() or p.is_symlink():continue
 b=p.read_bytes();manifest.update(name.encode()+b'\0'+hashlib.sha256(b).digest());counts['tracked_files']+=1;inspect(name,b)
report={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'counts':dict(counts),'manifest_sha256':manifest.hexdigest(),'hits':hits,'positive_calibration':calibration,'scope':'All tracked regular files including tostester; raw BE/LE bytes, standard base64 BOC tokens and folded base64 files, tar/gzip/xz/zstd/zip members. Does not inspect ignored runtime build databases, encrypted or arbitrary custom encodings; no history rewritten.'}
pathlib.Path('/tmp/uno-b-cadence-fixture-scan.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
