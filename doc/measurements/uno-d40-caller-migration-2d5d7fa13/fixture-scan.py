import base64,collections,gzip,hashlib,io,json,lzma,pathlib,re,subprocess,tarfile,zipfile
ROOT=pathlib.Path('/home/tomi/tos-m2');TAG=bytes.fromhex('6e1fa05f');counts=collections.Counter();hits=[]
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
header=(ROOT/'crypto/block/block-auto.h').read_text()
uno_tags={}
for typ,body in re.findall(r'struct (UnoV2\w+) final : TLB_Complex \{(.*?)\n\};',header,re.S):
 for tag in re.findall(r'0x([0-9a-fA-F]+)',re.search(r'cons_tag\[\d+\] = \{([^}]+)\}',body)[1]):uno_tags[tag.lower().zfill(8)]=typ
text_hits=[];retired_text_hits=[]
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
tree=subprocess.check_output(['git','ls-tree','-r','-z',commit],cwd=ROOT).split(b'\0')
entries={}
for row in filter(None,tree):
 meta,name=row.split(b'\t',1);mode,typ,oid=meta.split()
 if mode in (b'100644',b'100755'):entries[name.decode()]=oid
paths=list(entries);manifest=hashlib.sha256()
batch=subprocess.Popen(['git','cat-file','--batch'],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
for name in filter(None,paths):
 batch.stdin.write(entries[name]+b'\n');batch.stdin.flush()
 record=batch.stdout.readline().split();assert record[1]==b'blob'
 b=batch.stdout.read(int(record[2]));assert batch.stdout.read(1)==b'\n'
 for n,line in enumerate(b.splitlines(),1):
  if b'6e1fa05f' in line.lower():retired_text_hits.append({'path':name,'line':n,'count':line.lower().count(b'6e1fa05f')})
  for token in re.findall(rb'(?i)(?:0x|x\{|#)([0-9a-f]{1,8})(?![0-9a-f])',line):
   tag=token.decode().lower().zfill(8)
   if tag in uno_tags or tag=='6e1fa05f':text_hits.append({'path':name,'line':n,'tag':tag,'type':uno_tags.get(tag,'retired cadence')})
 manifest.update(name.encode()+b'\0'+hashlib.sha256(b).digest());counts['tracked_files']+=1;inspect(name,b)
batch.stdin.close();assert batch.wait()==0
report={'input_mode':'committed regular-file blobs (git cat-file --batch), not working-tree files','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'generated_header_sha256':hashlib.sha256(header.encode()).hexdigest(),'retired_text_hits':retired_text_hits,'literal_candidates':text_hits,'counts':dict(counts),'manifest_sha256':manifest.hexdigest(),'hits':hits,'positive_calibration':calibration,'scope':'All tracked regular files including tostester; raw BE/LE bytes, standard base64 BOC tokens and folded base64 files, tar/gzip/xz/zstd/zip members. Does not inspect ignored runtime build databases, encrypted or arbitrary custom encodings; no history rewritten.'}
pathlib.Path('/tmp/uno-d40-migration/fixture-scan.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
