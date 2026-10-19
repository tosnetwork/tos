# Public pre-beacon bundle comparison

Run from the repository root, with Python 3 and network access. This downloads
the pinned published archive, extracts the three members in memory, and compares
them byte for byte with the Git revision used as finalisation input. It does not
compare the already-finalised working tree.

```sh
python3 - <<'PYTHON'
import hashlib
import io
import subprocess
import tarfile
import urllib.request

url = 'https://github.com/tosnetwork/tos/releases/download/shielded-pool-phase2-contribution-5/tos-phase2-contribution-5-onemailweb3-design.tar.gz'
revision = 'c94ff1ceb819c6cafeba06dbb0b9de0ce652ad65'
expected = 'ef1c096b4395632d0f21f63bcaa6cc831df70d99e24924c380312424c1e4944d'
with urllib.request.urlopen(url) as response:
    bundle = response.read()
digest = hashlib.sha256(bundle).hexdigest()
assert digest == expected, 'published archive digest mismatch'
print('archive sha256 ' + digest)
with tarfile.open(fileobj=io.BytesIO(bundle), mode='r:gz') as archive:
    for name in ('ceremony.json', 'key.bin', 'contributions.bin'):
        member = archive.extractfile('ceremony/' + name)
        assert member is not None
        published = member.read()
        before = subprocess.check_output(['git', 'show', revision + ':artifacts/phase2/ceremony/' + name])
        assert published == before, name + ': byte comparison failed'
        print(name + ': byte-identical; bytes=' + str(len(before)) + '; sha256=' + hashlib.sha256(before).hexdigest())
print('PASS: all three published files match the pre-finalisation source revision')
PYTHON
```

Executed on 2026-10-10, exit status 0. Bounded output:

```text
archive sha256 ef1c096b4395632d0f21f63bcaa6cc831df70d99e24924c380312424c1e4944d
ceremony.json: byte-identical; bytes=1690; sha256=3526b1e7791264b067bd2e95c0b82051b559285cdd3259c73ffc8fc4af8e9091
key.bin: byte-identical; bytes=5949456; sha256=b0bc8de88dd92e0ae9efeec2c2ca72cb734004324df903e20507ab736a67189b
contributions.bin: byte-identical; bytes=3360; sha256=7f9d672446e0f9d900ccab111d1c047afd99fa19aa21d7cf7a4bbd7e93328f32
PASS: all three published files match the pre-finalisation source revision
```
