"""Prove historical bytes survive exact, separately inventoried native insertions."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def preserved(raw, insertions):
    original = bytearray(); source = 0
    for insertion in insertions:
        offset, text = insertion['offset'], insertion['text'].encode()
        if type(offset) is not int or offset < len(original) or not text:
            raise ValueError('invalid native insertion')
        length = offset - len(original)
        original.extend(raw[source:source+length]); source += length
        if raw[source:source+len(text)] != text:
            raise ValueError('native insertion changed')
        source += len(text)
    original.extend(raw[source:])
    return bytes(original)


def check(root, expected, insertions=None):
    insertions = insertions or {}
    if not set(insertions) <= set(expected):
        raise ValueError('native insertion outside inventory')
    raw = {name: (root/name).read_bytes() for name in expected}
    actual = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}
    retained = {name: hashlib.sha256(preserved(value, insertions.get(name, []))).hexdigest()
                for name, value in raw.items()}
    if retained != expected:
        raise ValueError('production/historical boundary changed')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((ROOT/'test/validator-auth-p0/production-baseline.json').read_text())
    manifest = ROOT/'doc/validator-auth-p0-native-insertions.json'
    insertions = json.loads(manifest.read_text())['insertions']
    actual = check(ROOT, baseline['source_sha256'], insertions)
    # A silent inventory is not evidence: prove it detects a changed byte.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root/'probe').write_bytes(b'original')
        expected = {'probe': hashlib.sha256(b'original').hexdigest()}
        check(root, expected); (root/'probe').write_bytes(b'changed')
        try:
            check(root, expected)
        except ValueError:
            pass
        else:
            raise RuntimeError('boundary negative control survived')
        # Both historical and newly inserted bytes are checked, not an exemption
        # for every byte in a file that happens to contain an adapter.
        (root/'probe').write_bytes(b'original')
        additions = {'probe': [{'offset': 3, 'text': '-native-'}]}
        (root/'probe').write_bytes(b'ori-native-ginal'); check(root, expected, additions)
        for changed in (b'ori-nativX-ginal', b'ori-native-ginaX'):
            (root/'probe').write_bytes(changed)
            try:
                check(root, expected, additions)
            except ValueError:
                pass
            else:
                raise RuntimeError('native insertion negative control survived')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dict(success=True, base=baseline['base'], source_sha256=actual,
                                       preserved_sha256=baseline['source_sha256'],
                                       insertions_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                                       negative_control='changed original and inserted bytes rejected'), indent=2)+'\n')
    print('PASS:', len(actual)-len(insertions), 'whole files unchanged;', len(insertions),
          'files preserve all historical bytes with exact native insertions; negative controls rejected')


if __name__ == '__main__':
    main()
