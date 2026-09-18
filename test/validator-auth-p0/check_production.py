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


def grammar(text):
    """Constructor lines only: the two sources carry different explanatory comments."""
    return '\n'.join(line for line in text.strip().splitlines()
                     if line.strip() and not line.strip().startswith('//'))


def productions(text):
    """Each ';'-terminated grammar production of a design or insertion, comments stripped."""
    return [p.strip() + ';' for p in grammar(text).split(';') if p.strip()]


def bound(design, inserted):
    """Every production of the design appears exactly once across the inserted texts.

    Both copies are pinned -- the design one by the freeze record, the production
    one by this inventory -- but neither lock can see the other, so each would keep
    passing while they described different wire formats. Requiring exactly one
    match per production also refuses a second copy appearing under another insertion.
    Generalized from a single whole-file match so one design artifact can pin more
    than one production (wire.tlb carries the profile grammar and the #13 finality
    constructor), and so the node TL can be pinned the same way; a single-production
    design behaves exactly as the old whole-file match.
    """
    target = [p for text in inserted for p in productions(text)]
    design_prods = productions(design)
    return bool(design_prods) and all(target.count(p) == 1 for p in design_prods)


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
    # --out names the report file, and this is checked before any work so that a
    # caller naming a directory is told what it did. Discovering it at the write
    # instead raised IsADirectoryError after a successful reconstruction, which
    # reads exactly like the boundary having failed.
    if args.out.is_dir():
        raise SystemExit(f'--out must name the report file, not the directory {args.out}')
    baseline = json.loads((ROOT/'test/validator-auth-p0/production-baseline.json').read_text())
    manifest = ROOT/'doc/validator-auth-p0-native-insertions.json'
    insertions = json.loads(manifest.read_text())['insertions']
    actual = check(ROOT, baseline['source_sha256'], insertions)
    wire = (ROOT/'doc/validator-auth-p0/wire.tlb').read_text()
    profile = [entry['text'] for entry in insertions.get('crypto/block/block.tlb', [])]
    if not bound(wire, profile):
        raise ValueError('frozen profile grammar is not the production insertion')
    # The node TL validatorAuth signature set is pinned two-sources: a design copy
    # in test/validator-auth-p0/node-tl-grammar.tl against the tos_api.tl production
    # insertion. The design copy lives here, not in wire.tl, because check_schema
    # feeds wire.tl to the TL parser combined with tos_api.tl, where a second copy of
    # the production constructor would be a duplicate combinator id.
    node_wire = (ROOT/'test/validator-auth-p0/node-tl-grammar.tl').read_text()
    node_design = [p for p in productions(node_wire) if p.startswith('tosNode.signatureSet.')]
    node_inserted = [p for entry in insertions.get('tl/generate/scheme/tos_api.tl', [])
                     for p in productions(entry['text'])]
    if len(node_design) != 1 or node_inserted.count(node_design[0]) != 1:
        raise ValueError('node TL validatorAuth grammar is not two-sources bound')
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
    # The binding must notice drift from either side, a removed insertion and a
    # duplicated one; a comment-only difference is not drift.
    if not bound('a#1 x:uint8 = A;', ['// production\na#1 x:uint8 = A;']):
        raise RuntimeError('profile binding rejects a comment-only difference')
    for design, inserted in (('a#1 x:uint16 = A;', ['a#1 x:uint8 = A;']),
                             ('a#1 x:uint8 = A;', ['a#1 x:uint16 = A;']),
                             ('a#1 x:uint8 = A;', []),
                             ('a#1 x:uint8 = A;', ['a#1 x:uint8 = A;', 'a#1 x:uint8 = A;'])):
        if bound(design, inserted):
            raise RuntimeError('profile binding negative control survived')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dict(success=True, base=baseline['base'], source_sha256=actual,
                                       preserved_sha256=baseline['source_sha256'],
                                       insertions_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                                       profile_grammar_bound='wire.tlb equals the block.tlb insertion',
                                       negative_control='changed original and inserted bytes rejected'), indent=2)+'\n')
    print('PASS:', len(actual)-len(insertions), 'whole files unchanged;', len(insertions),
          'files preserve all historical bytes with exact native insertions;',
          'frozen profile grammar bound to production; negative controls rejected')


if __name__ == '__main__':
    main()
