"""Independently replay real archived inputs through the measured classifier."""
import ast
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import sys

HERE = Path(__file__).resolve().parent
report = json.loads((HERE / 'report.json').read_text())
archive = HERE / 'raw-run.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == report['archive_sha256']
with tarfile.open(archive) as bundle:
    def read(name):
        raw = bundle.extractfile('./' + name).read()
        assert hashlib.sha256(raw).hexdigest() == report['retained_files']['./' + name]
        return raw

    source = read('wrapper.py')
    assert hashlib.sha256(source).hexdigest() == report['observation_controls']['classifier_source_sha256']
    parsed = ast.parse(source)
    fn = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == 'classify')
    if sys.argv[1:] == ['--inject-overlap']:
        # Both ordinary classifications still appear right due to first-match
        # ordering, but the earlier-failure rule now also accepts the gate.
        branches = [n for n in fn.body if isinstance(n, ast.If) and len(n.body) == 1
                    and isinstance(n.body[0], ast.Return)]
        branches[1].test = ast.copy_location(ast.Constant(True), branches[1].test)
    else:
        assert not sys.argv[1:], sys.argv[1:]
    gate = next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'GATE' for t in n.targets))
    # Extract the actual rule expressions, not a second manually aligned table.
    rules = []
    for node in fn.body:
        if isinstance(node, ast.If) and len(node.body) == 1 and isinstance(node.body[0], ast.Return):
            rules.append((ast.literal_eval(node.body[0].value),
                          compile(ast.Expression(node.test), 'measured-rule', 'eval')))
    assert [name for name, _ in rules] == ['account_readiness', 'earlier_configuration_failure']

    with tempfile.TemporaryDirectory(prefix='uno-a2-separation-') as temporary:
        root = Path(temporary)
        (root / 'sites.json').write_bytes(read('sites.json'))
        namespace = {'ROOT': root, 'Path': Path, 'json': json, 'GATE': gate}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'archived-wrapper.py', 'exec'), namespace)
        classify = namespace['classify']
        observed = {}
        for name, original in [('earlier', 'earlier.result'),
                               ('gate', 'fixture/account_binding_refused.result')]:
            p = root / name
            for suffix in ('', '.kind', '.message', '.stats'):
                Path(str(p) + suffix).write_bytes(read(original + suffix))
            trace = root / (name + '.trace')
            trace.write_bytes(read(name + '.trace.json'))
            verdict = classify(p, trace)
            c = json.loads(trace.read_text())['counts']
            message = Path(str(p) + '.message').read_text()
            matched = [label for label, code in rules if eval(code, dict(namespace, c=c, message=message))]
            observed[name] = {'verdict': verdict, 'matched_rules': matched}
        assert observed['earlier'] == {'verdict': 'earlier_configuration_failure',
                                       'matched_rules': ['earlier_configuration_failure']}, observed
        assert observed['gate'] == {'verdict': 'account_readiness',
                                    'matched_rules': ['account_readiness']}, observed
        assert not set(observed['earlier']['matched_rules']) & set(observed['gate']['matched_rules'])

        # Same -7201 code on both real inputs. Neither message alone nor counts
        # alone may turn the crossed observations into a recognized outcome.
        crossed = []
        for result_name, trace_name in [('earlier', 'gate'), ('gate', 'earlier')]:
            p, trace = root / result_name, root / (trace_name + '.trace')
            c = json.loads(trace.read_text())['counts']
            message = Path(str(p) + '.message').read_text()
            matched = [label for label, code in rules if eval(code, dict(namespace, c=c, message=message))]
            assert matched == [], matched
            try:
                classify(p, trace)
            except ValueError as error:
                assert str(error).startswith('unclassifiable:'), str(error)
                crossed.append({'result': result_name, 'counts': trace_name,
                                'matched_rules': matched, 'error': str(error)})
            else:
                raise AssertionError('crossed observations were silently classified')

        # Boolean rule overlap is impossible for any message: each exact equality
        # constrains it to a different string. Verify that property of the actual
        # source predicates rather than relying on first-match branch order.
        messages = []
        for node in fn.body:
            if not (isinstance(node, ast.If) and len(node.body) == 1 and isinstance(node.body[0], ast.Return)):
                continue
            term = node.test.values[0]
            assert isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.And)
            assert isinstance(term, ast.Compare) and isinstance(term.left, ast.Name) and term.left.id == 'message'
            assert len(term.ops) == 1 and isinstance(term.ops[0], ast.Eq)
            messages.append(eval(compile(ast.Expression(term.comparators[0]), 'message-rule', 'eval'), namespace))
        assert len(messages) == 2 and messages[0] != messages[1]
        print(json.dumps({'classifier_sha256': hashlib.sha256(source).hexdigest(),
                          'real_inputs': observed, 'crossed_inputs': crossed,
                          'exact_message_predicates_distinct': True,
                          'original_material_modified': False}, indent=2))
