"""Resource-admission regressions; the fake transport is not an isolation claim."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location("resources", Path(__file__).with_name("check-local-pq-resources.py"))
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)

CONTRACT = 'int deposit_gas_ceiling() asm "123 PUSHINT";\nint transact_gas_ceiling() asm "456 PUSHINT";\n'
FIXTURE = json.dumps({"verifying_key": {"hex": "00" * 1248}})


def response():
    return dict(ok=True, result=dict(schema="tos.local-pq-runtime-resources.v1",
                                     pool_source=CONTRACT, development_fixture=FIXTURE,
                                     verifying_key_hex="00" * 1248,
                                     deposit_gas_ceiling=123, transact_gas_ceiling=456))


def test_matching_resources_pass():
    assert resources.validate(json.dumps(response()), CONTRACT, FIXTURE)["deposit_gas_ceiling"] == 123


@pytest.mark.parametrize("mutation", ["json_failure", "init", "old_source", "old_fixture",
                                      "wrong_key", "wrong_gas", "bad_json", "two_lines"])
def test_false_success_and_stale_inputs_are_refused(mutation):
    value = response()
    if mutation == "json_failure": value = dict(ok=False, error="file missing")
    if mutation == "init": value = dict(ok=True,result=dict(state={}))
    for mode,key in [("old_source","pool_source"),("old_fixture","development_fixture"),
                     ("wrong_key","verifying_key_hex"),("wrong_gas","deposit_gas_ceiling")]:
        if mutation == mode: value["result"][key] = "different"
    text=json.dumps(value)
    if mutation == "bad_json": text="not json"
    if mutation == "two_lines": text += "\n"+text
    with pytest.raises((ValueError,KeyError)):
        resources.validate(text,CONTRACT,FIXTURE)


def test_source_and_build_are_hidden_from_the_staged_not_current_binary(tmp_path,monkeypatch):
    repo=tmp_path/'checkout with spaces';build=tmp_path/'build';dest=tmp_path/'snapshot'
    for name,text in [(resources.CONTRACT,CONTRACT),(resources.FIXTURE,FIXTURE)]:
        p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    seen=[]
    def run(command,**kwargs):
        seen.append(command)
        assert json.loads(kwargs["input"])["operation"] == "resources"
        return SimpleNamespace(returncode=0,stdout=json.dumps(response()),stderr="")
    monkeypatch.setattr(resources.subprocess,"run",run)
    resources.check(dest,repo,build)
    command=seen[0]
    assert "--property=ProtectHome=true" in command
    hidden=next(x for x in command if x.startswith('--property=InaccessiblePaths='))
    assert resources.quote_path(repo) in hidden and resources.quote_path(build) in hidden
    assert command[-1] == str(dest/'src'/resources.GENERATOR)
    assert 'current' not in command[-1]
    with pytest.raises(ValueError,match='outside'):
        resources.check(repo/'snapshot',repo,build)


def test_path_specifiers_are_not_expanded():
    assert '%%' in resources.quote_path('/tmp/build%h')
    with pytest.raises(ValueError): resources.quote_path('/tmp/new\nline')
