"""Compare and submit complete Rust SDK FPR3 bytes with a real fixture SLH signature."""

import json
import subprocess

from cells import from_boc


def encode(driver, out, envelope, now):
    header = envelope.slice()
    assert header.uint(32) == 0x46505233
    request, sig = header.ref(), header.ref()
    header.end()
    s = request.slice()
    assert s.uint(32) == 0x50525033
    global_id, network, wallet, source, deadline = (
        s.sint(32),
        s.uint(256),
        s.addr(),
        s.uint(256),
        s.uint(32),
    )
    plan = s.ref().slice()
    s.end()
    a, b = plan.coins(), plan.coins()
    module, metadata, vault = plan.ref(), plan.ref(), plan.ref()
    plan.end()
    assert wallet[0] == 0
    pieces = []
    while sig is not None:
        assert len(sig.bits) % 8 == 0 and len(sig.refs) <= 1
        pieces.append(int(sig.bits, 2).to_bytes(len(sig.bits) // 8, "big"))
        sig = sig.refs[0] if sig.refs else None
    payload = dict(
        global_id=global_id,
        network=f"{network:064x}",
        wallet=f"{wallet[1]:064x}",
        source_module=f"{source:064x}",
        deadline=deadline,
        proven_time=now,
        module_amount=str(a),
        vault_amount=str(b),
        module_init=module.boc().hex(),
        metadata=metadata.boc().hex(),
        vault_init=vault.boc().hex(),
        signature=b"".join(pieces).hex(),
    )
    result = subprocess.run(
        [str(driver.resolve())], input=json.dumps(payload), text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    actual = from_boc(bytes.fromhex(response["submission"]))
    assert actual.hash == envelope.hash
    assert from_boc(bytes.fromhex(response["request"])).hash == request.hash
    assert response["digest"] == request.hash.hex()
    assert response["context"] == b"TOS-RESCUE-FEE-PREP-v1".hex()
    assert int(response["deployment_value"]) == a + b
    out.write_text(json.dumps({"input": payload, "output": response}, indent=2) + "\n")
    return actual
