#!/usr/bin/env python3
"""Two real source transactions under serving and non-serving destinations."""
import argparse
import base64
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--create-state", type=Path, required=True)
parser.add_argument("--collator", type=Path, required=True)
parser.add_argument("--evidence", type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.repo / "test/tostester/src"))
from pytosiq_core import Cell
from pytosiq_core.tl import TlGenerator
from pytosiq_core.tlb.block import Block, ShardStateUnsplit

out = args.evidence or Path(tempfile.mkdtemp(prefix="uno-routing-evidence-")) / "run"
out.mkdir(parents=True, exist_ok=False)
schemas = TlGenerator.with_default_schemas().generate()
epoch = int(time.time())
report = {"scope": "Native source behavior and queues; not UNO execution or global liveness.",
          "SOURCE_DATE_EPOCH": epoch, "cases": []}

def require(value, identity):
    if not value:
        report["failure_identity"] = identity
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        raise AssertionError(identity)

for accepting in [True, False]:
    directory = out / ("serving" if accepting else "unserved")
    directory.mkdir()
    record = {"accept_msgs": accepting, "runs": [], "transactions": []}
    report["cases"].append(record)
    def save_report():
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def run(name, command):
        result = subprocess.run(list(map(str, command)), cwd=directory,
                                env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
                                capture_output=True, timeout=60)
        (directory / (name + ".stdout.log")).write_bytes(result.stdout)
        (directory / (name + ".stderr.log")).write_bytes(result.stderr)
        record["runs"].append({"name": name, "command": list(map(str, command)), "exit": result.returncode})
        save_report()
        require(result.returncode == 0, 950)
    includes = ":".join(map(str, (args.repo / "crypto/fift/lib", args.create_state.parent / "smartcont",
                                   args.repo / "crypto/smartcont")))
    for script in ["counter-shard-genesis", "counter-native-sender"]:
        run(script, [args.create_state, "-I", includes, args.repo / "test" / (script + ".fif")])
    master = (args.repo / "test/counter-masterchain-genesis.fif").read_text()
    marker = '0 mkemptyShardState\ndup 31 boc+>B dup "basestate0.boc" B>file\nBhashu constant base_fhash\nhashu constant base_rhash'
    require(master.count(marker) == 1, 951)
    master = master.replace(marker, '"basestate0.fhash" file>B 256 B>u@ constant base_fhash\n"basestate0.rhash" file>B 256 B>u@ constant base_rhash')
    if not accepting:
        serving_call = "2 0xe000 0x434e5431 add-basic-workchain drop"
        require(master.count(serving_call) == 1, 952)
        master = master.replace(serving_call, "2 0xc000 0x434e5431 add-basic-workchain drop")
    (directory / "master.fif").write_text(master)
    run("master", [args.create_state, "-I", includes, directory / "master.fif"])
    static = directory / "db/static"
    static.mkdir(parents=True)
    for name in ["zerostate", "basestate0", "counter-state"]:
        raw = (directory / (name + ".boc")).read_bytes()
        shutil.copyfile(directory / (name + ".boc"), static / hashlib.sha256(raw).hexdigest().upper())
    zero = {"workchain": -1, "shard": -(1 << 63), "seqno": 0,
            "root_hash": base64.b64encode((directory / "zerostate.rhash").read_bytes()).decode(),
            "file_hash": base64.b64encode((directory / "zerostate.fhash").read_bytes()).decode()}
    (directory / "global.json").write_text(json.dumps({"@type": "config.global", "dht": {
        "@type": "dht.config.global", "k": 6, "a": 3, "static_nodes": {"@type": "dht.nodes", "nodes": []}},
        "validator": {"@type": "validator.config.global", "zero_state": zero, "hardforks": []}}))
    def node(name, options):
        run(name, [args.collator, "-C", directory / "global.json", "-D", directory / "db",
                   "--query-result", directory / (name + ".result"), *options])
        require((directory / (name + ".result.kind")).read_text().strip() == "success", 953)
    node("bootstrap", ["-w", "-1"])
    if accepting:
        counter = f"(2,8000000000000000,0):{(directory/'counter-state.rhash').read_bytes().hex()}:{(directory/'counter-state.fhash').read_bytes().hex()}"
        node("serving-engine", ["-w", "2", "--counter-increment", "0", "-T", counter])
    # In the unserved case no command registers any Counter engine. Source
    # execution is native TVM in both cases; successful Counter execution above
    # supplies independent evidence that the serving network has an engine.
    initial = ShardStateUnsplit.deserialize(Cell.one_from_boc((directory / "basestate0.boc").read_bytes()).begin_parse())
    balance = initial.accounts[0][1].account.storage.balance.tomis
    previous_lt = 0
    tip = None
    for number in [1, 2]:
        name = f"source-{number}"
        candidate = directory / (name + ".candidate")
        options = ["-w", "0", "-m", directory / "sender-message.boc", "--export-candidate", candidate]
        if tip:
            options += ["-T", tip]
        node(name, options)
        raw = candidate.read_bytes()
        value, consumed = schemas.deserialize(raw)
        require(consumed == len(raw) and value["@type"] == "db.candidate", 954)
        block = Block.deserialize(Cell.one_from_boc(value["data"]).begin_parse())
        accounts = block.extra.account_blocks[0]
        require(set(accounts) == {1} and len(accounts[1].transactions[0]) == 1, 955)
        tx = next(iter(accounts[1].transactions[0].values()))
        state = block.state_update.new.shard_state_unsplit
        require(tx.description.compute_ph.success and tx.lt > previous_lt, 956)
        previous_lt = tx.lt
        action = tx.description.action
        require(action is not None and action.result_code == (0 if accepting else 36), 957)
        # The existing native sender first tries a non-ingress account with
        # ignore-errors, then sends to the real ingress without ignore-errors.
        require(action.skipped_actions == 1, 962)
        require(tx.description.aborted == (not accepting) and tx.outmsg_cnt == (1 if accepting else 0), 958)
        queue = state.out_msg_queue_info.begin_parse().load_hashmap_aug_e(
            352, x_deserializer=lambda s: s.copy(), y_deserializer=lambda s: s.load_uint(64))[0] or {}
        require(len(queue) == (number if accepting else 0), 959)
        require(state.accounts[0][1].account.storage.state.type_ == "account_active", 960)
        next_balance = state.accounts[0][1].account.storage.balance.tomis
        if not accepting:
            require(next_balance == balance - tx.total_fees.tomis, 961)
        balance = next_balance
        block_id = value["id"]
        tip = f"(0,8000000000000000,{block_id['seqno']}):{block_id['root_hash']}:{block_id['file_hash']}"
        record["transactions"].append({"lt": tx.lt, "action_result_code": action.result_code,
            "aborted": tx.description.aborted, "out_messages": tx.outmsg_cnt, "queue_entries": len(queue),
            "source_balance": balance, "source_fees": tx.total_fees.tomis, "block": tip})
        save_report()
print(f"PASS: serving and unserved source/queue matrix; evidence={out}")
