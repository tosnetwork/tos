import json
from pathlib import Path

root = Path(__file__).parent
trace = json.loads((root / "trace.json").read_text())
assert trace["errors"] == [], trace["errors"]
events = trace["events"]
assert sum(e["site"] == "bind" for e in events) == 1
configs = [e for e in events if e["site"] == "config"]
assert len(configs) == 2
assert configs[0]["config"] == configs[1]["config"] != 0
assert configs[0]["engine"] == configs[1]["engine"] != 0
assert "check_this_shard_mc_info" in configs[0]["stack"]
assert "validate_required_workchains" in configs[1]["stack"]
stages = ("readiness_return", "old_state", "old_state_return", "fetch", "release")
observed = [next(e for e in events if e["site"] == stage) for stage in stages]
assert len({e["actor"] for e in observed}) == 1
assert len({e["adapter"] for e in observed}) == 1
assert observed[0]["adapter"] != 0
assert all(e["adapter"] == 0 for e in events if e["site"] == "release_return")
assert (root / "result.kind").read_text() == "error\n"
assert (root / "result").read_text() == "collate -7201\n"
assert (root / "result.message").read_text() == (
    "cannot execute configured workchain: multi-account admission and replay are not connected")
assert (root / "calls").read_text() == "config=2\nexecute=0\n"
assert "transactions=0\n" in (root / "result.stats").read_text()
print("PASS: two configuration callbacks, same authenticated Config, one retained adapter; typed local stop")
