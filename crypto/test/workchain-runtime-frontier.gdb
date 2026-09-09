set pagination off
set confirm off
set breakpoint pending off
python
import gdb
import json
import os

events = []
sites = {
    "preinit": "tos::validator::Collator::do_preinit()",
    "configuration": "tos::validator::Collator::check_this_shard_mc_info()",
    "adapter": "block::ConfiguredWorkchainAccountEngine::bind(block::ResolvedWorkchainAccountBinding const&)",
    "validator_set": "tos::validator::Collator::check_cur_validator_set()",
    "old_state": "tos::validator::Collator::unpack_last_state()",
}
counts = {name: 0 for name in sites}

class Observe(gdb.Breakpoint):
    def __init__(self, name, symbol):
        super().__init__(symbol, internal=True)
        if self.pending or not self.is_valid():
            raise RuntimeError("missing production observation site: " + name)
        self.name = name

    def stop(self):
        counts[self.name] += 1
        events.append(self.name)
        return False

observers = [Observe(name, symbol) for name, symbol in sites.items()]

def finished(event):
    if not hasattr(event, "exit_code"):
        raise RuntimeError("inferior did not report an exit code")
    # Exclusive creation prevents a stale successful trace from masking failure.
    with open(os.environ["WORKCHAIN_FRONTIER_TRACE"], "x") as stream:
        json.dump({"exit_code": event.exit_code, "counts": counts, "events": events}, stream, indent=2)

gdb.events.exited.connect(finished)
end
run
