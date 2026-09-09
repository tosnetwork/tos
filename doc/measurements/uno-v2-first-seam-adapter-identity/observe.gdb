set pagination off
set confirm off
set breakpoint pending off
python
import gdb, json, traceback
events=[]
errors=[]
# Exact offset checked against this binary's release_account_adapter disassembly.
asm=gdb.execute("disassemble 'tos::validator::Collator::release_account_adapter()'",to_string=True)
if '0x610(%rdi),%rdi' not in asm or '$0x0,0x610(%rbx)' not in asm:
    raise RuntimeError('adapter member offset not established by binary')
def ptr(actor):
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(actor+0x610,8)), 'little')
class Finish(gdb.FinishBreakpoint):
    def __init__(self,site,actor):
        super().__init__(internal=True)
        self.site=site
        self.actor=actor
    def stop(self):
        try: events.append(dict(site=self.site,actor=self.actor,adapter=ptr(self.actor)))
        except Exception: errors.append(traceback.format_exc())
        return False
class Watch(gdb.Breakpoint):
    def __init__(self,site,symbol):
        super().__init__("*'"+symbol+"'",internal=True)
        self.site=site
    def stop(self):
        try:
            if self.site=='config':
                events.append(dict(site=self.site,config=int(gdb.parse_and_eval('$rcx')),
                    engine=int(gdb.parse_and_eval('$rsi')),stack=gdb.execute('bt 9',to_string=True)))
            elif self.site=='bind': events.append(dict(site=self.site))
            else:
                actor=int(gdb.parse_and_eval('$rdi'))
                events.append(dict(site=self.site,actor=actor,adapter=ptr(actor)))
                if self.site in ('readiness','old_state','release'):
                    Finish(self.site+'_return',actor)
        except Exception: errors.append(traceback.format_exc())
        return False
observers=[Watch(k,v) for k,v in {
 'config':'AccountBindingProbe::validate_and_resolve_config(block::WorkchainExecutionDescriptor const&, block::Config const&, td::Ref<vm::Cell> const&) const',
 'bind':'block::ConfiguredWorkchainAccountEngine::bind(block::ResolvedWorkchainAccountBinding const&)',
 'readiness':'tos::validator::Collator::check_this_shard_mc_info()',
 'old_state':'tos::validator::Collator::unpack_last_state()',
 'fetch':'tos::validator::Collator::fetch_config_params()',
 'release':'tos::validator::Collator::release_account_adapter()'}.items()]
def done(e):
    with open('/tmp/uno-adapter-identity-2WbNQD/trace.json','x') as f:
        json.dump(dict(exit_code=getattr(e,'exit_code',None),events=events,errors=errors,disassembly=asm),f,indent=2)
gdb.events.exited.connect(done)
end
run
