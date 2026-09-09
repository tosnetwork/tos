set pagination off
set confirm off
set breakpoint pending off
set language c++
python
import gdb, json, os, traceback

# This is an x86-64 SysV/libstdc++ diagnostic, not a portable runtime ABI.
# The helper contributes DWARF only; no inferior calls or writes are performed.
gdb.execute('add-symbol-file ' + os.environ['CONNECTIVITY_TYPES'] + ' 0')
events = []
errors = []

def registry(ptr):
    value = ptr.cast(gdb.lookup_type('block::WorkchainExecutionRegistry').pointer()).dereference()
    result = {}
    for field in ('engines_', 'block_engines_', 'account_engines_'):
        mapping = value[field]
        count = int(mapping['_M_t']['_M_impl']['_M_node_count'])
        if count > 16:
            raise RuntimeError('diagnostic registry bound exceeded')
        printer = gdb.default_visualizer(mapping)
        if printer is None:
            raise RuntimeError('missing map printer')
        children = list(printer.children())
        keys = [{'format': int(v['format']), 'selector': int(v['selector'])}
                for _, v in children[::2]]
        if len(keys) != count:
            raise RuntimeError('registry key/count mismatch')
        result[field] = keys
    return result

class Returned(gdb.FinishBreakpoint):
    def __init__(self, site, ptr=None):
        super().__init__(internal=True)
        self.site = site
        self.ptr = ptr

    def stop(self):
        try:
            ptr = self.ptr if self.ptr is not None else gdb.parse_and_eval('$rax')
            events.append({'site': self.site, 'registry': registry(ptr)})
        except Exception:
            errors.append(traceback.format_exc())
        return False

class Observe(gdb.Breakpoint):
    def __init__(self, site, symbol):
        # Exact entry, before a prologue moves the SysV argument registers.
        super().__init__("*'" + symbol + "'", internal=True)
        self.site = site

    def stop(self):
        try:
            if self.site == 'registry_default':
                Returned(self.site)
            elif self.site == 'register_account':
                # Status is returned indirectly; the registry is argument two.
                Returned(self.site, gdb.parse_and_eval('$rsi'))
            elif self.site == 'config':
                # Result<Table> is returned indirectly; Config is argument two.
                cfg = gdb.parse_and_eval('$rsi').cast(gdb.lookup_type('block::Config').pointer()).dereference()
                events.append({'site': self.site, 'version': int(cfg['version_']),
                               'capabilities': int(cfg['capabilities_'])})
            else:
                events.append({'site': self.site})
        except Exception:
            errors.append(traceback.format_exc())
        return False

sites = {
    'registry_default': 'block::default_workchain_execution_registry()',
    'register_account': 'block::WorkchainExecutionRegistry::register_account_engine(std::unique_ptr<block::RegisteredWorkchainAccountEngine, std::default_delete<block::RegisteredWorkchainAccountEngine> >)',
    'config': 'block::load_workchain_native_ingress_table(block::Config const&)',
    'preinit': 'tos::validator::Collator::do_preinit()',
    'dispatch': 'tos::validator::Collator::check_this_shard_mc_info()',
    'adapter': 'block::ConfiguredWorkchainAccountEngine::bind(block::ResolvedWorkchainAccountBinding const&)',
    'validator_set': 'tos::validator::Collator::check_cur_validator_set()',
    'old_state': 'tos::validator::Collator::unpack_last_state()',
}
observers = [Observe(k, v) for k, v in sites.items()]

def done(event):
    with open(os.environ['CONNECTIVITY_TRACE'], 'x') as stream:
        json.dump({'exit_code': getattr(event, 'exit_code', None),
                   'events': events, 'errors': errors}, stream, indent=2)

gdb.events.exited.connect(done)
end
run
