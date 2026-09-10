set pagination off
set confirm off
set breakpoint pending off
python
import gdb, json, os, traceback
from pathlib import Path
root = Path(os.environ['A2_ROOT'])
cfg = json.loads((root / 'sites.json').read_text())
counts = {key: 0 for key in cfg}
events, errors = [], []
class Watch(gdb.Breakpoint):
    def __init__(self, key, spec):
        super().__init__(spec, internal=True)
        self.key = key
    def stop(self):
        try:
            counts[self.key] += 1
            frame, stack = gdb.newest_frame(), []
            for _ in range(4):
                if frame is None:
                    break
                stack.append({'name': frame.name(), 'pc': int(frame.pc())})
                frame = frame.older()
            events.append({'site': self.key, 'stack': stack})
        except Exception:
            errors.append(traceback.format_exc())
        return False
observers = [Watch(key, spec) for key, spec in cfg.items()]
bound = {bp.key: {'location': bp.location, 'pending': bp.pending,
                 'enabled': bp.enabled, 'valid': bp.is_valid()}
         for bp in observers}
if any(item['pending'] or not item['enabled'] or not item['valid'] for item in bound.values()):
    raise RuntimeError('unbound observer: ' + repr(bound))
def done(event):
    with open(os.environ['A2_TRACE'], 'x') as stream:
        json.dump({'counts': counts, 'events': events, 'errors': errors,
                   'bound_before_run': bound,
                   'exit_code': getattr(event, 'exit_code', None)}, stream, indent=2)
gdb.events.exited.connect(done)
end
run
