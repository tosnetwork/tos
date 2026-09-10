set pagination off
set confirm off
set breakpoint pending off
python
import gdb, json, os, traceback
from pathlib import Path
root=Path(os.environ['A2_ROOT'])
cfg=json.loads((root/'sites.json').read_text())
gdb.execute('set substitute-path /tmp/uno-merged-default-source '+str(root/'source'))
counts={k:0 for k in cfg}
events=[]
errors=[]
class Watch(gdb.Breakpoint):
    def __init__(self, key, spec):
        super().__init__(spec, internal=True)
        self.key=key
    def stop(self):
        try:
            counts[self.key]+=1
            frame=gdb.newest_frame()
            stack=[]
            for _ in range(4):
                if frame is None: break
                stack.append({'name':frame.name(),'pc':int(frame.pc())})
                frame=frame.older()
            events.append({'site':self.key,'stack':stack})
        except Exception:
            errors.append(traceback.format_exc())
        return False
observers=[Watch(k,v) for k,v in cfg.items()]
def done(event):
    with open(os.environ['A2_TRACE'],'x') as f:
        json.dump({'counts':counts,'events':events,'errors':errors,
                   'exit_code':getattr(event,'exit_code',None),
                   'breakpoints':gdb.execute('info breakpoints',to_string=True)},f,indent=2)
gdb.events.exited.connect(done)
end
run
