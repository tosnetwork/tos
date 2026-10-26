"""Bounded cleanup for owned groups created with start_new_session=True."""

import os
import signal
import time


def stop_process_group(process, grace=5.0):
    """Reclaim children even if their group leader has already exited."""

    def exists():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        if not exists():
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()
            if not exists():
                break
            time.sleep(0.05)
    process.wait(timeout=grace)
    if exists():
        raise ValueError("owned network process group did not exit")
