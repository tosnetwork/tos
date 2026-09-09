"""Tamper only with in-memory reads; never edit historical evidence or binaries."""
import contextlib
import io
from pathlib import Path
import runpy
from unittest.mock import patch

audit = Path(__file__).with_name("restore-audit.py")
original_bytes, original_text, original_glob = Path.read_bytes, Path.read_text, Path.glob

def bad_binary(path, *args, **kwargs):
    if path.name == "test-workchain-settlement-continuation":
        return b"not the recorded restored binary"
    return original_bytes(path, *args, **kwargs)

def bad_positive(path, *args, **kwargs):
    text = original_text(path, *args, **kwargs)
    return text.replace("actual_engine_calls=1", "actual_engine_calls=9") if path.name == "restore-run.log" else text

def missing_name(path, pattern):
    values = list(original_glob(path, pattern))
    return values[:-1] if path == audit.parent and pattern == "*/record.json" else values

for name, method, replacement in (("restored-binary", "read_bytes", bad_binary),
                                  ("restored-positive", "read_text", bad_positive),
                                  ("exact-name-set", "glob", missing_name)):
    with patch.object(Path, method, replacement), contextlib.redirect_stdout(io.StringIO()):
        try:
            runpy.run_path(str(audit))
        except AssertionError:
            refused = True
        else:
            refused = False
    assert refused, name
    print(name + ": tampered observation rejected")
