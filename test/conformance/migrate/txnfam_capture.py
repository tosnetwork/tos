# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Record every native transaction-emulator call of an unchanged family run.

Installed by ``txnfam_site/sitecustomize.py`` in every Python process of a family run (the families
start supervised worker subprocesses, which inherit the environment):

    TXNFAM_CAPTURE_DIR  directory that receives one ``<pid>-<ns>.jsonl`` file per process
    TXNFAM_NATIVE       path of the C++ libemulator; other libraries (the Rust executor exports the
                        same C names) pass through unrecorded

``ctypes.CDLL`` is replaced by a subclass whose emulator functions forward to the real ones and
remember, per emulator object, exactly the arguments the caller passed: the configuration BOC given
to ``transaction_emulator_create`` (or a later ``set_config``/``set_config_object``), unixtime, lt,
rand seed, libraries, previous blocks, ``ignore_chksig`` and the debug flag. At each
``emulate_transaction``/``emulate_tick_tock_transaction`` call it writes one record with that state,
the ShardAccount and message strings as passed, and the raw native response. Nothing is derived from
the response; a setting the caller never made is recorded as ``null`` so the converter can say how
the emulator fills it.
"""

from __future__ import annotations

import ctypes
import json
import os
import threading
import time
import traceback
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_STATE: dict[int, dict[str, Any]] = {}
_CONFIGS: dict[int, str] = {}
_OUT: dict[str, Any] = {"handle": None, "seq": 0}
_REAL_CDLL = ctypes.CDLL
_RESPONSE_KEYS = (
    "success",
    "transaction",
    "shard_account",
    "external_not_accepted",
    "vm_exit_code",
    "error",
)
INTERCEPTED = frozenset(
    {
        "transaction_emulator_create",
        "transaction_emulator_destroy",
        "transaction_emulator_set_unixtime",
        "transaction_emulator_set_lt",
        "transaction_emulator_set_rand_seed",
        "transaction_emulator_set_ignore_chksig",
        "transaction_emulator_set_config",
        "transaction_emulator_set_config_object",
        "transaction_emulator_set_libs",
        "transaction_emulator_set_debug_enabled",
        "transaction_emulator_set_prev_blocks_info",
        "transaction_emulator_emulate_transaction",
        "transaction_emulator_emulate_tick_tock_transaction",
        "emulator_config_create",
    }
)


def _pointer(value: Any) -> int | None:
    if isinstance(value, ctypes.c_void_p):
        return value.value
    if isinstance(value, int):
        return value
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, bytes):
        return value.decode("ascii")
    if isinstance(value, str):
        return value
    if isinstance(value, ctypes.c_char_p):
        raw = value.value
        return None if raw is None else raw.decode("ascii")
    return None


def _caller() -> list[str]:
    frames = traceback.extract_stack()[:-3]
    return [f"{Path(f.filename).name}:{f.name}:{f.lineno}" for f in frames[-6:]]


def _emit(record: dict[str, Any]) -> None:
    directory = os.environ.get("TXNFAM_CAPTURE_DIR")
    if not directory:
        return
    with _LOCK:
        if _OUT["handle"] is None:
            name = f"{os.getpid()}-{time.time_ns()}.jsonl"
            _OUT["handle"] = (Path(directory) / name).open("a", encoding="utf-8")
        _OUT["seq"] += 1
        record["seq"] = _OUT["seq"]
        record["pid"] = os.getpid()
        record["ns"] = time.time_ns()
        handle = _OUT["handle"]
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        handle.flush()


def _response(func: Any, raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, bytes):
        text = raw
    elif isinstance(raw, int) and raw:
        text = ctypes.string_at(raw)
    else:
        return None
    parsed = json.loads(text)
    return {k: parsed[k] for k in _RESPONSE_KEYS if k in parsed}


class _Function:
    """A forwarding wrapper around one native function; attribute writes reach the real one."""

    def __init__(self, name: str, func: Any) -> None:
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_func", func)

    def __getattr__(self, item: str) -> Any:
        return getattr(object.__getattribute__(self, "_func"), item)

    def __setattr__(self, item: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_func"), item, value)

    def __call__(self, *args: Any) -> Any:
        name = object.__getattribute__(self, "_name")
        func = object.__getattribute__(self, "_func")
        result = func(*args)
        try:
            _observe(name, func, args, result)
        except Exception as exc:  # noqa: BLE001 - a capture failure must be visible, not fatal
            _emit({"kind": "capture_failure", "function": name, "error": repr(exc)})
        return result


def _observe(name: str, func: Any, args: tuple[Any, ...], result: Any) -> None:
    if name == "emulator_config_create":
        ptr = _pointer(result)
        if ptr:
            _CONFIGS[ptr] = _text(args[0]) or ""
        return
    if name == "transaction_emulator_create":
        ptr = _pointer(result)
        if ptr:
            _STATE[ptr] = {
                "config": _text(args[0]),
                "vm_log_verbosity": int(args[1]) if len(args) > 1 else None,
                "now": None,
                "lt": None,
                "rand_seed": None,
                "ignore_chksig": None,
                "debug_enabled": None,
                "libraries": None,
                "prev_blocks": None,
                "config_replaced": False,
            }
        return
    ptr = _pointer(args[0]) if args else None
    if ptr is None:
        return
    if name == "transaction_emulator_destroy":
        _STATE.pop(ptr, None)
        return
    state = _STATE.get(ptr)
    if state is None:
        _emit({"kind": "unknown_emulator", "function": name})
        return
    if name.startswith("transaction_emulator_set_"):
        if not result:
            state.setdefault("refused_settings", []).append(name)
            return
        key = name.removeprefix("transaction_emulator_set_")
        value = args[1]
        if key == "unixtime":
            state["now"] = int(value)
        elif key == "lt":
            state["lt"] = int(value)
        elif key == "rand_seed":
            state["rand_seed"] = (_text(value) or "").lower()
        elif key == "ignore_chksig":
            state["ignore_chksig"] = bool(value)
        elif key == "debug_enabled":
            state["debug_enabled"] = bool(value)
        elif key == "libs":
            state["libraries"] = _text(value)
        elif key == "prev_blocks_info":
            state["prev_blocks"] = _text(value)
        elif key == "config":
            state["config"] = _text(value)
            state["config_replaced"] = True
        elif key == "config_object":
            state["config"] = _CONFIGS.get(_pointer(value) or 0)
            state["config_replaced"] = True
        return
    record: dict[str, Any] = {"kind": "call", "state": dict(state), "caller": _caller()}
    record["shard_account"] = _text(args[1])
    if name == "transaction_emulator_emulate_transaction":
        record["message"] = _text(args[2])
    else:
        record["tick_tock"] = "tock" if bool(args[2]) else "tick"
    record["response"] = _response(func, result)
    _emit(record)


class CaptureCDLL(_REAL_CDLL):
    def __init__(self, name: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(name, *args, **kwargs)
        native = os.environ.get("TXNFAM_NATIVE", "")
        self._txnfam_native = bool(
            native and name and os.path.realpath(str(name)) == os.path.realpath(native)
        )

    def __getitem__(self, name: Any) -> Any:
        func = super().__getitem__(name)
        if self._txnfam_native and name in INTERCEPTED:
            return _Function(name, func)
        return func


def install() -> None:
    if os.environ.get("TXNFAM_CAPTURE_DIR") and ctypes.CDLL is _REAL_CDLL:
        ctypes.CDLL = CaptureCDLL  # type: ignore[misc]
