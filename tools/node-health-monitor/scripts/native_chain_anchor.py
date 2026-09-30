"""Bounded interpretation of native v3 chain anchor observations."""

import datetime as dt
import re


HEX = re.compile(r"[0-9a-f]{64}\Z")
U64 = (1 << 64) - 1


def exact_u64(value):
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("chain_u64")
    result = int(value)
    if result > U64:
        raise ValueError("chain_u64")
    return result


def chain_anchor(chain, network_id, snapshot_at, now):
    """Return a current observation; this does not prove applied progress."""
    if chain is None:
        return None, "missing"
    if type(chain) is not dict or set(chain) != {"applied", "served", "observed_unix_seconds",
                                                "applied_advanced_unix_seconds"}:
        raise ValueError("chain_contract")

    def block(value, point):
        if (type(value) is not dict
                or set(value) != {"file_hash", "kind", "network_id", "point", "root_hash",
                                  "scope_id", "seqno", "shard", "workchain"}
                or value["kind"] != "block" or value["network_id"] != network_id
                or value["point"] != point or value["scope_id"] != "masterchain"
                or type(value["workchain"]) is not int or value["workchain"] != -1
                or value["shard"] != "9223372036854775808"
                or type(value["seqno"]) is not int or not 0 <= value["seqno"] <= 0xffffffff
                or any(type(value[name]) is not str or not HEX.fullmatch(value[name])
                       or value[name] == "0" * 64
                       for name in ("root_hash", "file_hash"))):
            raise ValueError("chain_block_identity")
        return value

    applied = block(chain["applied"], "applied")
    served = None if chain["served"] is None else block(chain["served"], "served")
    if served is not None and served["seqno"] > applied["seqno"]:
        raise ValueError("chain_order")
    observed = exact_u64(chain["observed_unix_seconds"])
    advanced = exact_u64(chain["applied_advanced_unix_seconds"])
    snapshot = dt.datetime.fromisoformat(snapshot_at)
    if snapshot.tzinfo is None or snapshot.utcoffset() != dt.timedelta(0):
        raise ValueError("chain_clock")
    snapshot_seconds = int(snapshot.timestamp())
    if (observed == 0 or observed > snapshot_seconds or observed > now + 1
            or advanced > observed):
        raise ValueError("chain_clock")
    if now - observed > 30:
        return None, "stale"
    return chain, "observed"
