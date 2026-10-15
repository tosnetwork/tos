def make_url_safe(str: str) -> str:
    return str.replace("+", "-").replace("/", "_")


def bytes_to_uint(data: bytes):
    return int.from_bytes(data, "big", signed=False)


def bin_to_signed_int(ba: str) -> int:
    if not ba or any(bit not in "01" for bit in ba):
        raise ValueError("expected a nonempty binary string")
    value = int(ba, 2)
    return value - (1 << len(ba)) if ba[0] == "1" else value
