"""Retain exact native test output while rendering arbitrary diagnostic bytes safely."""


def retain_output(output, label, result):
    (output / f"{label}.stdout.bin").write_bytes(result.stdout)
    (output / f"{label}.stderr.bin").write_bytes(result.stderr)
    log = result.stdout.decode("utf-8", errors="backslashreplace") + result.stderr.decode(
        "utf-8", errors="backslashreplace"
    )
    (output / f"{label}.log").write_text(log)
    return log
