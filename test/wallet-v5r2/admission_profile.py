"""Reconcile a complete pre-ACCEPT trace with independently probed admission credit."""


def profile(trace, initial_credit, minimum_credit):
    remaining = initial_credit
    costs = {}
    instruction = None
    for line in trace.splitlines():
        if line.startswith("execute "):
            instruction = line.removeprefix("execute ").split()[0]
            if instruction == "ACCEPT":
                break
        if line.startswith("gas remaining:"):
            current = int(line.split(":", 1)[1])
            assert instruction is not None and current <= remaining
            costs[instruction] = costs.get(instruction, 0) + remaining - current
            remaining = current
    assert instruction == "ACCEPT", "trace omitted admission or was truncated"
    assert costs.get("LMSCHECKFEEHASH", 0) > 0, "trace omitted the real verifier"
    before_accept = initial_credit - remaining
    # ACCEPT is an eight-bit simple instruction: 18 + 8 gas. Its charge is
    # required to enter paid execution, although it follows the pre-ACCEPT trace.
    assert minimum_credit == before_accept + 26, "trace/probed admission mismatch"
    return {
        "before_accept": before_accept,
        "accept_instruction": 26,
        "minimum_accept_credit": minimum_credit,
        "default_credit": 10000,
        "default_credit_shortfall": max(0, minimum_credit - 10000),
        "lms_opcode": costs["LMSCHECKFEEHASH"],
        "other_admission": before_accept - costs["LMSCHECKFEEHASH"],
        "instruction_totals": dict(sorted(costs.items(), key=lambda item: -item[1])),
    }
