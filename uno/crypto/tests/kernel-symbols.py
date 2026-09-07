"""Inspect direct/GOT reachability; unresolved indirect calls require source review."""
import collections
import re
import subprocess
import sys


def reachable(edges, root):
    pending = collections.deque([root])
    seen = {root}
    while pending:
        for child in edges.get(pending.popleft(), ()):
            if child not in seen:
                seen.add(child)
                pending.append(child)
    return seen


def entropy_name(name):
    return bool(re.search(r"getrandom|RandomState|build_rng|rand::|random_device|arc4random", name))


def main(binary):
    # Negative control for the graph predicate, independent of the real binary.
    graph = {1: {2}, 2: {3}}
    assert 3 in reachable(graph, 1)
    assert entropy_name("std::sys::random::linux::getrandom")
    assert not entropy_name("uno_crypto_verify_v1")
    disassembly = subprocess.check_output(["objdump", "-d", "-C", binary], text=True)
    assert not re.search(r"\b(?:rdrand|rdseed)\b", disassembly), "hardware entropy instruction in test image"
    relocations = {}
    for line in subprocess.check_output(["readelf", "-rW", binary], text=True).splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[2] in {"R_X86_64_RELATIVE", "R_AARCH64_RELATIVE"}:
            relocations[int(fields[0], 16)] = int(fields[3], 16)
    names, edges, indirect = {}, collections.defaultdict(set), collections.Counter()
    current = None
    for line in disassembly.splitlines():
        label = re.match(r"^([0-9a-f]+) <(.*)>:", line)
        if label:
            current = int(label[1], 16)
            names[current] = label[2]
            continue
        if current is None:
            continue
        direct = re.search(r"\b(?:callq?|jmpq?|j[a-z]+|bl|b)\s+([0-9a-f]+)\s+<", line)
        if direct:
            edges[current].add(int(direct[1], 16))
        if re.search(r"\b(?:call|jmp)\s+\*|\b(?:blr|br)\s+", line):
            got = re.search(r"# ([0-9a-f]+)", line)
            if got and int(got[1], 16) in relocations:
                edges[current].add(relocations[int(got[1], 16)])
            else:
                indirect[current] += 1
    roots = [address for address, name in names.items() if name == "uno_crypto_verify_v1"]
    assert len(roots) == 1, "missing or ambiguous verification root"
    visited = reachable(edges, roots[0])
    assert len(visited) > 10, "disassembly instrument did not traverse the verifier"
    forbidden = [names[a] for a in visited if entropy_name(names.get(a, ""))]
    assert not forbidden, forbidden
    print(f"PASS: {len(visited)} direct/GOT nodes, no matched entropy target; "
          f"{sum(indirect[a] for a in visited)} unresolved indirect sites REQUIRE source/runtime review")
    print("Dormant runtime entropy symbols are not classified as reachable merely because they are linked.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("supply the actual linked ABI test executable")
    main(sys.argv[1])
