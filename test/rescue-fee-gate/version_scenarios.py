"""Expand the frozen valid fixtures across the development protocol boundary.

Usage: version_scenarios.py <output.tsv>
No signing or fixture regeneration is needed: the VM version is not signed data.
"""

import sys
from pathlib import Path


def main(output):
    source = Path(__file__).with_name("suite-scenarios.tsv")
    rows = [line.split("\t") for line in source.read_text().splitlines()]
    fixtures = ("s1-valid", "s2-valid", "s3-valid", "s4-h20w4-valid")
    valid = {row[4]: row for row in rows if row[0] in fixtures}
    assert all(row[3] == "V" and len(row) == 9 for row in valid.values())
    assert set(valid) == {"int:1", "int:2", "int:3", "int:4"}
    expanded = []
    for suite, fixture in sorted(valid.items()):
        for version in range(20):
            row = fixture.copy()
            row[0] = f"version-{version}-suite-{suite[4:]}"
            row[1] = str(version)
            row[3] = "E6" if version < 16 else "V"
            expanded.append(row)
    Path(output).write_text("".join("\t".join(row) + "\n" for row in expanded))
    print(f"{len(expanded)} version scenarios")


if __name__ == "__main__":
    main(sys.argv[1])
