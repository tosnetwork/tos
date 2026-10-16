#!/usr/bin/env python3
"""Check that doc/openapi.yaml documents exactly what the JSON-RPC server serves.

The server's methods live in one table in validator-engine/json-rpc-server.cpp
(between `// BEGIN METHOD TABLE` and `// END METHOD TABLE`), each row carrying
flag letters: W write, G has a GET route, C cacheable, A admin-gated, R none.
The typed error kinds live in validator-engine/json-rpc-contract.h as
`ErrorKind kX{"REASON", code, retryable}` constants.

A spec that drifts from those is worse than none: clients generated from it
call methods that no longer exist, miss the ones that do, and branch on error
reasons the server never sends. Nothing in the build or the unit tests reads
the spec, so the drift is invisible until a client breaks. This check pins it:

  * the `method` enum of the /jsonRPC request equals every table name;
  * the POST /<method> operations (operationId = the method name) equal every
    table name except the admin-gated ones, which are off by default;
  * the GET /<method> operations (operationId `<name>_get`) equal exactly the
    names flagged G;
  * x-admin-methods and x-write-methods of /jsonRPC equal the A and W names;
  * the ErrorData reason enum and its x-error-reasons table
    ({reason, code, retryable}) equal the ErrorKind constants, all three
    fields of every kind.

Every extraction must find something: an empty table, enum or path list
fails rather than comparing equal to another empty set.

Standard library only (the CI job has no YAML package), so the spec is read
with a small parser for the YAML subset the file uses: block mappings and
lists with 2-space indentation, flow collections, quoted and plain scalars,
and literal/folded block scalars.

Run: python3 scripts/check-jsonrpc-spec.py [--spec PATH] [--server PATH] [--contract PATH]
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SPEC = ROOT / "doc" / "openapi.yaml"
DEFAULT_SERVER = ROOT / "validator-engine" / "json-rpc-server.cpp"
DEFAULT_CONTRACT = ROOT / "validator-engine" / "json-rpc-contract.h"

# A table row starts `{"name", FLAGS,`; the handler lambda may follow on the
# same line or on the next ones.
TABLE_ROW = re.compile(r'^\s*\{"([A-Za-z_][A-Za-z0-9_]*)",\s*([A-Z](?:\s*\|\s*[A-Z])*)\s*,', re.M)
KNOWN_FLAGS = {"W", "G", "C", "A", "R"}
ERROR_KIND = re.compile(
    r'inline\s+constexpr\s+ErrorKind\s+k\w+\s*\{\s*"([A-Z_]+)"\s*,\s*(-?\d+)\s*,\s*(true|false)\s*\}')


class SpecError(Exception):
    pass


# ----------------------------------------------------------------- YAML subset


def _scalar(text):
    text = text.strip()
    if text.startswith("'"):
        if not text.endswith("'") or len(text) < 2:
            raise SpecError(f"unterminated single-quoted scalar: {text}")
        return text[1:-1].replace("''", "'")
    if text.startswith('"'):
        if not text.endswith('"') or len(text) < 2:
            raise SpecError(f"unterminated double-quoted scalar: {text}")
        return bytes(text[1:-1], "utf-8").decode("unicode_escape")
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    if text in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


class _Flow:
    """Parser for one flow collection, e.g. {a: [b, 'c d'], e: 1}."""

    def __init__(self, text):
        self.text = text
        self.pos = 0

    def _ws(self):
        while self.pos < len(self.text) and self.text[self.pos] in " \t":
            self.pos += 1

    def _quoted(self):
        quote = self.text[self.pos]
        end = self.pos + 1
        while True:
            end = self.text.find(quote, end)
            if end < 0:
                raise SpecError(f"unterminated quote in flow: {self.text}")
            if quote == "'" and self.text[end + 1:end + 2] == "'":
                end += 2
                continue
            break
        token = self.text[self.pos:end + 1]
        self.pos = end + 1
        return _scalar(token)

    def value(self, stops):
        self._ws()
        if self.pos >= len(self.text):
            raise SpecError(f"truncated flow collection: {self.text}")
        ch = self.text[self.pos]
        if ch == "{":
            return self._mapping()
        if ch == "[":
            return self._sequence()
        if ch in "'\"":
            return self._quoted()
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in stops:
            self.pos += 1
        return _scalar(self.text[start:self.pos])

    def _mapping(self):
        self.pos += 1
        out = {}
        while True:
            self._ws()
            if self.text[self.pos] == "}":
                self.pos += 1
                return out
            key = self.value(":")
            self._ws()
            if self.text[self.pos] != ":":
                raise SpecError(f"expected ':' in flow mapping: {self.text}")
            self.pos += 1
            out[key] = self.value(",}")
            self._ws()
            if self.text[self.pos] == ",":
                self.pos += 1

    def _sequence(self):
        self.pos += 1
        out = []
        while True:
            self._ws()
            if self.text[self.pos] == "]":
                self.pos += 1
                return out
            out.append(self.value(",]"))
            self._ws()
            if self.text[self.pos] == ",":
                self.pos += 1

    def parse(self):
        result = self.value("")
        self._ws()
        if self.pos != len(self.text):
            raise SpecError(f"trailing text after flow collection: {self.text}")
        return result


def _inline(text):
    text = text.strip()
    if text.startswith("{") or text.startswith("["):
        return _Flow(text).parse()
    return _scalar(text)


def _split_key(content):
    """Split `key: value` (key possibly quoted); None when not a mapping entry."""
    if content[:1] in "'\"":
        quote = content[0]
        end = 1
        while True:
            end = content.find(quote, end)
            if end < 0:
                return None
            if quote == "'" and content[end + 1:end + 2] == "'":
                end += 2
                continue
            break
        key_text, rest = content[:end + 1], content[end + 1:]
        if not (rest == ":" or rest.startswith(": ")):
            return None
        return _scalar(key_text), rest[1:].strip()
    match = re.match(r"^([^\s:#'\"{}\[\],][^:#]*?):(?:\s+(.*))?$", content)
    if not match:
        return None
    return match.group(1), (match.group(2) or "").strip()


def parse_yaml(text):
    lines = []
    for raw in text.split("\n"):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw, stripped))

    pos = 0

    def skip_blank():
        nonlocal pos
        while pos < len(lines) and (not lines[pos][2] or lines[pos][2].startswith("#")):
            pos += 1

    def block_scalar(parent_indent):
        nonlocal pos
        while pos < len(lines) and (not lines[pos][2] or lines[pos][0] > parent_indent):
            pos += 1
        return ""  # contents are never compared

    def value_after(rest, indent):
        nonlocal pos
        if rest in ("|", "|-", ">", ">-"):
            return block_scalar(indent)
        if rest:
            return _inline(rest)
        skip_blank()
        if pos < len(lines) and lines[pos][0] > indent:
            return node(lines[pos][0])
        if pos < len(lines) and lines[pos][0] == indent and lines[pos][2].startswith("- "):
            return node(indent)
        return None

    def node(indent):
        nonlocal pos
        skip_blank()
        if pos >= len(lines):
            return None
        if lines[pos][2].startswith("- ") or lines[pos][2] == "-":
            return sequence(indent)
        return mapping(indent)

    def mapping(indent):
        nonlocal pos
        out = {}
        while True:
            skip_blank()
            if pos >= len(lines) or lines[pos][0] < indent:
                return out
            if lines[pos][0] > indent:
                raise SpecError(f"line {pos + 1}: unexpected indentation")
            content = lines[pos][2]
            if content.startswith("- "):
                return out
            split = _split_key(content)
            if split is None:
                raise SpecError(f"line {pos + 1}: not a mapping entry: {content}")
            key, rest = split
            if key in out:
                raise SpecError(f"line {pos + 1}: duplicate key {key!r}")
            pos += 1
            out[key] = value_after(rest, indent)

    def sequence(indent):
        nonlocal pos
        out = []
        while True:
            skip_blank()
            if pos >= len(lines) or lines[pos][0] != indent or not lines[pos][2].startswith("- "):
                if pos < len(lines) and lines[pos][0] > indent:
                    raise SpecError(f"line {pos + 1}: unexpected indentation")
                return out
            content = lines[pos][2][2:].strip()
            split = _split_key(content) if not content.startswith(("{", "[", "'", '"')) else None
            if split is None:
                pos += 1
                if content in ("|", "|-", ">", ">-"):
                    out.append(block_scalar(indent))
                else:
                    out.append(_inline(content))
                continue
            # A mapping item: its first entry sits on the dash line, the rest
            # at the dash column + 2.
            item_indent = indent + 2
            key, rest = split
            pos += 1
            item = {key: value_after(rest, item_indent)}
            more = mapping(item_indent)
            for k, v in more.items():
                if k in item:
                    raise SpecError(f"duplicate key {k!r} in list item")
                item[k] = v
            out.append(item)

    result = node(0)
    skip_blank()
    if pos != len(lines):
        raise SpecError(f"line {pos + 1}: could not parse: {lines[pos][1]}")
    return result


# ----------------------------------------------------------------- extraction


def read_method_table(server_path):
    text = server_path.read_text(encoding="utf-8")
    begin = text.find("// BEGIN METHOD TABLE")
    end = text.find("// END METHOD TABLE")
    if begin < 0 or end < 0 or end < begin:
        raise SpecError(f"{server_path}: METHOD TABLE markers not found")
    rows = []
    for match in TABLE_ROW.finditer(text[begin:end]):
        flags = {f.strip() for f in match.group(2).split("|")}
        unknown = flags - KNOWN_FLAGS
        if unknown:
            raise SpecError(f"{server_path}: method {match.group(1)} has unknown flags {sorted(unknown)}")
        rows.append((match.group(1), flags))
    names = [name for name, _ in rows]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise SpecError(f"{server_path}: duplicate method table names {duplicates}")
    return dict(rows)


def read_error_kinds(contract_path):
    text = contract_path.read_text(encoding="utf-8")
    kinds = {}
    for reason, code, retryable in ERROR_KIND.findall(text):
        if reason in kinds:
            raise SpecError(f"{contract_path}: duplicate reason {reason}")
        kinds[reason] = (int(code), retryable == "true")
    return kinds


def dig(doc, *keys):
    node = doc
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            raise SpecError("spec has no " + " -> ".join(str(k) for k in keys))
        node = node[key]
    return node


def read_spec(spec_path):
    doc = parse_yaml(spec_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise SpecError(f"{spec_path}: top level is not a mapping")
    paths = dig(doc, "paths")
    rpc = dig(paths, "/jsonRPC", "post")
    enum = dig(dig(doc, "components", "schemas", "JsonRpcRequest", "properties", "method"), "enum")
    post_ops, get_ops = {}, {}
    for path, item in paths.items():
        if path == "/jsonRPC" or not isinstance(item, dict):
            continue
        for verb, table, suffix in (("post", post_ops, ""), ("get", get_ops, "_get")):
            op = item.get(verb)
            if op is None:
                continue
            op_id = op.get("operationId") if isinstance(op, dict) else None
            if not isinstance(op_id, str) or not op_id.endswith(suffix):
                continue
            name = op_id[:len(op_id) - len(suffix)] if suffix else op_id
            if path != "/" + name:
                raise SpecError(f"{verb.upper()} {path}: operationId {op_id} does not match its path")
            table[name] = path
    error_data = dig(doc, "components", "schemas", "ErrorData")
    reason_enum = dig(error_data, "properties", "reason", "enum")
    reason_table = {}
    for row in dig(error_data, "x-error-reasons"):
        if not isinstance(row, dict) or set(row) != {"reason", "code", "retryable"}:
            raise SpecError(f"x-error-reasons row is not {{reason, code, retryable}}: {row}")
        if row["reason"] in reason_table:
            raise SpecError(f"x-error-reasons lists {row['reason']} twice")
        reason_table[row["reason"]] = (row["code"], row["retryable"])
    return {
        "enum": list(enum or []),
        "post": post_ops,
        "get": get_ops,
        "admin": list(rpc.get("x-admin-methods") or []),
        "write": list(rpc.get("x-write-methods") or []),
        "reason_enum": list(reason_enum or []),
        "reason_table": reason_table,
    }


# ----------------------------------------------------------------- comparison


def compare(label, expected, actual, problems, expected_name, actual_name):
    expected, actual = set(expected), set(actual)
    if expected == actual:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    detail = []
    if missing:
        detail.append(f"in {expected_name} but not in {actual_name}: {', '.join(missing)}")
    if extra:
        detail.append(f"in {actual_name} but not in {expected_name}: {', '.join(extra)}")
    problems.append(f"{label}: " + "; ".join(detail))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--spec", type=pathlib.Path, default=DEFAULT_SPEC)
    parser.add_argument("--server", type=pathlib.Path, default=DEFAULT_SERVER)
    parser.add_argument("--contract", type=pathlib.Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()

    try:
        table = read_method_table(args.server)
        kinds = read_error_kinds(args.contract)
        spec = read_spec(args.spec)
    except (OSError, SpecError) as error:
        print(f"check-jsonrpc-spec: FAIL: {error}", file=sys.stderr)
        return 1

    problems = []
    names = set(table)
    get_names = {n for n, f in table.items() if "G" in f}
    admin_names = {n for n, f in table.items() if "A" in f}
    write_names = {n for n, f in table.items() if "W" in f}
    extracted = {
        "method table rows": table,
        "GET-flagged methods": get_names,
        "error kinds in the contract header": kinds,
        "/jsonRPC method enum": spec["enum"],
        "POST /<method> operations": spec["post"],
        "GET /<method> operations": spec["get"],
        "ErrorData reason enum": spec["reason_enum"],
        "ErrorData x-error-reasons": spec["reason_table"],
    }
    for what, found in extracted.items():
        if not found:
            problems.append(f"extracted nothing for {what}; the layout changed or the source is empty")

    dupes = sorted({n for n in spec["enum"] if spec["enum"].count(n) > 1})
    if dupes:
        problems.append(f"/jsonRPC method enum lists names twice: {', '.join(dupes)}")
    compare("/jsonRPC method enum", names, spec["enum"], problems, "the method table", "the spec enum")
    compare("POST /<method> paths", names - admin_names, spec["post"], problems,
            "the method table (non-admin)", "the spec")
    compare("GET /<method> paths", get_names, spec["get"], problems, "the G-flagged methods", "the spec")
    compare("x-admin-methods", admin_names, spec["admin"], problems, "the A-flagged methods", "the spec")
    compare("x-write-methods", write_names, spec["write"], problems, "the W-flagged methods", "the spec")

    compare("ErrorData reason enum", kinds, spec["reason_enum"], problems, "json-rpc-contract.h", "the spec enum")
    compare("x-error-reasons", kinds, spec["reason_table"], problems, "json-rpc-contract.h", "x-error-reasons")
    for reason in sorted(set(kinds) & set(spec["reason_table"])):
        if kinds[reason] != spec["reason_table"][reason]:
            code, retryable = kinds[reason]
            spec_code, spec_retryable = spec["reason_table"][reason]
            problems.append(f"x-error-reasons {reason}: header says code {code} retryable {str(retryable).lower()}, "
                            f"spec says code {spec_code} retryable {str(spec_retryable).lower()}")

    if problems:
        print(f"check-jsonrpc-spec: FAIL: {args.spec} disagrees with the server", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"check-jsonrpc-spec: OK: {len(names)} methods ({len(names) - len(admin_names)} POST routes, "
          f"{len(get_names)} GET routes, {len(admin_names)} admin, {len(write_names)} write), "
          f"{len(kinds)} error reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
