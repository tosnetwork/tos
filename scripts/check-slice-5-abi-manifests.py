#!/usr/bin/env python3
"""Validate Slice 5 ABI manifests and FunC<->Tol golden fixtures."""

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_DIR = ROOT / "doc" / "slice5-abi-manifests"
DEFAULT_SCHEMA = ROOT / "doc" / "slice-5-abi-manifest-schema.json"

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
OPCODE_RE = re.compile(r"^0x[0-9a-fA-F]{8}$")
ABI_INT_RE = re.compile(r"^(u?int)([1-9][0-9]*)$")
CUSTOM_RE = re.compile(r"^custom:([A-Za-z_][A-Za-z0-9_]*)$")

REQUIRED_TOP = {
    "version",
    "schema",
    "contract",
    "language",
    "stage",
    "messages",
    "get_methods",
    "cell_types",
    "errors",
    "wire_compatibility_exceptions",
}
MESSAGE_KEYS = {
    "name",
    "direction",
    "opcode",
    "query_id",
    "query_id_presence",
    "body_encoding",
    "signature_algorithm",
    "signing_input",
    "fields",
    "fixtures",
}
GETTER_KEYS = {"name", "method_id", "id_source", "arguments", "returns"}
CELL_TYPE_KEYS = {"name", "encoding", "fields", "fixtures"}
FIELD_KEYS = {"name", "type", "bits", "refs"}
STACK_ITEM_KEYS = {"name", "type"}
FIXTURE_REF_KEYS = {"name", "kind", "path"}
ERROR_KEYS = {"name", "code", "class"}
EXCEPTION_KEYS = {"exception", "reason"}

SCALAR_ABI_TYPES = {
    "int",
    "bool",
    "coins",
    "address",
    "any_address",
    "cell",
    "slice",
    "builder",
    "dict",
    "uint256",
    "remaining_bits_and_refs",
}
ERROR_CLASSES = {
    "Ok",
    "Transient",
    "Permanent",
    "Authorization",
    "Protocol",
    "BackPressure",
    "ApplicationSpecific",
}


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        fail(f"{path}: invalid JSON: {e}")


def require_keys(path: Path, data: dict, required: set[str], prefix: str) -> None:
    missing = sorted(required - set(data))
    extra = sorted(set(data) - required)
    require(not missing, f"{path}: {prefix} missing keys: {', '.join(missing)}")
    require(not extra, f"{path}: {prefix} unexpected keys: {', '.join(extra)}")


def require_ident(value: object, context: str) -> None:
    require(isinstance(value, str) and bool(IDENT_RE.fullmatch(value)), f"{context}: expected identifier")


def require_nonempty_string(value: object, context: str) -> None:
    require(isinstance(value, str) and bool(value), f"{context}: expected non-empty string")


def validate_abi_type(value: object, custom_types: set[str], context: str) -> None:
    require(isinstance(value, str), f"{context}: ABI type must be string")
    if value in SCALAR_ABI_TYPES:
        return
    match = ABI_INT_RE.fullmatch(value)
    if match:
        prefix, width_text = match.groups()
        width = int(width_text)
        require(1 <= width <= 1023, f"{context}: {prefix} width must be 1..1023")
        return
    custom = CUSTOM_RE.fullmatch(value)
    if custom:
        type_name = custom.group(1)
        require(type_name in custom_types, f"{context}: custom type `{type_name}` has no cell_types entry")
        return
    fail(f"{context}: unsupported ABI type `{value}`")


def validate_bits_refs(value: object, context: str) -> None:
    require(value is None or (isinstance(value, int) and value >= 0), f"{context}: must be null or non-negative int")


def validate_field(path: Path, field: dict, custom_types: set[str], context: str) -> None:
    require(isinstance(field, dict), f"{path}: {context}: field must be object")
    require_keys(path, field, FIELD_KEYS, context)
    require_ident(field["name"], f"{path}: {context}.name")
    validate_abi_type(field["type"], custom_types, f"{path}: {context}.type")
    validate_bits_refs(field["bits"], f"{path}: {context}.bits")
    validate_bits_refs(field["refs"], f"{path}: {context}.refs")


def validate_stack_item(path: Path, item: dict, custom_types: set[str], context: str) -> None:
    require(isinstance(item, dict), f"{path}: {context}: stack item must be object")
    require_keys(path, item, STACK_ITEM_KEYS, context)
    require_nonempty_string(item["name"], f"{path}: {context}.name")
    validate_abi_type(item["type"], custom_types, f"{path}: {context}.type")


def validate_fixture_ref(path: Path, fixture: dict, context: str) -> Path:
    require(isinstance(fixture, dict), f"{path}: {context}: fixture ref must be object")
    require_keys(path, fixture, FIXTURE_REF_KEYS, context)
    require_nonempty_string(fixture["name"], f"{path}: {context}.name")
    require(fixture["kind"] in ("func", "tol", "cross_language", "golden_cell"), f"{path}: {context}.kind invalid")
    require_nonempty_string(fixture["path"], f"{path}: {context}.path")
    fixture_path = ROOT / fixture["path"]
    require(fixture_path.exists(), f"{path}: {context}.path missing: {fixture_path}")
    return fixture_path


def validate_fixture_file(path: Path, manifest_path: Path, manifest: dict, message_name: str) -> dict:
    data = load_json(path)
    required = {
        "version",
        "schema",
        "contract",
        "message",
        "producer_language",
        "body_encoding",
        "canonical_body_hex",
        "canonical_sha256",
        "fields",
    }
    require_keys(path, data, required, "fixture")
    require(data["version"] == 1, f"{path}: fixture version must be 1")
    require(data["schema"] == "slice-5-abi-fixture", f"{path}: bad fixture schema")
    require(data["contract"] == manifest["contract"], f"{path}: contract must match {manifest_path}")
    require(data["message"] == message_name, f"{path}: message must match manifest fixture ref")
    require(data["producer_language"] in ("func", "tol", "golden"), f"{path}: bad producer_language")
    require(data["body_encoding"] in ("tol_auto_struct", "manual_cell", "raw_slice", "tlb_reference"), f"{path}: bad body_encoding")
    body_hex = data["canonical_body_hex"]
    require(isinstance(body_hex, str) and len(body_hex) % 2 == 0, f"{path}: canonical_body_hex must be even-length hex")
    try:
        body = bytes.fromhex(body_hex)
    except ValueError as e:
        fail(f"{path}: canonical_body_hex is not hex: {e}")
    expected = hashlib.sha256(body).hexdigest()
    require(data["canonical_sha256"] == expected, f"{path}: canonical_sha256 mismatch, expected {expected}")
    require(isinstance(data["fields"], dict), f"{path}: fields must be object")
    return data


def validate_manifest(path: Path) -> tuple[dict, list[dict]]:
    data = load_json(path)
    require(isinstance(data, dict), f"{path}: manifest must be object")
    require_keys(path, data, REQUIRED_TOP, "manifest")
    require(data["version"] == 1, f"{path}: version must be 1")
    require(data["schema"] == "slice-5-abi-manifest", f"{path}: bad schema")
    require_ident(data["contract"], f"{path}: contract")
    require(data["language"] in ("tol", "func", "mixed"), f"{path}: language must be tol/func/mixed")
    require_nonempty_string(data["stage"], f"{path}: stage")

    require(isinstance(data["cell_types"], list), f"{path}: cell_types must be array")
    custom_types = set()
    for i, cell_type in enumerate(data["cell_types"]):
        prefix = f"cell_types[{i}]"
        require(isinstance(cell_type, dict), f"{path}: {prefix}: must be object")
        require_keys(path, cell_type, CELL_TYPE_KEYS, prefix)
        require_ident(cell_type["name"], f"{path}: {prefix}.name")
        custom_types.add(cell_type["name"])

    loaded_fixtures = []
    for i, cell_type in enumerate(data["cell_types"]):
        prefix = f"cell_types[{i}]"
        require(cell_type["encoding"] in ("tol_auto_struct", "manual_builder", "tlb_reference", "raw_suffix"), f"{path}: {prefix}.encoding invalid")
        require(isinstance(cell_type["fields"], list), f"{path}: {prefix}.fields must be array")
        for j, field in enumerate(cell_type["fields"]):
            validate_field(path, field, custom_types, f"{prefix}.fields[{j}]")
        require(isinstance(cell_type["fixtures"], list), f"{path}: {prefix}.fixtures must be array")
        if cell_type["encoding"] in ("manual_builder", "raw_suffix"):
            require(cell_type["fixtures"], f"{path}: {prefix}: {cell_type['encoding']} requires at least one fixture")
        for j, fixture in enumerate(cell_type["fixtures"]):
            validate_fixture_ref(path, fixture, f"{prefix}.fixtures[{j}]")

    require(isinstance(data["messages"], list) and data["messages"], f"{path}: messages must be non-empty array")
    for i, msg in enumerate(data["messages"]):
        prefix = f"messages[{i}]"
        require(isinstance(msg, dict), f"{path}: {prefix}: must be object")
        require_keys(path, msg, MESSAGE_KEYS, prefix)
        require_ident(msg["name"], f"{path}: {prefix}.name")
        require(msg["direction"] in ("internal_in", "internal_out", "external_in", "external_out"), f"{path}: {prefix}.direction invalid")
        if msg["opcode"] is not None:
            require(isinstance(msg["opcode"], str) and OPCODE_RE.fullmatch(msg["opcode"]), f"{path}: {prefix}.opcode must be 32-bit hex or null")
        require(msg["query_id"] in ("required_after_opcode", "optional", "absent", "custom_external"), f"{path}: {prefix}.query_id invalid")
        require(msg["query_id_presence"] in ("not_applicable", "flag_bit_before_query_id", "flag_bit_after_opcode", "length_prefixed", "custom_external"), f"{path}: {prefix}.query_id_presence invalid")
        if msg["query_id"] == "optional":
            require(msg["query_id_presence"] != "not_applicable", f"{path}: {prefix}: optional query_id requires presence indicator")
        if msg["query_id"] in ("required_after_opcode", "absent"):
            require(msg["query_id_presence"] == "not_applicable", f"{path}: {prefix}: {msg['query_id']} requires query_id_presence not_applicable")
        if msg["query_id"] == "custom_external":
            require(msg["query_id_presence"] == "custom_external", f"{path}: {prefix}: custom_external requires custom_external presence")
        require(msg["body_encoding"] in ("tol_auto_struct", "manual_cell", "raw_slice", "tlb_reference"), f"{path}: {prefix}.body_encoding invalid")
        if msg["opcode"] is None:
            require(msg["body_encoding"] != "tol_auto_struct", f"{path}: {prefix}: opcode null cannot use tol_auto_struct")
        require(msg["signature_algorithm"] in ("none", "ed25519"), f"{path}: {prefix}.signature_algorithm invalid")
        require(msg["signing_input"] in ("none", "cell_hash", "raw_bits"), f"{path}: {prefix}.signing_input invalid")
        if msg["signature_algorithm"] == "none":
            require(msg["signing_input"] == "none", f"{path}: {prefix}: unsigned message must use signing_input none")
        if msg["signature_algorithm"] == "ed25519":
            require(msg["signing_input"] in ("cell_hash", "raw_bits"), f"{path}: {prefix}: ed25519 requires signing_input cell_hash/raw_bits")
            require(msg["fixtures"], f"{path}: {prefix}: ed25519 signed bodies require fixtures")
        require(isinstance(msg["fields"], list), f"{path}: {prefix}.fields must be array")
        for j, field in enumerate(msg["fields"]):
            validate_field(path, field, custom_types, f"{prefix}.fields[{j}]")
        require(isinstance(msg["fixtures"], list), f"{path}: {prefix}.fixtures must be array")
        if msg["body_encoding"] in ("manual_cell", "raw_slice"):
            require(msg["fixtures"], f"{path}: {prefix}: {msg['body_encoding']} requires at least one fixture")
        for j, fixture in enumerate(msg["fixtures"]):
            fixture_path = validate_fixture_ref(path, fixture, f"{prefix}.fixtures[{j}]")
            loaded_fixtures.append(validate_fixture_file(fixture_path, path, data, msg["name"]))

    require(isinstance(data["get_methods"], list), f"{path}: get_methods must be array")
    for i, getter in enumerate(data["get_methods"]):
        prefix = f"get_methods[{i}]"
        require(isinstance(getter, dict), f"{path}: {prefix}: must be object")
        require_keys(path, getter, GETTER_KEYS, prefix)
        require_ident(getter["name"], f"{path}: {prefix}.name")
        require(isinstance(getter["method_id"], int) and getter["method_id"] >= 1, f"{path}: {prefix}.method_id must be >= 1")
        require(getter["id_source"] in ("explicit", "auto_derived"), f"{path}: {prefix}.id_source invalid")
        require(isinstance(getter["arguments"], list), f"{path}: {prefix}.arguments must be array")
        require(isinstance(getter["returns"], list), f"{path}: {prefix}.returns must be array")
        for j, item in enumerate(getter["arguments"]):
            validate_stack_item(path, item, custom_types, f"{prefix}.arguments[{j}]")
        for j, item in enumerate(getter["returns"]):
            validate_stack_item(path, item, custom_types, f"{prefix}.returns[{j}]")

    require(isinstance(data["errors"], list), f"{path}: errors must be array")
    for i, err in enumerate(data["errors"]):
        prefix = f"errors[{i}]"
        require(isinstance(err, dict), f"{path}: {prefix}: must be object")
        require_keys(path, err, ERROR_KEYS, prefix)
        require_nonempty_string(err["name"], f"{path}: {prefix}.name")
        require(isinstance(err["code"], int) and 1024 <= err["code"] <= 65535, f"{path}: {prefix}.code must be 1024..65535")
        require(err["class"] in ERROR_CLASSES, f"{path}: {prefix}.class invalid")

    require(isinstance(data["wire_compatibility_exceptions"], list), f"{path}: wire_compatibility_exceptions must be array")
    exceptions_text = " ".join(
        f"{exc.get('exception', '')} {exc.get('reason', '')}" for exc in data["wire_compatibility_exceptions"] if isinstance(exc, dict)
    ).lower()
    for i, exc in enumerate(data["wire_compatibility_exceptions"]):
        prefix = f"wire_compatibility_exceptions[{i}]"
        require(isinstance(exc, dict), f"{path}: {prefix}: must be object")
        require_keys(path, exc, EXCEPTION_KEYS, prefix)
        require_nonempty_string(exc["exception"], f"{path}: {prefix}.exception")
        require_nonempty_string(exc["reason"], f"{path}: {prefix}.reason")
    if any(err["class"] == "BackPressure" for err in data["errors"]):
        require("backpressure" in exceptions_text and "5.7" in exceptions_text, f"{path}: BackPressure errors require an explicit §5.7 compatibility exception")

    return data, loaded_fixtures


def validate_cross_language_fixtures(fixtures: list[dict]) -> int:
    groups: dict[tuple[str, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for fixture in fixtures:
        groups[(fixture["contract"], fixture["message"])][fixture["producer_language"]].append(fixture)

    compared = 0
    for (contract, message), by_language in groups.items():
        if "func" not in by_language or "tol" not in by_language:
            continue
        func_fixture = by_language["func"][0]
        tol_fixture = by_language["tol"][0]
        if func_fixture["canonical_body_hex"].lower() != tol_fixture["canonical_body_hex"].lower():
            fail(f"{contract}.{message}: FunC/Tol canonical_body_hex mismatch")
        if func_fixture["canonical_sha256"].lower() != tol_fixture["canonical_sha256"].lower():
            fail(f"{contract}.{message}: FunC/Tol canonical_sha256 mismatch")
        compared += 1
    require(compared > 0, "no FunC/Tol cross-language fixture pair was compared")
    return compared


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-dir", type=Path, default=DEFAULT_MANIFEST_DIR)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.schema.exists():
        print(f"{args.schema}: schema not found", file=sys.stderr)
        return 1
    load_json(args.schema)
    if not args.manifest_dir.is_dir():
        print(f"{args.manifest_dir}: manifest directory not found", file=sys.stderr)
        return 1

    manifest_paths = sorted(args.manifest_dir.glob("*.json"))
    if not manifest_paths:
        print(f"{args.manifest_dir}: no ABI manifests found", file=sys.stderr)
        return 1

    all_fixtures = []
    try:
        for path in manifest_paths:
            _manifest, fixtures = validate_manifest(path)
            all_fixtures.extend(fixtures)
        compared = validate_cross_language_fixtures(all_fixtures)
    except ValidationError as e:
        print(e, file=sys.stderr)
        return 1

    print(f"Validated {len(manifest_paths)} Slice 5 ABI manifest(s); compared {compared} FunC/Tol fixture pair(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
