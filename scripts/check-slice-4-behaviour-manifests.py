#!/usr/bin/env python3
"""Validate Slice 4 behaviour manifests and check ordinary Tol sources.

Stage 4 keeps behaviour conformance outside Tol code generation: this
script reads JSON manifests and source text, emits warning/error-mode
diagnostics, and never rewrites the Tol source or generated Fift.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_DIR = ROOT / "doc" / "slice4-behaviours"
POSTPONING_MANIFEST = DEFAULT_MANIFEST_DIR / "postponing_state_machine.json"
POSTPONED_AUCTION = ROOT / "examples" / "slice4" / "postponed-auction.tol"
SOURCE_BY_BEHAVIOUR = {
    "jetton_wallet": ROOT / "crypto" / "smartcont" / "tol-stdlib" / "jetton.tol",
    "nft_item": ROOT / "crypto" / "smartcont" / "tol-stdlib" / "nft.tol",
    "multisig": ROOT / "crypto" / "smartcont" / "tol-stdlib" / "multisig.tol",
    "postponing_state_machine": POSTPONED_AUCTION,
}
SCAFFOLD_MANIFESTS = (
    ROOT / "examples" / "slice3" / "jetton-author-trial" / "manifest.json",
    ROOT / "examples" / "slice3" / "nft-author-trial" / "manifest.json",
)
REQUIRED_TOP = {
    "version",
    "schema",
    "behaviour",
    "stage",
    "mode",
    "callbacks",
    "messages",
    "states",
    "postponement",
    "errors",
    "wire_compatibility_exceptions",
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from e


def validate_manifest(path: Path) -> dict:
    data = load_json(path)
    missing = sorted(REQUIRED_TOP - set(data))
    extra = sorted(set(data) - REQUIRED_TOP)
    require(not missing, f"{path}: missing keys: {', '.join(missing)}")
    require(not extra, f"{path}: unexpected keys: {', '.join(extra)}")
    require(data["version"] == 1, f"{path}: version must be 1")
    require(data["schema"] == "slice-4-behaviour-manifest", f"{path}: bad schema")
    require(re.fullmatch(r"[a-z][a-z0-9_]*", data["behaviour"]), f"{path}: invalid behaviour name")
    require(data["mode"] in ("warning", "error"), f"{path}: mode must be warning/error")

    for i, cb in enumerate(data["callbacks"]):
        prefix = f"{path}: callbacks[{i}]"
        require(set(cb) == {"name", "kind", "required"}, f"{prefix}: invalid keys")
        require(isinstance(cb["name"], str) and cb["name"], f"{prefix}: name required")
        require(cb["kind"] in ("receive", "receive_external", "get", "helper"), f"{prefix}: invalid kind")
        require(isinstance(cb["required"], bool), f"{prefix}: required must be bool")

    message_names = set()
    for i, msg in enumerate(data["messages"]):
        prefix = f"{path}: messages[{i}]"
        require(set(msg) == {"name", "opcode", "query_id", "missing_query_id"}, f"{prefix}: invalid keys")
        require(isinstance(msg["name"], str) and msg["name"], f"{prefix}: name required")
        require(re.fullmatch(r"0x[0-9a-fA-F]{8}", msg["opcode"]), f"{prefix}: opcode must be 32-bit hex")
        require(msg["query_id"] in ("required", "optional", "absent"), f"{prefix}: bad query_id")
        require(msg["missing_query_id"] in ("not_applicable", "reject", "author_key"), f"{prefix}: bad missing_query_id")
        if msg["query_id"] == "required":
            require(msg["missing_query_id"] == "not_applicable", f"{prefix}: required query_id must use not_applicable")
        else:
            require(msg["missing_query_id"] != "not_applicable", f"{prefix}: non-required query_id needs a missing policy")
        message_names.add(msg["name"])

    postponement = data["postponement"]
    require(set(postponement) == {"enabled", "queue_field", "deferrable", "budgets"}, f"{path}: invalid postponement keys")
    require(isinstance(postponement["enabled"], bool), f"{path}: postponement.enabled must be bool")
    if postponement["enabled"]:
        require(isinstance(postponement["queue_field"], str) and postponement["queue_field"], f"{path}: queue_field required")
    else:
        require(postponement["queue_field"] is None, f"{path}: disabled queue_field must be null")
    budgets = postponement["budgets"]
    budget_keys = {
        "max_items",
        "max_body_bits",
        "max_body_refs",
        "max_total_body_bits",
        "max_total_body_refs",
        "max_age_seconds",
        "max_drain_items",
        "max_cell_depth",
    }
    require(set(budgets) == budget_keys, f"{path}: invalid budget keys")
    for key, value in budgets.items():
        require(isinstance(value, int) and value >= 0, f"{path}: {key} must be non-negative int")
    require(budgets["max_cell_depth"] <= 1023, f"{path}: max_cell_depth must be <= 1023")
    if postponement["enabled"]:
        for key in ("max_items", "max_age_seconds", "max_drain_items", "max_cell_depth"):
            require(budgets[key] >= 1, f"{path}: enabled postponement requires {key} >= 1")
    for i, item in enumerate(postponement["deferrable"]):
        prefix = f"{path}: postponement.deferrable[{i}]"
        require(set(item) == {"message", "from_states", "until_states"}, f"{prefix}: invalid keys")
        require(item["message"] in message_names, f"{prefix}: unknown message {item['message']}")
        require(isinstance(item["from_states"], list), f"{prefix}: from_states must be list")
        require(isinstance(item["until_states"], list), f"{prefix}: until_states must be list")

    for i, err in enumerate(data["errors"]):
        prefix = f"{path}: errors[{i}]"
        require(set(err) == {"name", "code", "class"}, f"{prefix}: invalid keys")
        require(isinstance(err["code"], int) and 0 <= err["code"] <= 65535, f"{prefix}: code out of range")
        require(err["class"] in ERROR_CLASSES, f"{prefix}: invalid error class")

    for i, exc in enumerate(data["wire_compatibility_exceptions"]):
        prefix = f"{path}: wire_compatibility_exceptions[{i}]"
        require(set(exc) == {"exception", "reason"}, f"{prefix}: invalid keys")
        require(isinstance(exc["exception"], str) and exc["exception"], f"{prefix}: exception required")
        require(isinstance(exc["reason"], str) and exc["reason"], f"{prefix}: reason required")
    return data


def parse_source(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    constants = {
        name: value
        for name, value in re.findall(r"\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_]+)?\s*=\s*(0x[0-9a-fA-F]+)", text)
    }
    structs = {}
    for match in re.finditer(r"struct\s*(?:\(([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)\))?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\}", text, re.S):
        body = match.group(3)
        fields = {}
        for field, typ in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z0-9_?<>]+)", body):
            fields[field] = typ
        opcode = match.group(1)
        if opcode and not opcode.startswith("0x"):
            opcode = constants.get(opcode, opcode)
        structs[match.group(2)] = {
            "opcode": opcode,
            "fields": fields,
        }
    contract_match = re.search(r"contract\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\n\}", text, re.S)
    contract_body = contract_match.group(2) if contract_match else ""
    storage_match = re.search(r"storage\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", contract_body)
    states_match = re.search(r"states\s*:\s*([^\n]+)", contract_body)
    receive_messages = set(re.findall(r"\breceive\s*\(\s*msg\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", contract_body))
    receive_external_messages = set(re.findall(r"\breceive_external\s*\(\s*msg\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", contract_body))
    get_methods = set(re.findall(r"\bget\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", contract_body))
    functions = set(re.findall(r"\bfun\s+((?:[A-Za-z_][A-Za-z0-9_<>]*\.)?[A-Za-z_][A-Za-z0-9_]*)\s*\(", text))
    storage_struct = storage_match.group(1) if storage_match else None
    states = []
    if states_match:
        states = [s.strip() for s in states_match.group(1).split(",") if s.strip()]
    return {
        "text": text,
        "structs": structs,
        "contract": contract_match.group(1) if contract_match else None,
        "storage_struct": storage_struct,
        "storage_fields": structs.get(storage_struct, {}).get("fields", {}) if storage_struct else {},
        "states": states,
        "receive_messages": receive_messages,
        "receive_external_messages": receive_external_messages,
        "get_methods": get_methods,
        "functions": functions,
    }


def check_source_against_manifest(source: Path, manifest: dict) -> list[str]:
    parsed = parse_source(source)
    problems = []
    needs_contract = manifest["postponement"]["enabled"] or any(cb["kind"] != "helper" for cb in manifest["callbacks"])
    if needs_contract and not parsed["contract"]:
        problems.append("source has no `contract X { ... }` declaration")

    for cb in manifest["callbacks"]:
        if not cb["required"]:
            continue
        if cb["kind"] == "receive" and not parsed["receive_messages"]:
            problems.append(f"required receive callback `{cb['name']}` is absent")
        if cb["kind"] == "receive_external" and not parsed["receive_external_messages"]:
            problems.append(f"required receive_external callback `{cb['name']}` is absent")
        if cb["kind"] == "get" and not parsed["get_methods"]:
            problems.append(f"required get callback `{cb['name']}` is absent")
        if cb["kind"] == "helper" and cb["name"] not in parsed["functions"]:
            problems.append(f"required helper `{cb['name']}` is absent")

    for msg in manifest["messages"]:
        struct = parsed["structs"].get(msg["name"])
        if not struct:
            problems.append(f"message struct `{msg['name']}` is absent")
            continue
        if struct["opcode"] and struct["opcode"].lower() != msg["opcode"].lower():
            problems.append(f"message `{msg['name']}` opcode is {struct['opcode']}, expected {msg['opcode']}")
        if msg["query_id"] == "required" and struct["fields"].get("queryId") != "uint64":
            problems.append(f"message `{msg['name']}` must declare `queryId: uint64`")
        if msg["query_id"] == "absent" and "queryId" in struct["fields"]:
            problems.append(f"message `{msg['name']}` must not declare queryId")

    postponement = manifest["postponement"]
    if postponement["enabled"]:
        if 'import "@stdlib/postponement"' not in parsed["text"]:
            problems.append("postponing behaviour requires `import \"@stdlib/postponement\"`")
        queue_field = postponement["queue_field"]
        if parsed["storage_fields"].get(queue_field) != "PostponedQueue":
            problems.append(f"storage field `{queue_field}: PostponedQueue` is required")
        if "enqueueWithQueryId" not in parsed["text"] and ".enqueue(" not in parsed["text"]:
            problems.append("postponing behaviour requires a stdlib enqueue call")
        if "dropNonce" not in parsed["text"] and ".drain(" not in parsed["text"]:
            problems.append("postponing behaviour requires an explicit drain/drop path")
        for item in postponement["deferrable"]:
            if item["message"] not in parsed["structs"]:
                problems.append(f"deferrable message `{item['message']}` is not declared")

    return problems


def effective_mode(manifest: dict, mode: str) -> str:
    if mode == "raw":
        return "warning"
    if mode == "generated":
        return manifest["mode"]
    return mode


def run_validation(manifest_path: Path, source_path: Path, mode: str, emit: bool = True) -> int:
    manifest = validate_manifest(manifest_path)
    problems = check_source_against_manifest(source_path, manifest)
    if not problems:
        if emit:
            print(f"OK {source_path} conforms to {manifest['behaviour']}")
        return 0
    use_mode = effective_mode(manifest, mode)
    label = "warning" if use_mode == "warning" else "error"
    if emit:
        for problem in problems:
            print(f"{label}: {source_path}: {problem}", file=sys.stderr)
    return 0 if use_mode == "warning" else 1


def compile_fift_hash(tol: Path, source: Path) -> str:
    res = subprocess.run(
        [str(tol), "--no-line-comments", "--no-stack-comments", str(source)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"{tol} failed")
    return hashlib.sha256(res.stdout.encode("utf-8")).hexdigest()


def validate_scaffold_behaviour_conformance(path: Path) -> None:
    data = load_json(path)
    entries = data.get("behaviour_conformance")
    require(isinstance(entries, list) and entries, f"{path}: behaviour_conformance must be a non-empty list")
    for i, entry in enumerate(entries):
        prefix = f"{path}: behaviour_conformance[{i}]"
        require(set(entry) == {"behaviour", "manifest", "mode"}, f"{prefix}: invalid keys")
        require(entry["mode"] in ("raw", "generated"), f"{prefix}: mode must be raw/generated")
        manifest_path = (path.parent / entry["manifest"]).resolve()
        require(manifest_path.exists(), f"{prefix}: manifest not found: {entry['manifest']}")
        manifest = validate_manifest(manifest_path)
        require(manifest["behaviour"] == entry["behaviour"], f"{prefix}: behaviour does not match manifest")


def run_default_checks(tol: Path | None) -> int:
    manifests = sorted(DEFAULT_MANIFEST_DIR.glob("*.json"))
    require(bool(manifests), f"{DEFAULT_MANIFEST_DIR}: no behaviour manifests found")
    for path in manifests:
        validate_manifest(path)
    print(f"Validated {len(manifests)} Slice 4 behaviour manifest(s)")

    for manifest_path in manifests:
        manifest = validate_manifest(manifest_path)
        source = SOURCE_BY_BEHAVIOUR.get(manifest["behaviour"])
        if source:
            rc = run_validation(manifest_path, source, "generated")
            if rc != 0:
                return rc
    for scaffold in SCAFFOLD_MANIFESTS:
        validate_scaffold_behaviour_conformance(scaffold)
    print(f"Validated {len(SCAFFOLD_MANIFESTS)} scaffold behaviour declaration(s)")

    bad_source = """
import "@stdlib/common"
struct BadStorage { opened: bool }
struct (0x53413401) Slice4AuctionBid { queryId: uint64 }
contract BadPostponing {
  storage: BadStorage
  receive(msg: Slice4AuctionBid) { msg.queryId; }
}
"""
    with tempfile.TemporaryDirectory() as td:
        bad_path = Path(td) / "bad-postponing.tol"
        bad_path.write_text(bad_source, encoding="utf-8")
        raw_rc = run_validation(POSTPONING_MANIFEST, bad_path, "raw", emit=False)
        require(raw_rc == 0, "raw mode should warn but pass")
        print("Warning-mode negative self-test: passed")
        generated_rc = run_validation(POSTPONING_MANIFEST, bad_path, "generated", emit=False)
        require(generated_rc == 1, "generated mode should fail on nonconformance")
        print("Error-mode negative self-test: passed")

    if tol:
        before = compile_fift_hash(tol, POSTPONED_AUCTION)
        rc = run_validation(POSTPONING_MANIFEST, POSTPONED_AUCTION, "generated")
        if rc != 0:
            return rc
        after = compile_fift_hash(tol, POSTPONED_AUCTION)
        require(before == after, "behaviour validation changed generated Fift")
        fift = subprocess.run(
            [str(tol), "--no-line-comments", "--no-stack-comments", str(POSTPONED_AUCTION)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        ).stdout
        forbidden = ("request_server", "state_machine", "postponing_state_machine", "vtable", "trait")
        require(not any(word in fift for word in forbidden), "behaviour metadata leaked into generated Fift")
        print(f"Bytecode-visible behaviour check: unchanged Fift sha256 {before}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--mode", choices=("raw", "generated", "warning", "error"), default="generated")
    parser.add_argument("--tol", type=Path, default=Path(os.environ.get("TOL_EXECUTABLE", ROOT / "build" / "tol" / "tol")))
    parser.add_argument("--no-bytecode-check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.manifest or args.source:
            require(args.manifest is not None and args.source is not None, "--manifest and --source must be provided together")
            return run_validation(args.manifest, args.source, args.mode)
        tol = None if args.no_bytecode_check else args.tol
        return run_default_checks(tol)
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
