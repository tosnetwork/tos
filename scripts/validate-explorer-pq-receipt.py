"""Validate typed fragments in public native RPC receipts with jsonschema 4.26.0."""

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, nargs="+")
    args = parser.parse_args()
    schema = json.loads((ROOT / "doc/explorer-pq-rpc-v1.schema.json").read_text())
    counts = {}

    def validate(name, value):
        Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]}).validate(value)
        counts[name] = counts.get(name, 0) + 1

    for receipt in args.receipt:
        records = json.loads(receipt.read_text())
        assert records, f"empty receipt: {receipt}"
        for record in records:
            response = record["response"]
            if "error_info" in response:
                validate("ErrorInfo", response["error_info"])
            result = response.get("result", {})
            if not isinstance(result, dict):
                continue
            if "verification" in result:
                validate("PqSignaturesResult", result)
            if "pq_authorization" in result:
                validate("PublicAuthorization", result["pq_authorization"])
            if "decoded" in result:
                validate("DecodedConfig", result["decoded"])
            if record["method"] == "getProofQuery" and record["http_status"] == 200:
                validate("ProofResult", result)
    required = {"PqSignaturesResult", "PublicAuthorization", "DecodedConfig", "ProofResult"}
    assert required <= counts.keys(), f"missing typed responses: {required - counts.keys()}"
    print(json.dumps({"status": "passed", "validated_fragments": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
