"""Actual CLI POP receipt lookup: native transaction history and mocked account proofs."""

import base64
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cli_sign_primary as shared

Cell, from_boc, native = shared.Cell, shared.from_boc, shared.native


def check_receipts(
    args, root, common, receipts, addresses, codes, data, *, successor=False, continuation=None
):
    status = (
        "successor_funded_pop_proven_at_checkpoint"
        if successor
        else "initial_funded_pop_proven_at_checkpoint"
    )
    transactions = {}
    for item in receipts:
        for label in ("paid", "proved"):
            tx = from_boc(item[label]["transaction"])
            transactions[base64.b64encode(tx.hash).decode()] = tx
    calls = []
    mode = {"value": "valid"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(body)
            assert body["method"] == "getTransactions", body
            assert body["params"]["limit"] == 1, body
            tx = transactions[body["params"]["hash"]]
            if mode["value"] == "wrong_transaction":
                tx = next(other for other in transactions.values() if other.hash != tx.hash)
            # Deliberately false RPC metadata: only the BOC can establish identity.
            response = json.dumps(
                dict(
                    jsonrpc="2.0",
                    id=body["id"],
                    ok=True,
                    result=[
                        dict(
                            data=base64.b64encode(tx.boc()).decode(),
                            lt="1",
                            hash="untrusted",
                            utime=0,
                        )
                    ],
                )
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    results = {}

    def invoke(label, item, changes=None, expected=None):
        directory = item["output"]
        options = dict(
            pop_request=directory / "pop-request.boc",
            external_message=directory / "message.boc",
            fee_before_account=directory / "fee-observed-account.boc",
            module_before_account=directory / "module-observed-account.boc",
            history_limit=8,
        )
        options.update(changes or {})
        command = [
            str(args.cli.resolve()),
            "wallet",
            "pq-verify-pop-initial",
            *common,
            "--transaction-rpc-url",
            f"http://127.0.0.1:{server.server_port}",
            "--timeout-seconds",
            "5",
        ]
        for name, value in options.items():
            command += ["--" + name.replace("_", "-"), str(value)]
        start = len(calls)
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (args.output / f"receipt-{label}.stdout").write_text(result.stdout)
        (args.output / f"receipt-{label}.stderr").write_text(result.stderr)
        results[label] = dict(exit=result.returncode, rpc_reads=len(calls) - start)
        if expected:
            assert result.returncode != 0, f"receipt CLI accepted {label}"
            assert expected in result.stderr, result.stderr
            assert status not in result.stdout
        else:
            assert result.returncode == 0, result.stderr
            report = json.loads(result.stdout)
            assert report["status"] == status
            assert report["role"] == item["role"]
            assert (
                report["fee_transaction_hash"] == from_boc(item["paid"]["transaction"]).hash.hex()
            )
            assert (
                report["module_transaction_hash"]
                == from_boc(item["proved"]["transaction"]).hash.hex()
            )
        return len(calls) - start

    try:
        for offset, item in enumerate(receipts):
            for name in (
                "pop-request.boc",
                "fee-observed-account.boc",
                "module-observed-account.boc",
            ):
                (args.output / f"receipt-{offset}-{name}").write_bytes(
                    (item["output"] / name).read_bytes()
                )
            reads = invoke(f"valid-{offset}", item)
            assert reads == 2 * (len(receipts) - offset), (
                "CLI did not walk both authenticated histories"
            )
        first = receipts[0]
        pop = from_boc((first["output"] / "pop-request.boc").read_bytes())
        bits = pop.bits
        changed = Cell(bits[:328] + ("0" if bits[328] == "1" else "1") + bits[329:], pop.refs)
        wrong_challenge = root / "wrong-challenge.boc"
        wrong_challenge.write_bytes(changed.boc())
        invoke(
            "wrong_challenge",
            first,
            dict(pop_request=wrong_challenge),
            "POP challenge differs from request",
        )
        wrong_enrollment = root / "wrong-pop-enrollment.boc"
        wrong_enrollment.write_bytes(
            Cell(bits[:64] + ("0" if bits[64] == "1" else "1") + bits[65:], pop.refs).boc()
        )
        invoke(
            "wrong_enrollment",
            first,
            dict(pop_request=wrong_enrollment),
            "retained POP enrollment or canonical encoding mismatch",
        )
        before = native.active_account(
            addresses["vault"], codes["vault"], data["vault"], balance=99_000_000_000
        )
        wrong_before = root / "wrong-before.boc"
        wrong_before.write_bytes(before.refs[0].boc())
        invoke("wrong_prestate", first, dict(fee_before_account=wrong_before), "pre-state")
        invoke("history_budget", first, dict(history_limit=1), "history budget exhausted")
        invoke(
            "unrelated_message",
            first,
            dict(
                external_message=receipts[1]["output"] / "message.boc",
                fee_before_account=receipts[1]["output"] / "fee-observed-account.boc",
                module_before_account=receipts[1]["output"] / "module-observed-account.boc",
            ),
            "challenge differs",
        )
        mode["value"] = "wrong_transaction"
        invoke("wrong_transaction", first, expected="transaction hash mismatch")
        mode["value"] = "valid"
        (args.output / "receipt-results.json").write_text(
            json.dumps(
                dict(
                    cases=results,
                    requests=calls,
                    scope="Real native transaction BOCs and actual CLI HTTP history adapter; local account-proof verifier is mocked. Not deployed cryptographic proof acquisition or current recovery readiness.",
                ),
                indent=2,
            )
            + "\n"
        )
        if continuation is not None:
            continuation(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    print("9 POP receipt CLI outcomes passed with authenticated-history binding")


if __name__ == "__main__":
    shared.main()
