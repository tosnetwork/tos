"""Actual fee-session CLI startup, exclusive journal and pre-sign restore barrier; mock proofs."""

import json
import selectors
import shutil
import subprocess
import time


def check_session_barrier(args, root, common, accounts, config, inputs):
    cache = root / "tree.cache"
    with cache.open("wb") as output:
        output.write(b"TOSFT001" + bytes.fromhex(inputs["fee_public_key"]))
        with args.fee_session_tree.open("rb") as tree:
            shutil.copyfileobj(tree, output)
    journal = root / "journal"
    journal.mkdir(mode=0o700)
    (root / "scenario.json").write_text(json.dumps(dict(mode="valid", accounts=accounts)))
    (root / "config.json").write_text(json.dumps(config))
    # Avoid straddling a real slot boundary in this specifically pre-boundary test.
    remaining = 3600 - (int(time.time()) - inputs["epoch0"]) % 3600
    if remaining < 30:
        time.sleep(remaining + 1)
    command = [
        str(args.cli.resolve()),
        "wallet",
        "pq-fee-session-initial",
        *common,
        "--journal-dir",
        str(journal),
        "--fee-tree-cache",
        str(cache),
        "--fee-vault-file",
        str(root / "absent-fee-vault"),
        "--fee-record-id",
        "fee",
        "--fee-vault-key-file",
        str(root / "absent-fee-key"),
        "--rescue-vault-file",
        str(root / "absent-rescue-vault"),
        "--rescue-record-id",
        "rescue",
        "--rescue-vault-key-file",
        str(root / "absent-rescue-key"),
    ]
    stderr = (args.output / "session.stderr").open("w")
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    reports = []

    def read():
        assert selector.select(timeout=90), "fee session output timed out"
        line = process.stdout.readline()
        assert line, "fee session exited before response"
        report = json.loads(line)
        reports.append(report)
        return report

    def request(value):
        process.stdin.write(json.dumps(value).encode() + b"\n")
        process.stdin.flush()
        return read()

    try:
        assert read()["status"] == "fee_session_open"
        before = (journal / "fee-reservations").read_bytes()
        status = request(dict(command="status"))
        assert (
            status["status"] == "request_refused" and "restore wait: WaitUntil" in status["reason"]
        ), "session skipped restore barrier"
        location = root / "must-not-sign"
        refused = request(
            dict(
                command="lock",
                valid_for_seconds=600,
                value_nanotos="1000000000",
                output_dir=str(location),
            )
        )
        assert (
            refused["status"] == "request_refused"
            and "restore wait: WaitUntil" in refused["reason"]
        ), "lock bypassed restore barrier"
        assert not location.exists(), "barrier failure created a signing output"
        assert before == (journal / "fee-reservations").read_bytes(), (
            "barrier refusal consumed a fee leaf"
        )
        # A second CLI must fail to acquire the same journal, not become another writer.
        second = subprocess.run(
            command, input=b'{"command":"quit"}\n', capture_output=True, timeout=90
        )
        (args.output / "second.stderr").write_bytes(second.stderr)
        assert second.returncode != 0 and b'"status":"fee_session_open"' not in second.stdout, (
            "concurrent journal owner accepted"
        )
        process.terminate()
        try:
            assert process.wait(timeout=10) == 0, "idle session did not honor cancellation"
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            raise AssertionError("idle session ignored cancellation") from None
        restarted = subprocess.run(
            command,
            input=b'{"command":"status"}\n{"command":"quit"}\n',
            capture_output=True,
            timeout=90,
        )
        (args.output / "restart.stderr").write_bytes(restarted.stderr)
        assert restarted.returncode == 0, restarted.stderr
        restart = [json.loads(line) for line in restarted.stdout.splitlines()]
        assert restart[0]["status"] == "fee_session_open"
        assert (
            restart[1]["status"] == "request_refused"
            and "restore wait: WaitUntil" in restart[1]["reason"]
        ), "reopening removed restore barrier"
        assert before == (journal / "fee-reservations").read_bytes()
        (args.output / "results.json").write_text(
            json.dumps(
                dict(
                    reports=reports,
                    restart=restart,
                    concurrent_exit=second.returncode,
                    journal_unchanged=True,
                    scope="startup and refusal only; not fee signing or retry acceptance",
                ),
                indent=2,
            )
            + "\n"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        selector.close()
        stderr.close()
    print("Fee session restore barrier, exclusive owner and reopen checks passed")


if __name__ == "__main__":
    import cli_inspect_initial

    cli_inspect_initial.main()
