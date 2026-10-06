"""CLI route promotion, encrypted restart, recipient execution and two rotations.

The account-proof verifier is the existing explicit fixture adapter. A Linux
preload library advances only the fixture wall clock across fixed one-hour fee
slots; no production clock, signature rule or journal barrier is changed.
"""

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import cli_sign_primary as shared

Cell, from_boc, native = shared.Cell, shared.from_boc, shared.native

PATH_ARGUMENTS = {
    "--recovery-manifest",
    "--installed-successor-manifest",
    "--successor-manifest",
    "--fee-history",
    "--wallet-code",
    "--module-code",
    "--vault-code",
    "--proof-config",
    "--journal-dir",
    "--fee-tree-cache",
    "--fee-vault-file",
    "--fee-vault-key-file",
    "--rescue-vault-file",
    "--rescue-vault-key-file",
    "--primary-vault-file",
    "--primary-vault-key-file",
}


def relative_arguments(arguments, directory):
    result = list(arguments)
    changed = 0
    for i, argument in enumerate(result[:-1]):
        if argument in PATH_ARGUMENTS:
            result[i + 1] = os.path.relpath(result[i + 1], directory)
            assert not Path(result[i + 1]).is_absolute()
            changed += 1
    assert changed, "relative-path fixture did not change any command input"
    return result


def check_full_history_refusal(args, request, operation, journal_file, output_dir, label):
    """Fill a valid public history without installing 64 routes or changing limits."""
    path = args.rotation_fee_history_file
    original = path.read_bytes()
    history = json.loads(original)
    keys = set(history["used_fee_public_key_hashes"])
    initial_count = len(keys)
    index = 0
    while len(keys) < 64:
        keys.add(hashlib.sha256(f"PUBLIC-TEST-ONLY-history-capacity-{index}".encode()).hexdigest())
        index += 1
    assert len(keys) == 64
    history["used_fee_public_key_hashes"] = sorted(keys)
    before = journal_file.read_bytes()
    path.write_text(json.dumps(history))
    try:
        refused = request(operation)
        assert (
            refused["status"] == "request_refused"
            and "fee history has no capacity" in refused["reason"]
        ), f"{label} accepted full fee history: {refused}"
        assert journal_file.read_bytes() == before, f"{label} consumed a leaf with full history"
        if output_dir is not None:
            assert not output_dir.exists(), f"{label} wrote output with full history"
        (args.output / ("history-capacity-" + label + ".json")).write_text(
            json.dumps(
                dict(
                    refused=refused,
                    history_keys=64,
                    synthesized_public_hashes=64 - initial_count,
                    journal_unchanged=True,
                    scope="Test-only public history saturation before any migration signature",
                ),
                indent=2,
            )
        )
    finally:
        path.write_bytes(original)


def check_full_journal_attachment_refusal(
    args, request, operation, journal_file, successor_journal
):
    """Use a private limit-zero binary; production still permits 32 retired journals."""
    before = journal_file.read_bytes()
    assert not successor_journal.exists(), "capacity fixture opened its successor journal early"
    refused = request(operation)
    assert refused["status"] != "successor_session_attached", (
        "attachment accepted full journal capacity: " + json.dumps(refused)
    )
    assert (
        refused["status"] == "request_refused" and "session rotation limit" in refused["reason"]
    ), refused
    assert journal_file.read_bytes() == before, (
        "full journal attachment changed current reservations"
    )
    assert not successor_journal.exists(), "full journal attachment opened successor reservations"
    (args.output / "journal-attachment-capacity.json").write_text(
        json.dumps(
            dict(
                refused=refused,
                actual_retired_journals=0,
                private_test_limit=0,
                production_limit=32,
                current_journal_unchanged=True,
                successor_journal_opened=False,
                scope="Private limit-zero build tests the real Attach entry point; no 33-rotation claim",
            ),
            indent=2,
        )
        + "\n"
    )
    print("Private zero-limit Attach preflight refused before opening successor journal")


class FixtureClock:
    def __init__(self, root):
        assert sys.platform.startswith("linux"), "rotation wall-clock fixture requires Linux"
        self.file = root / "rotation-clock-offset"
        self.file.write_text("0")
        self.library = root / "rotation-clock.so"
        subprocess.run(
            [
                "cc",
                "-shared",
                "-fPIC",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-o",
                str(self.library),
                str(shared.ROOT / "test/wallet-v5r2/rotation_clock.c"),
                "-ldl",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self.real_time = time.time
        self.offset = 0
        self.previous = {
            key: os.environ.get(key) for key in ("LD_PRELOAD", "TOS_TEST_CLOCK_OFFSET_FILE")
        }
        # Extend only this run's explicitly trusted mock verifier. A selected
        # live fee account can be proven at a different checkpoint time to make
        # the CLI's cross-account binding check independently falsifiable.
        verifier = root / "verifier"
        source = verifier.read_text()
        # The production verifier process deliberately clears its environment,
        # including LD_PRELOAD. This fixture adapter reads the same test clock
        # explicitly; preserve the production environment isolation.
        clock_read = "now = int(time.time())"
        assert source.count(clock_read) == 1
        source = source.replace(
            clock_read, 'now = int(time.time()) + int((root / "rotation-clock-offset").read_text())'
        )
        needle = (
            'out = dict(status="verified", interface="tos-proof-verify/1", mode=request["mode"],'
        )
        assert source.count(needle) == 1
        source = source.replace(
            needle,
            'if scenario.get("rotation_other_fee_checkpoint") == request["account"]:\n'
            '    target["gen_utime"] -= 1\n'
            'if scenario.get("rotation_live_fee_advance") == request["account"] and request["mode"] == "live":\n'
            '    target["seqno"] += 1\n'
            '    target["root_hash"] = "66" * 32\n' + needle,
        )
        verifier.write_text(source)

    def install(self):
        assert not self.previous["LD_PRELOAD"], "fixture requires an unmodified loader environment"
        os.environ["LD_PRELOAD"] = str(self.library)
        os.environ["TOS_TEST_CLOCK_OFFSET_FILE"] = str(self.file)
        time.time = self.now

    def now(self):
        return self.real_time() + self.offset

    def advance(self, seconds):
        assert 0 < seconds <= 3600 and self.offset + seconds <= 86400
        self.offset += seconds
        # Atomic replacement avoids an empty/truncated clock file between reads.
        temporary = self.file.with_suffix(".next")
        temporary.write_text(str(self.offset))
        temporary.replace(self.file)
        observed = int(
            subprocess.check_output(
                [sys.executable, "-c", "import time; print(int(time.time()))"],
                text=True,
                timeout=10,
            )
        )
        assert abs(observed - int(self.now())) <= 1, "fixture wall-clock instrument did not advance"

    def restore(self):
        time.time = self.real_time
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def check_initial_lock(args, root, request, accounts, codes, data, addresses):
    """Retire PRIMARY in real transactions before the repeated recovery flow."""
    output = root / "initial-primary-lock"
    signed = request(
        dict(
            command="lock",
            valid_for_seconds=600,
            value_nanotos="5000000000",
            output_dir=str(output),
        )
    )
    assert signed["status"] == "fee_message_cached" and signed["leaf"] == 4, signed
    native.NOW = int(time.time())
    original_config = native.config

    def diagnostic(*_args, **_kwargs):
        entries = shared.read_dict(original_config(17), 32)
        price = entries[21].refs[0]
        prefix = 136 if int(price.bits[:8], 2) == 0xD1 else 0
        offset = prefix + 8 + 64 * 3
        entries[21] = Cell().ref(
            Cell(price.bits[:offset] + f"{20000:064b}" + price.bits[offset + 64 :], price.refs)
        )
        return shared.make_dict(entries, 32)

    with patch.object(native, "config", diagnostic):
        emu = native.Emulator(global_version=17)
    try:
        incoming = from_boc((output / "message.boc").read_bytes())
        for name in ["vault", "module", "wallet"]:
            before = native.active_account(addresses[name], codes[name], data[name])
            result = emu.send(before, incoming)
            outgoing = shared.check_execution(
                result, before, incoming, "initial retirement " + name
            )
            assert len(outgoing) == (0 if name == "wallet" else 1)
            if outgoing:
                incoming = outgoing[0]
            state = from_boc(result["shard_account"])
            contents, balance = native.account_data(state)
            history = state.slice()
            last_hash, last_lt = history.uint(256), history.uint(64)
            record = accounts[f"0:{addresses[name][1]:064x}"]
            record.update(
                state_boc=base64.b64encode(state.refs[0].boc()).decode(),
                state_hash=state.refs[0].hash.hex(),
                data_hash=contents.hash.hex(),
                balance=str(balance),
                last_trans_hash=f"{last_hash:064x}",
                last_trans_lt=last_lt,
            )
            data[name] = contents
            (args.output / f"initial-retirement-{name}.json").write_text(
                json.dumps(result, indent=2)
            )
        assert int(data["wallet"].refs[0].bits[10:26], 2) & 2, "initial lock did not retire PRIMARY"
        (root / "scenario.json").write_text(json.dumps(dict(mode="valid", accounts=accounts)))
    finally:
        emu.close()


def check_rotation(
    args,
    root,
    request,
    scenario_path,
    original,
    successor,
    journal,
    old_journal_bytes,
    context,
    emu,
):
    round_number = getattr(args, "rotation_round", 1)
    current_journal = journal / "fee-reservations"
    before = current_journal.read_bytes()
    old_journal = root / "journal" / "fee-reservations"
    report = {}
    for name, operation in [
        ("status", dict(command="status")),
        (
            "retry",
            dict(
                command="retry",
                intent=str(root / "migration" / "pending-intent.boc"),
                output_dir=str(root / "old-route-retry"),
            ),
        ),
    ]:
        refused = request(operation)
        assert (
            refused["status"] == "request_refused"
            and "installed module/fee tuple mismatch" in refused["reason"]
        ), f"old route still serviced {name} after installation"
        assert (
            old_journal.read_bytes() == old_journal_bytes and current_journal.read_bytes() == before
        )
        report["old_" + name] = refused

    scenario = json.loads(scenario_path.read_text())
    wallet_address = f"0:{original['wallet'][1]:064x}"
    original_record = copy.deepcopy(scenario["accounts"][wallet_address])
    code = from_boc(bytes.fromhex(context["template"]["wallet_code"]))
    wallet_data = native.account_data(
        Cell().uint(0, 320).ref(from_boc(base64.b64decode(original_record["state_boc"])))
    )[0]
    auth = wallet_data.refs[0]
    for name, changed in [
        (
            "epoch",
            Cell(
                auth.bits[:26] + f"{int(auth.bits[26:90], 2) - 1:064b}" + auth.bits[90:], auth.refs
            ),
        ),
        ("retirement", Cell(auth.bits[:10] + "0" * 16 + auth.bits[26:], auth.refs)),
    ]:
        data = Cell(wallet_data.bits, [changed])
        account = native.active_account(
            original["wallet"], code, data, balance=int(original_record["balance"])
        ).refs[0]
        scenario["accounts"][wallet_address] = dict(
            original_record,
            state_boc=base64.b64encode(account.boc()).decode(),
            state_hash=account.hash.hex(),
            data_hash=data.hash.hex(),
            last_trans_lt=0,
            last_trans_hash="00" * 32,
        )
        scenario_path.write_text(json.dumps(scenario))
        destination = root / ("regressed-" + name)
        refused = request(dict(command="promote", output_dir=str(destination)))
        assert (
            refused["status"] == "request_refused"
            and "regressed epoch or retirement" in refused["reason"]
        ), f"promotion accepted regressed {name}: {refused}"
        assert not destination.exists() and current_journal.read_bytes() == before
        report["regressed_" + name] = refused
    scenario["accounts"][wallet_address] = original_record
    scenario["rotation_other_fee_checkpoint"] = f"0:{context['addresses']['vault'][1]:064x}"
    scenario_path.write_text(json.dumps(scenario))
    mismatch_output = root / "mismatched-fee-checkpoint"
    mismatch = request(dict(command="promote", output_dir=str(mismatch_output)))
    assert (
        mismatch["status"] == "request_refused"
        and "authenticated account checkpoint mismatch" in mismatch["reason"]
    ), "promotion accepted mismatched authenticated fee checkpoint"
    assert not mismatch_output.exists() and current_journal.read_bytes() == before
    report["mismatched_fee_checkpoint"] = mismatch
    del scenario["rotation_other_fee_checkpoint"]
    scenario_path.write_text(json.dumps(scenario))

    # A failed export must leave the attached journal owned and unchanged.
    failed = request(dict(command="promote", output_dir=str(root / "absent-parent" / "export")))
    assert failed["status"] == "request_refused", "promotion ignored failed durable export"
    assert current_journal.read_bytes() == before and old_journal.read_bytes() == old_journal_bytes
    exported = root / "installed-enrollment"
    scenario["rotation_live_fee_advance"] = f"0:{context['addresses']['vault'][1]:064x}"
    scenario_path.write_text(json.dumps(scenario))
    promoted = request(dict(command="promote", output_dir=str(exported)))
    assert promoted["status"] == "installed_route_promoted", (
        f"promotion did not bind fee to live wallet checkpoint: {promoted}"
    )
    del scenario["rotation_live_fee_advance"]
    scenario_path.write_text(json.dumps(scenario))
    assert promoted["wallet"] == f"0:{original['wallet'][1]:064x}"
    assert promoted["module"] == f"0:{context['addresses']['module'][1]:064x}"
    assert promoted["vault"] == f"0:{context['addresses']['vault'][1]:064x}"
    assert (
        current_journal.read_bytes() == before and old_journal.read_bytes() == old_journal_bytes
    ), "promotion reopened or changed journal reservations"
    available = request(dict(command="status"))
    assert available["status"] == "leaf_available" and available["leaf"] == 6, (
        "promotion lost the successor's held journal continuity"
    )
    duplicate = request(dict(command="promote", output_dir=str(root / "duplicate-promotion")))
    assert duplicate["status"] == "request_refused" and "not attached" in duplicate["reason"]
    resume = json.loads((exported / "resume.json").read_text())
    assert "--successor-manifest" not in resume["fee_session_arguments"]
    assert "--installed-successor-manifest" in resume["fee_session_arguments"]
    assert "--fee-history" in resume["fee_session_arguments"]
    for arguments in [resume["proof_arguments"], resume["fee_session_arguments"]]:
        for i, argument in enumerate(arguments[:-1]):
            if argument in PATH_ARGUMENTS:
                assert Path(arguments[i + 1]).is_absolute(), (
                    "installed export retained a relative path"
                )
    history = json.loads((exported / "fee-history.json").read_text())
    args.rotation_fee_history_file = exported / "fee-history.json"
    assert len(history["used_fee_public_key_hashes"]) == round_number + 1, (
        "promotion lost known fee history"
    )
    cli = [str(args.cli.resolve()), "wallet"]
    resume_cwd = root / "unrelated-directory" / "resume"
    resume_cwd.mkdir(parents=True)
    inspected = subprocess.run(
        cli + ["pq-inspect-initial", *resume["proof_arguments"]],
        cwd=resume_cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert inspected.returncode == 0, (
        "installed proof export depends on original cwd: " + inspected.stderr
    )
    assert json.loads(inspected.stdout)["status"] == "installed_wallet_pair_proven"
    for name, command, directory in [
        ("new", cli + ["pq-fee-session-initial", *resume["fee_session_arguments"]], resume_cwd),
        ("old", args.rotation_previous_command, args.rotation_previous_cwd),
    ]:
        competing = subprocess.run(
            command, cwd=directory, input=b'{"command":"quit"}\n', capture_output=True, timeout=60
        )
        assert (
            competing.returncode != 0 and b"Resource temporarily unavailable" in competing.stderr
        ), f"promotion released the {name} journal lock"
    args.rotation_previous_command = cli + [
        "pq-fee-session-initial",
        *resume["fee_session_arguments"],
    ]
    args.rotation_previous_cwd = resume_cwd

    def reject_intermediate_tree(label):
        if round_number == 1:
            return
        previous_manifest, previous_pin = args.rotation_intermediate_manifest
        destination = root / ("retired-tree-" + label)
        before_refusal = current_journal.read_bytes()
        refused = request(
            dict(
                command="prepare",
                successor_manifest=previous_manifest,
                expected_template_wallet=previous_pin,
                module_nanotos="10000000000",
                vault_nanotos="20000000000",
                valid_for_seconds=600,
                value_nanotos="50000000000",
                output_dir=str(destination),
            )
        )
        assert (
            refused["status"] == "request_refused"
            and "reuses a retained LMS public key" in refused["reason"]
        ), f"rotation accepted retired intermediate tree after {label}: {refused}"
        assert not destination.exists() and current_journal.read_bytes() == before_refusal
        report["retired_tree_" + label] = refused

    if round_number == 1:
        args.rotation_intermediate_manifest = (str(context["manifest"]), context["pin"])
        args.rotation_intermediate_fee_hash = (
            Cell().uint(int(context["template"]["fee_public_key"], 16), 480).hash.hex()
        )
        assert args.rotation_intermediate_fee_hash in history["used_fee_public_key_hashes"]
    reject_intermediate_tree("promotion")

    def reject_shrunk_history(label):
        if round_number == 1:
            return
        # A public file may be edited while this process owns the journal. The
        # process must retain all keys it already observed, across promotion and
        # initial restore alike. Restore the complete backup before any restart.
        complete = (exported / "fee-history.json").read_bytes()
        reduced = copy.deepcopy(history)
        reduced["used_fee_public_key_hashes"].remove(args.rotation_intermediate_fee_hash)
        (exported / "fee-history.json").write_text(json.dumps(reduced))
        try:
            reject_intermediate_tree("history-file-rewrite-" + label)
        finally:
            (exported / "fee-history.json").write_bytes(complete)

    reject_shrunk_history("promotion")

    # Exercise a full strict OutList through the installed SLH/fee route.
    recipient_source = root / "rotation-recipient.fc"
    recipient_source.write_text(
        "() recv_internal(slice body) impure { "
        "throw_unless(1777, get_data().begin_parse().preload_uint(32) == 0); "
        "set_data(begin_cell().store_uint(1, 32).end_cell()); }\n"
    )
    recipient_code = native.compile_contract(
        str(recipient_source), args.output / "rotation-recipient.boc"
    )
    recipient_data = Cell().uint(0, 32)
    recipient = (0, int.from_bytes(native.state_init(recipient_code, recipient_data).hash, "big"))
    payment = native.internal(original["wallet"], recipient, Cell(), value=1_000_000_000)
    actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(payment)
    if round_number == 1:
        # The first recovered wallet funds its next recovery through an actual
        # SLH-authorized action. No classical payer or fabricated credit top-up.
        funding = native.internal(
            original["wallet"], context["addresses"]["vault"], Cell(), value=60_000_000_000
        )
        actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(actions).ref(funding)
    action_file = root / "rotation-actions.boc"
    action_file.write_bytes(actions.boc())
    output = root / "new-route-payment"
    signed = request(
        dict(
            command="execute",
            actions=str(action_file),
            valid_for_seconds=600,
            value_nanotos="5000000000",
            output_dir=str(output),
        )
    )
    assert signed["status"] == "fee_message_cached" and signed["leaf"] == 6, signed
    assert signed["vault"] == promoted["vault"], "promoted execution used the old fee route"
    signed_bytes = (output / "message.boc").read_bytes()
    after = current_journal.read_bytes()
    assert len(after) > len(before)

    # Copy only encrypted key custody, never clone an active LMS journal. A
    # restarted session receives the same real journal and must reinstate wait.
    restored_args = list(resume["fee_session_arguments"])
    backup_dir = root / "encrypted-custody-backup"
    backup_dir.mkdir(mode=0o700)
    copies = {}
    for flag in ["--fee-vault-file", "--rescue-vault-file", "--primary-vault-file"]:
        if flag not in restored_args:
            continue
        position = restored_args.index(flag) + 1
        source = restored_args[position]
        if source not in copies:
            destination = backup_dir / (str(len(copies)) + ".vault.json")
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
            copies[source] = str(destination)
        restored_args[position] = copies[source]
    # Lose only the regenerable public output. Cached retry must recover exactly
    # the signed message without consulting either stateless key vault.
    (output / "message.boc").unlink()
    (output / "binding.json").unlink()
    args.rotation_restart(restored_args, f"rotation-{round_number}-restarted", cwd=resume_cwd)
    reject_intermediate_tree("restore")
    reject_shrunk_history("restore")
    waiting = request(dict(command="status"))
    assert waiting["status"] == "request_refused" and "WaitUntil" in waiting["reason"], (
        "exported enrollment removed the restored journal barrier"
    )
    retry_dir = root / "new-route-payment-retry"
    retried = request(
        dict(command="retry", intent=str(output / "pending-intent.boc"), output_dir=str(retry_dir))
    )
    assert retried["status"] == "fee_message_cached", retried
    assert (retry_dir / "message.boc").read_bytes() == signed_bytes, (
        "installed restart retry changed message bytes"
    )
    assert current_journal.read_bytes() == after, "installed restart retry consumed another leaf"

    scenario = json.loads(scenario_path.read_text())

    def observed(address):
        value = scenario["accounts"][f"0:{address[1]:064x}"]
        return (
            Cell()
            .uint(int(value["last_trans_hash"], 16), 256)
            .uint(value["last_trans_lt"], 64)
            .ref(from_boc(base64.b64decode(value["state_boc"])))
        )

    def record(address, state):
        value = scenario["accounts"][f"0:{address[1]:064x}"]
        contents, balance = native.account_data(state)
        history = state.slice()
        last_hash, last_lt = history.uint(256), history.uint(64)
        value.update(
            state_boc=base64.b64encode(state.refs[0].boc()).decode(),
            state_hash=state.refs[0].hash.hex(),
            data_hash=contents.hash.hex(),
            balance=str(balance),
            last_trans_hash=f"{last_hash:064x}",
            last_trans_lt=last_lt,
        )
        scenario_path.write_text(json.dumps(scenario))

    native.NOW = int(time.time())
    emu.lib.transaction_emulator_set_unixtime(emu.ptr, native.NOW)
    incoming = from_boc(signed_bytes)
    outcomes = {}
    for name, address in [
        ("vault", context["addresses"]["vault"]),
        ("module", context["addresses"]["module"]),
        ("wallet", original["wallet"]),
    ]:
        state = observed(address)
        result = emu.send(state, incoming)
        outgoing = shared.check_execution(result, state, incoming, "promoted " + name)
        expected = 2 if name == "wallet" and round_number == 1 else 1
        assert len(outgoing) == expected, f"promoted {name} did not deliver its exact next message"
        if expected == 2:
            messages = {}
            for message in outgoing:
                fields = message.slice()
                fields.uint(4)
                assert fields.addr() == original["wallet"]
                messages[fields.addr()] = message
            incoming = messages[recipient]
            vault_address = context["addresses"]["vault"]
            funded_before = observed(vault_address)
            funded = emu.send(funded_before, messages[vault_address])
            assert not shared.check_execution(
                funded, funded_before, messages[vault_address], "next rotation funding"
            )
            record(vault_address, from_boc(funded["shard_account"]))
            outcomes["funding"] = funded
        else:
            incoming = outgoing[0]
        record(address, from_boc(result["shard_account"]))
        outcomes[name] = result
    before_recipient = native.active_account(recipient, recipient_code, recipient_data)
    delivered = emu.send(before_recipient, incoming)
    outcomes["recipient"] = delivered
    for name, result in outcomes.items():
        (args.output / f"rotation-{name}.json").write_text(json.dumps(result, indent=2))
    shared.check_recipient(delivered, before_recipient, incoming)
    report.update(
        promoted=promoted,
        signed=signed,
        restored=waiting,
        recipient_delivered=True,
        journal_unchanged_on_retry=True,
        fixed_slot_seconds=3600,
        exported_fee_history=history,
        encrypted_custody_files=len(copies),
        relative_inputs_restored_from_different_cwd=True,
        fixture_clock_offset_seconds=args.rotation_clock.offset,
        scope="local native full transactions with explicit mocked account proofs and public mnemonic fixtures; not live proof acquisition, broadcast/finality or remote-device revocation",
    )
    (args.output / "rotation-results.json").write_text(json.dumps(report, indent=2))

    if round_number == 1:
        # A second generation uses a third independently derived fee tree. Its
        # first source reservation occurs only after the restored wait boundary.
        args.rotation_clock.advance(3600)
        scenario.pop("checkpoint_time", None)
        scenario_path.write_text(json.dumps(scenario))
        next_root = root / "second-rotation"
        next_root.mkdir(mode=0o700)
        (next_root / "scenario.json").symlink_to(scenario_path)
        (next_root / "journal").symlink_to(journal)
        shutil.copyfile(root / "encryption", next_root / "encryption")
        (next_root / "encryption").chmod(0o600)
        next_args = copy.copy(args)
        next_args.rotation_round = 2
        next_args.successor_fee_fixture = args.second_successor_fee_fixture
        next_args.output = args.output / "second-rotation"
        next_args.output.mkdir()
        payload = dict(
            context["template"],
            expected_wallet=f"{original['wallet'][1]:064x}",
            recovery_derivation=json.loads(context["manifest"].read_text())["derivation"],
        )
        addresses = dict(context["addresses"], wallet=original["wallet"])
        codes = dict(context["codes"], wallet=from_boc((exported / "wallet-code.boc").read_bytes()))
        data = dict(context["data"], wallet=native.account_data(observed(original["wallet"]))[0])
        from cli_fee_session_prepare import check_preparation

        check_preparation(
            next_args,
            next_root,
            request,
            journal,
            payload,
            codes,
            data,
            addresses,
            resume["proof_arguments"],
        )
        stale = subprocess.run(
            cli + ["pq-inspect-initial", *resume["proof_arguments"]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert stale.returncode != 0 and "installed module/fee tuple mismatch" in stale.stderr, (
            "a previous exported enrollment authorized the wallet after repeated rotation"
        )
        print(
            "Two installed-route promotions, encrypted restarts, exact retries and native recipient payments passed"
        )


if __name__ == "__main__":
    shared.main()
