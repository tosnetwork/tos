#!/usr/bin/env python3
"""Exercise an installed shielded tosctl as an ordinary user, without a chain or funds.

What an installation can prove offline: the shield commands are present with their
arguments and refusals; the shipped proving material audits in full under the wrapper's
default, is refused when tampered, and an explicit argument, an environment variable and
the default take precedence in that order; the local Tor client the relayed spend speaks to
runs isolated, onion-only and without a control port; and the machine has no egress.

TOSCTL_SHIELD_MATERIAL names the store path the installation ships. TOSCTL_SHIELD_SMOKE_FAST=1
skips the one positive audit (minutes), for the reruns after the sensitivity controls.
"""

import json
import os
import resource
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

# Checks are explicit raises, never `assert`, so `python3 -O` cannot strip them; the VM test
# runs this file under -O too and rejects any assert statement in it.
AUDIT_MESSAGE = "the proving key"
CEREMONY_VARIABLE = "TOSCTL_SHIELD_CEREMONY_DIR"
PHASE1_VARIABLE = "TOSCTL_SHIELD_PHASE1_DIR"
# The finished ceremony's verifying key, as the client pins it (shield/profile.rs).
PINNED_VK = "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c"
SUBCOMMANDS = (
    "init",
    "sync",
    "balance",
    "address",
    "deposit",
    "withdraw",
    "send",
    "status",
    "audit-ceremony",
)
# The audit must fit the production machine class (12 GB) with room to spare: measured at
# about 150 MiB resident and under three minutes on two cores. The bounds are loose enough
# for a slow runner and tight enough to catch the failure they guard against, a program whose
# circuit synthesis formats the constraint system on every step (tens of GiB, hours).
PEAK_MEMORY_LIMIT = 2 * 1024 * 1024 * 1024
AUDIT_SECONDS_LIMIT = 900
SOCKS_PORT = 9050
# SOCKS5 reply: "connection not allowed by ruleset", what Tor answers a request its
# SafeSocks or OnionTrafficOnly setting forbids.
SOCKS5_NOT_ALLOWED = 0x02


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def record_field(record, field):
    return json.loads(Path(record).read_text())[field]


def torrc_of_running_service():
    """The torrc the running tor.service was started with, read from its unit, not from
    the module's intent."""
    state = subprocess.run(
        ["systemctl", "show", "tor.service", "-p", "ActiveState", "--value"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    require(state == "active", f"tor.service is {state!r}")
    exec_start = subprocess.run(
        ["systemctl", "show", "tor.service", "-p", "ExecStart", "--value"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    words = exec_start.replace(";", " ").split()
    require("-f" in words, f"tor.service ExecStart names no torrc: {exec_start!r}")
    path = Path(words[words.index("-f") + 1])
    require(path.is_file(), f"torrc {path} is not a file")
    return path, path.read_text()


def parse_torrc(text):
    settings = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        settings.setdefault(key, []).append(value.strip())
    return settings


def check_torrc(text):
    """Each property the relayed spend relies on, asserted independently."""
    settings = parse_torrc(text)
    socks = settings.get("SOCKSPort", [])
    require(len(socks) == 1, f"exactly one SOCKSPort, found {socks!r}")
    address, *flags = socks[0].split()
    require(address == f"127.0.0.1:{SOCKS_PORT}", f"SOCKSPort on loopback only, found {address!r}")
    require("OnionTrafficOnly" in flags, f"SOCKSPort carries OnionTrafficOnly: {flags!r}")
    require("IsolateSOCKSAuth" in flags, f"SOCKSPort carries IsolateSOCKSAuth: {flags!r}")
    require("NoOnionTraffic" not in flags, f"SOCKSPort does not forbid onion traffic: {flags!r}")
    for key in ("ClientOnly", "SafeSocks", "SafeLogging"):
        require(settings.get(key) == ["1"], f"{key} 1, found {settings.get(key)!r}")
    policy = [rule.strip() for rule in ",".join(settings.get("SocksPolicy", [])).split(",")]
    require(policy[:1] == ["accept 127.0.0.1"], f"SocksPolicy accepts loopback first: {policy!r}")
    require(policy[-1:] == ["reject *"], f"SocksPolicy rejects everything else last: {policy!r}")
    for key in ("ControlPort", "ControlSocket", "TransPort", "DNSPort", "HiddenServiceDir"):
        require(key not in settings, f"{key} is not configured, found {settings.get(key)!r}")
    for key in ("ORPort", "DirPort"):
        require(
            all(value == "0" for value in settings.get(key, [])),
            f"{key} is off, found {settings.get(key)!r}",
        )
    require(
        settings.get("PublishServerDescriptor") == ["0"],
        f"PublishServerDescriptor 0, found {settings.get('PublishServerDescriptor')!r}",
    )
    return settings


def torrc_checker_is_sensitive(text):
    """The checker must refuse each weakening on its own."""
    weakenings = (
        ("OnionTrafficOnly ", " "),
        ("IsolateSOCKSAuth", "NoIsolateSOCKSAuth"),
        ("SafeSocks 1", "SafeSocks 0"),
        ("ClientOnly 1", "ClientOnly 0"),
        ("SocksPolicy accept 127.0.0.1,reject *", "SocksPolicy accept *"),
    )
    for before, after in weakenings:
        require(before in text, f"the torrc control anchor {before!r} is present")
        try:
            check_torrc(text.replace(before, after, 1))
        except RuntimeError:
            continue
        raise RuntimeError(f"the torrc checker accepted a weakened torrc: {before!r} -> {after!r}")
    for added in ("ControlPort 9051", "ControlSocket /run/tor/control", "HiddenServiceDir /x"):
        try:
            check_torrc(text + "\n" + added + "\n")
        except RuntimeError:
            continue
        raise RuntimeError(f"the torrc checker accepted an added {added!r}")


def socks5_connect(destination, timeout):
    """One SOCKS5 CONNECT, returning Tor's reply status or None when no reply came in time."""
    with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=5) as sock:
        sock.sendall(b"\x05\x01\x00")
        greeting = sock.recv(2)
        require(greeting == b"\x05\x00", f"SOCKS5 handshake without authentication: {greeting!r}")
        kind, address = destination
        if kind == "ipv4":
            request = b"\x05\x01\x00\x01" + socket.inet_aton(address) + (80).to_bytes(2, "big")
        else:
            name = address.encode()
            request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (80).to_bytes(2, "big")
        sock.sendall(request)
        sock.settimeout(timeout)
        try:
            reply = sock.recv(10)
        except socket.timeout:
            return None
        require(len(reply) >= 2 and reply[0] == 0x05, f"a SOCKS5 reply: {reply!r}")
        return reply[1]


def listeners():
    out = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True, check=True).stdout
    found = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            found.append(fields[3])
    return found


def interfaces():
    out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True)
    return [line.split(":")[1].strip().split("@")[0] for line in out.stdout.splitlines()]


def main():
    binary = shutil.which("tosctl")
    if binary is None:
        raise RuntimeError("tosctl is not installed")
    require(os.geteuid() != 0, "acceptance must run as an ordinary user")
    material = Path(os.environ.get("TOSCTL_SHIELD_MATERIAL", ""))
    require(material.is_dir(), "TOSCTL_SHIELD_MATERIAL must name the shipped material")
    fast = os.environ.get("TOSCTL_SHIELD_SMOKE_FAST") == "1"
    base = dict(os.environ)
    for name in ("CONFIG_PATH", "VAULT_URL", CEREMONY_VARIABLE, PHASE1_VARIABLE):
        base.pop(name, None)
    base["TOKIO_WORKER_THREADS"] = "2"

    with tempfile.TemporaryDirectory(prefix="tosctl-shielded-", dir=Path.home()) as directory:
        work = Path(directory)
        os.chmod(work, 0o700)

        def run(*args, error=None, env=None, timeout=60):
            environment = dict(base)
            environment.update(env or {})
            result = subprocess.run(
                [binary, *map(str, args)],
                cwd=work,
                env=environment,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            if error is None:
                require(result.returncode == 0, output)
            else:
                require(result.returncode != 0 and error in output, output)
            return output

        # The commands and their arguments, as the installed binary describes them.
        help_text = run("shield", "--help")
        require("(experimental)" in help_text, "shield --help keeps the experimental mark")
        for command in SUBCOMMANDS:
            require(f"\n  {command} " in help_text, f"shield --help lists {command}")
        send_help = run("shield", "send", "--help")
        for flag in ("--relayer", "--direct", "--from", "--ceremony-dir", "--phase1-dir"):
            require(flag in send_help, f"shield send --help names {flag}")
        for variable in (CEREMONY_VARIABLE, PHASE1_VARIABLE):
            require(variable in send_help, f"shield send --help names {variable}")
        require("--relayer" in run("shield", "status", "--help"), "status takes --relayer")

        # Argument conflicts are refused by the parser, with complete argument sets so only
        # the conflict is wrong.
        profile = work / "relayer.json"
        profile.write_text("{}")
        common = ("shield", "send", "--name", "main", "--to", "shd1example", "--amount", "1")
        run(*common, "--direct", "--from", "ops", "--relayer", profile, error="cannot be used with")
        run(*common, "--relayer", profile, "--unverified-rpc", error="cannot be used with")
        run(*common, "--relayer", profile, "--from", "ops", error="cannot be used with")
        run(*common, "--amount-nanotos", "5", "--direct", "--from", "ops", error="cannot be used")
        run(*common, "--direct", error="--from")
        run(*common, "--relayer", profile, "--quote-lifetime", "10", error="61..=300")
        run(*common, "--relayer", profile, "--relay-timeout", "0", error="1..=60")
        run("shield", "status", "--name", "main", error="--relayer")

        # Refusals that need no chain, instance or configuration: the relayer profile and the
        # pool profile are held to their own rules before anything else is opened.
        run("shield", "status", "--name", "main", "--relayer", work / "none.json", error="read relayer profile")
        run("shield", "status", "--name", "main", "--relayer", work, error="is not a regular file")
        release = {
            "global_id": 3,
            "genesis_root": "11" * 32,
            "genesis_file": "22" * 32,
            "bond": "0:" + "33" * 32,
            "bond_code_hash": "44" * 32,
            "policy_hash": "55" * 32,
            "worker_key_hash": "66" * 32,
            "pool": "0:" + "77" * 32,
            "pool_code_hash": "88" * 32,
            "pool_config_hash": "99" * 32,
        }
        profile.write_text(json.dumps({"schema": "other", "release": release, "bond_init_b64": ""}))
        run("shield", "status", "--name", "main", "--relayer", profile, error="relayer profile schema")
        profile.write_text(
            json.dumps({"schema": "tos.shield.relayer-profile.v1", "release": release, "bond_init_b64": ""})
        )
        run("shield", "status", "--name", "main", "--relayer", profile, error="Bond StateInit")
        pool = work / "pool.json"
        for global_id, error in ((1, "refuses to act on global id 1"), (2, "--allow-testnet-pool"), (99, "names no network")):
            pool.write_text(
                '{"schema":"tosctl-shield-profile-v1","global_id":%d,"pool_address":"0:%s","pool_code_hash":"%s"}'
                % (global_id, "11" * 32, "22" * 32)
            )
            output = run("shield", "init", "--name", "main", "--profile", pool, "--mnemonic-fd", "0", error=error)
            # A refused network gets no notice: the notice is about acting, and nothing acted.
            require("UNPROVEN" not in output and "EXPERIMENTAL" not in output, output)
        pool.write_text(
            '{"schema":"other","global_id":3,"pool_address":"0:%s","pool_code_hash":"%s"}' % ("11" * 32, "22" * 32)
        )
        run("shield", "init", "--name", "main", "--profile", pool, "--mnemonic-fd", "0", error="profile schema")
        # A spend names its material before it reads any configuration: with the variable set
        # to nothing, the refusal names both ways to name the directory.
        withdraw = ("shield", "withdraw", "--name", "main", "--amount", "1", "--to", "0:" + "11" * 32, "--from", "ops")
        output = run(*withdraw, env={CEREMONY_VARIABLE: ""}, error="no directory named")
        require("--ceremony-dir" in output and CEREMONY_VARIABLE in output, output)

        # The material: tampered copies for the refusals and the precedence checks.
        tampered = work / "tampered"
        shutil.copytree(material / "ceremony", tampered / "ceremony")
        for path in (tampered / "ceremony", *(tampered / "ceremony").iterdir()):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        key = tampered / "ceremony" / "key.bin"
        flipped = bytearray(key.read_bytes())
        flipped[100] ^= 0x01
        key.write_bytes(flipped)
        (tampered / "phase1").mkdir()

        # The environment stands in for an absent argument, so a variable naming the tampered
        # copy is what the audit reads, over the wrapper's default.
        output = run("shield", "audit-ceremony", env={CEREMONY_VARIABLE: str(tampered / "ceremony")}, error=AUDIT_MESSAGE)
        require("hashes to" in output, output)
        # An explicit argument wins over the variable: a missing directory named on the command
        # line is what is refused, not the tampered copy the variable names.
        output = run(
            "shield",
            "audit-ceremony",
            "--ceremony-dir",
            work / "absent",
            env={CEREMONY_VARIABLE: str(tampered / "ceremony")},
            error="ceremony directory",
        )
        require(AUDIT_MESSAGE not in output and str(work / "absent") in output, output)
        # Invalid overrides: an empty variable names nothing; a directory without a slice is
        # refused before anything is rebuilt.
        output = run("shield", "audit-ceremony", env={PHASE1_VARIABLE: ""}, error="no directory named")
        require("--phase1-dir" in output and PHASE1_VARIABLE in output, output)
        run("shield", "audit-ceremony", env={PHASE1_VARIABLE: str(tampered / "phase1")}, error="the phase-1 slice")
        run("shield", "audit-ceremony", "--ceremony-dir", tampered / "ceremony", error=AUDIT_MESSAGE)
        run("shield", "audit-ceremony", "--phase1-dir", work / "pool.json", error="is not a directory")

        # The positive audit under the wrapper's default alone: the shipped material is
        # finished and its verifying key is the pinned one. Time and peak memory are the
        # installation's own numbers.
        if fast:
            print("SKIP: positive audit (TOSCTL_SHIELD_SMOKE_FAST)")
        else:
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.monotonic()
            output = run("shield", "audit-ceremony", timeout=1800)
            elapsed = time.monotonic() - started
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            peak = after.ru_maxrss * 1024
            require("OK" in output and "is finished" in output, output)
            # The audit has no network, so it carries no network notice.
            require("UNPROVEN" not in output and "EXPERIMENTAL" not in output, output)
            require(f"Verifying key:   {PINNED_VK} (pinned)" in output, output)
            proving_key = record_field(material / "ceremony" / "ceremony.json", "key_sha256")
            require(f"Proving key:     {proving_key}" in output, output)
            require(peak <= PEAK_MEMORY_LIMIT, f"peak memory {peak} bytes over {PEAK_MEMORY_LIMIT}")
            require(elapsed <= AUDIT_SECONDS_LIMIT, f"audit took {elapsed:.0f} s, over {AUDIT_SECONDS_LIMIT}")
            require(after.ru_utime >= before.ru_utime, "child CPU time was accounted")
            print(f"AUDIT: {elapsed:.1f} s wall, peak RSS {peak / (1024 * 1024):.0f} MiB")

        # The Tor client the relayed spend speaks to, as the running service was started.
        torrc_path, torrc = torrc_of_running_service()
        settings = check_torrc(torrc)
        torrc_checker_is_sensitive(torrc)
        print(f"TORRC: {torrc_path} ({len(settings)} settings)")
        bound = listeners()
        socks = [address for address in bound if address.endswith(f":{SOCKS_PORT}")]
        require(socks == [f"127.0.0.1:{SOCKS_PORT}"], f"SOCKS listens on loopback only: {bound!r}")
        require(not any(a.endswith(":9051") for a in bound), f"no control port listens: {bound!r}")
        status = socks5_connect(("ipv4", "192.0.2.1"), timeout=10)
        require(status == SOCKS5_NOT_ALLOWED, f"an IP-literal CONNECT is refused by ruleset: {status!r}")
        status = socks5_connect(("name", "example.com"), timeout=10)
        require(status == SOCKS5_NOT_ALLOWED, f"a clearnet hostname is refused by ruleset: {status!r}")
        onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
        status = socks5_connect(("name", onion), timeout=3)
        require(status != SOCKS5_NOT_ALLOWED, "an onion name is not refused by ruleset")
        print(f"SOCKS: ruleset refusals {SOCKS5_NOT_ALLOWED:#x}; onion request status {status!r}")

        # No egress: the machine has its loopback and the test harness's own link and nothing
        # else; the harness link is restricted by the VM's configuration.
        links = interfaces()
        require(set(links) <= {"lo", "eth0"}, f"no further interfaces: {links!r}")
        print(f"LINKS: {links}")
    print("PASS: shielded commands, material audit and precedence, Tor client, no egress")


if __name__ == "__main__":
    main()
