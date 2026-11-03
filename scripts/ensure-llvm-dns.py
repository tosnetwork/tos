#!/usr/bin/env python3
# Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
"""Repair only temporary LLVM DNS failure on an explicitly ephemeral CI runner.

The probe retains TLS verification for both resolver and original repository.
Package repository URLs, versions and committed signing-key checks do not change.
Never invoke the opt-in mode on a persistent host.
"""

import argparse
import ipaddress
import os
import socket
import stat
import subprocess
from pathlib import Path

HOST = "apt.llvm.org"
HOSTS_FILE = Path("/etc/hosts")
PROXY_VARIABLES = (
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
)


def lookup():
    return socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)


def probe_origin():
    # Disable curlrc; do not inherit a proxy whose remote_ip would be the proxy.
    # A certificate-valid IP endpoint avoids depending on resolver bootstrap DNS.
    command = [
        "curl",
        "--disable",
        "--ipv4",
        "--proto",
        "=https",
        "--doh-url",
        "https://1.1.1.1/dns-query",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--fail",
        "--silent",
        "--show-error",
        "--head",
        "--output",
        "/dev/null",
        "--write-out",
        "%{remote_ip}",
        "https://apt.llvm.org/",
    ]
    text = subprocess.check_output(command, text=True, stderr=subprocess.PIPE, timeout=40).strip()
    address = ipaddress.IPv4Address(text)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise RuntimeError("TLS origin probe did not return a public unicast IPv4 address")
    return str(address)


def append_host(address):
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(HOSTS_FILE, flags)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("hosts file is not a protected root-owned regular file")
        stream.write(f"\n{address} {HOST} # tos-ci-llvm-dns\n")
        stream.flush()
        os.fsync(stream.fileno())


def ensure_dns():
    try:
        if not lookup():
            raise RuntimeError("The configured resolver returned no addresses")
    except socket.gaierror as error:
        # Do not bypass NXDOMAIN, an explicit hosts mapping, or other DNS policy.
        if error.errno != socket.EAI_AGAIN:
            raise
    else:
        print("LLVM repository resolves through the configured system resolver; no change")
        return False
    if any(os.environ.get(name) for name in PROXY_VARIABLES):
        raise RuntimeError(
            "DNS fallback refuses to infer an origin IP with a configured HTTP proxy"
        )
    if os.geteuid() != 0:
        raise PermissionError("Temporary hosts mapping requires the ephemeral runner's root user")
    address = probe_origin()
    append_host(address)
    if address not in {entry[4][0] for entry in lookup()}:
        raise RuntimeError("The system resolver did not adopt the verified origin mapping")
    print(
        f"Temporary LLVM DNS failure: verified TLS origin {address} mapped on this ephemeral runner"
    )
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ephemeral-runner", action="store_true", required=True)
    parser.parse_args()
    ensure_dns()


if __name__ == "__main__":
    main()
