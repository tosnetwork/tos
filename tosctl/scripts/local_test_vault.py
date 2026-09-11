#!/usr/bin/env python3
"""Run one local-test command with an ephemeral TOS SecretsVault capability.

This is deliberately a *test harness*, not a Vault or HSM implementation.
It creates an empty, private directory and a fresh 256-bit file-vault master
key, then passes the capability only to the child process.  TOS's existing
SecretsVault backend owns encryption, key generation and Ed25519 signing.

The design follows the useful part of HashiCorp Vault's development workflow:
an isolated, throw-away secret store for local tests.  Unlike Vault dev mode,
this never starts a network listener or emits a root token.  It must never be
used for a persistent, shared, or production vault.

Example (the command after ``--`` receives VAULT_URL):

  python3 tosctl/scripts/local_test_vault.py \
    --also-export OPENFOX_TOS_VAULT_URL \
    --also-export OPENFOX_PREDICTION_VAULT_URL -- \
    go test ./pkg/earning -run TestTOSCTLPaymentSinkThreeNode -count=1
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence
from urllib.parse import quote


_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PRIVATE_DIRECTORY_MODE = 0o700


def _private_directory(base: str | None) -> Path:
    """Create and verify a new owner-only directory below an optional base."""
    if base is None:
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        _require_safe_parent(parent)
        return Path(tempfile.mkdtemp(prefix="tosctl-test-vault-", dir=parent))

    parent = Path(base).expanduser().resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("--directory must name an existing directory")
    _require_safe_parent(parent)
    return Path(tempfile.mkdtemp(prefix="tosctl-test-vault-", dir=parent))


def _require_safe_parent(directory: Path) -> None:
    """Require a parent that cannot replace our just-created child directory."""
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise ValueError("--directory must resolve to a real directory")
    permissions = stat.S_IMODE(details.st_mode)
    writable_by_other_principal = permissions & 0o022
    # /tmp is safe for an owner-created child because its sticky bit prevents a
    # different UID from unlinking or replacing that child. Other shared bases
    # are not safe places for a capability-bearing temporary directory.
    safe_sticky_root = details.st_uid == 0 and details.st_mode & stat.S_ISVTX
    safe_private_owner = details.st_uid == os.geteuid() and not writable_by_other_principal
    if not safe_sticky_root and not safe_private_owner:
        raise ValueError("--directory is writable by another principal")


def _require_private_directory(directory: Path) -> None:
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode) or details.st_uid != os.geteuid():
        raise RuntimeError("temporary Vault directory is not owned by this user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise RuntimeError("temporary Vault directory is accessible by another principal")


def _file_vault_url(directory: Path, master_key: str) -> str:
    # quote() prevents a whitespace, '#', or '?' in an operator-supplied base
    # directory from changing the file backend URL grammar.
    vault_path = directory / "vault.json"
    return "file://" + quote(str(vault_path), safe="/") + "?master_key=" + master_key


def _validate_environment_name(value: str) -> str:
    if not _ENVIRONMENT_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError("environment variable name is invalid")
    return value


def _child_environment(vault_url: str, aliases: Sequence[str]) -> dict[str, str]:
    environment = dict(os.environ)
    # The supplied capability replaces, rather than silently falling back to,
    # a caller's persistent Vault configuration.
    environment.pop("VAULT_URL", None)
    for alias in aliases:
        environment.pop(alias, None)
    environment["VAULT_URL"] = vault_url
    for alias in aliases:
        environment[alias] = vault_url
    return environment


def _check_vault_file(directory: Path) -> None:
    """Reject surprising artifacts before cleanup can hide a harness bug."""
    vault_path = directory / "vault.json"
    try:
        details = vault_path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
        raise RuntimeError("test Vault file is not a regular file owned by this user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise RuntimeError("test Vault file is accessible by another principal")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        help="existing parent directory for the new private temporary directory",
    )
    parser.add_argument(
        "--also-export",
        action="append",
        default=[],
        type=_validate_environment_name,
        metavar="NAME",
        help="also provide the capability through NAME (repeatable)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the encrypted temporary directory for debugging (never use in CI)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to run, introduced by --")
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("a command after -- is required")
    if args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command after -- is required")
    if len(set(args.also_export)) != len(args.also_export):
        parser.error("--also-export names must be unique")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    directory = _private_directory(args.directory)
    try:
        # mkdtemp honors umask, but chmod makes the confidentiality invariant
        # explicit and makes the script's behavior independent of it.
        directory.chmod(_PRIVATE_DIRECTORY_MODE)
        _require_private_directory(directory)
        master_key = secrets.token_hex(32)
        vault_url = _file_vault_url(directory, master_key)
        # TOS's file backend creates the encrypted vault on demand. Force a
        # private creation mode for that child, then restore the runner's own
        # umask even if the child fails. This avoids treating encryption as a
        # substitute for filesystem access control.
        prior_umask = os.umask(0o077)
        try:
            result = subprocess.run(args.command, env=_child_environment(vault_url, args.also_export), check=False)
        finally:
            os.umask(prior_umask)
        _check_vault_file(directory)
        if args.keep:
            # The path is useful for debugging; it is not a secret and does
            # not include the master key or the file-backend URL.
            print(f"local test Vault retained at {directory}", file=sys.stderr)
        return result.returncode
    finally:
        if not args.keep:
            shutil.rmtree(directory, ignore_errors=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"local test Vault: {error}", file=sys.stderr)
        raise SystemExit(2)
