"""Source-content pin for the test wallet, not a Native binary attestation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def inputs(repo):
    paths = [repo / 'test/uno_wallet_freshness.py']
    directories = []
    for package in ('crypto', 'prover'):
        root = repo / 'uno' / package
        for parent, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in ('target', '.git', '__pycache__'))
            directories.append(Path(parent))
            paths.extend(Path(parent) / f for f in sorted(files))
    return sorted(paths), sorted(directories)


def identity(repo):
    digest = hashlib.sha256(b'uno-wallet-source-v1\0')
    paths, _ = inputs(repo)
    for path in paths:
        name = path.relative_to(repo).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, 'big') + name)
        digest.update(len(data).to_bytes(8, 'big') + data)
    return digest.hexdigest()


def pin(repo, binary, destination):
    """Fail before wallet business commands; execute only the checked copy."""
    expected = identity(repo)
    destination.mkdir(parents=True, exist_ok=True)
    snapshot = destination / 'm3-scenario.pinned'
    shutil.copyfile(binary, snapshot)
    snapshot.chmod(0o500)
    result = subprocess.run([str(snapshot), '--source-identity'], text=True,
                            capture_output=True)
    if result.returncode != 0 or result.stdout.strip() != expected:
        snapshot.unlink()
        raise RuntimeError('WALLET_FRESHNESS_MISMATCH: expected source ' + expected +
                           ', wallet reported ' + repr(result.stdout.strip()) +
                           ', exit=' + str(result.returncode))
    # Detect source edits during identification; this is not a timestamp pin.
    if identity(repo) != expected:
        snapshot.unlink()
        raise RuntimeError('WALLET_FRESHNESS_SOURCE_CHANGED')
    observation = dict(source_identity=expected,
                       binary_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                       executable=str(snapshot), scope='uno/crypto + uno/prover source trees')
    (destination / 'wallet-freshness.json').write_text(json.dumps(observation, indent=2) + '\n')
    return snapshot


if __name__ == '__main__':
    root = Path(sys.argv[2]).resolve()
    if sys.argv[1] == '--cargo':
        files, directories = inputs(root)
        for path in files + directories:
            print('cargo:rerun-if-changed=' + str(path))
        print('cargo:rustc-env=UNO_WALLET_SOURCE_ID=' + identity(root))
    elif sys.argv[1] == '--identity':
        print(identity(root))
    else:
        raise SystemExit('unknown freshness mode')
