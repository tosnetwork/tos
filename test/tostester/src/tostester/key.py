import functools
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import SigningKey
from tosapi import tos_api

PUB_ED25519_PREFIX = b"\xc6\xb4\x13\x48"
PK_ED25519_PREFIX = b"\x17\x23\x68\x49"


@dataclass(frozen=True)
class Key:
    key: SigningKey = field(default_factory=lambda: SigningKey.generate())

    @functools.cached_property
    def private_key(self):
        return tos_api.Pk_ed25519(key=self.key.encode())

    @functools.cached_property
    def public_key(self):
        return tos_api.Pub_ed25519(key=self.key.verify_key.encode())

    @functools.cached_property
    def id(self):
        return hashlib.sha256(PUB_ED25519_PREFIX + self.public_key.key).digest()

    @property
    def short_key(self):
        return tos_api.Adnl_id_short(id=self.id)

    def write_pub_key_file(self, path: Path) -> Path:
        _ = path.write_bytes(PUB_ED25519_PREFIX + self.public_key.key)
        return path

    def write_pk_key_file(self, path: Path) -> Path:
        _ = path.write_bytes(PK_ED25519_PREFIX + self.private_key.key)
        # Test localnets exercise the same fail-closed keyring boundary as a
        # production node. Do not let the caller's umask leave validator keys
        # readable by the group or other users.
        path.chmod(0o600)
        return path

    def add_to_keyring(self, keyring: Path) -> Path:
        path = keyring / self.id.hex().upper()
        _ = self.write_pk_key_file(path)
        return path
