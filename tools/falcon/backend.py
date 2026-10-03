"""Local key handles for the fixed original Falcon profile (experimental).

The native library is an explicit local dependency. There is no remote signing
or deterministic production key generation. Encoded secrets use mutable storage;
Python and the native implementation do not provide a memory-forensics guarantee.
"""
import ctypes
import os
from pathlib import Path

PROFILE = 'TOS-FALCON512-PADDED-v1'
TAG = b'TOS-AUTH-FALCON512-PADDED-v1'

class KeyHandle:
    def __init__(self, secret, public_key):
        if len(secret) != 1281 or len(public_key) != 897:
            raise ValueError('incorrect encoded key length')
        self._secret = bytearray(secret)
        self.public_key = bytes(public_key)
        self.closed = False

    def __repr__(self):
        return 'FalconKeyHandle(<redacted>)'

    def close(self):
        for i in range(len(self._secret)):
            self._secret[i] = 0
        self.closed = True

    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class Backend:
    def __init__(self, library):
        self.lib = ctypes.CDLL(str(Path(library).resolve(strict=True)))
        ptr = ctypes.c_void_p
        size = ctypes.c_size_t
        for name, types in {
            'tos_falcon_offline_keygen': [ptr, size, ptr, ptr],
            'tos_falcon_offline_sign': [ptr, size, ptr, ptr, ptr, size, ptr],
            'tos_falcon512_padded_verify': [ptr, size, ptr, size, ptr, size],
            'tos_falcon512_public_key_valid': [ptr, size],
        }.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = types, ctypes.c_int

    @staticmethod
    def _buffer(value):
        return (ctypes.c_ubyte * len(value)).from_buffer(value)

    @staticmethod
    def _entropy():
        # Exceptions and short reads fail closed; there is no fallback source.
        value = bytearray(os.urandom(48))
        if len(value) != 48: raise RuntimeError('OS entropy failed')
        return value

    def generate_key(self):
        entropy, secret, public = self._entropy(), bytearray(1281), bytearray(897)
        try:
            if self.lib.tos_falcon_offline_keygen(self._buffer(entropy), len(entropy),
                                                self._buffer(secret), self._buffer(public)):
                raise RuntimeError('Falcon key generation failed')
            return KeyHandle(secret, public)
        finally:
            for buffer in (entropy, secret):
                for i in range(len(buffer)): buffer[i] = 0

    def validate_public_key(self, key):
        return type(key) is bytes and len(key) == 897 and self.lib.tos_falcon512_public_key_valid(key, len(key)) == 1

    def verify(self, message, signature, public_key):
        if type(message) is not bytes or type(signature) is not bytes or type(public_key) is not bytes:
            raise TypeError('raw bytes required')
        return self.lib.tos_falcon512_padded_verify(message, len(message), signature,
                                                  len(signature), public_key, len(public_key)) == 1

    def sign(self, handle, message):
        if handle.closed: raise ValueError('key handle is closed')
        if type(message) is not bytes or len(message) > 8192: raise ValueError('invalid raw message')
        entropy, signature = self._entropy(), bytearray(666)
        try:
            if self.lib.tos_falcon_offline_sign(self._buffer(entropy), len(entropy),
                    self._buffer(handle._secret), handle.public_key, message, len(message), self._buffer(signature)):
                raise RuntimeError('Falcon signing or self-verification failed')
            proof = bytes(signature)
            if not self.verify(message, proof, handle.public_key):
                raise RuntimeError('Falcon proof failed local verification')
            return proof
        finally:
            for buffer in (entropy, signature):
                for i in range(len(buffer)): buffer[i] = 0
