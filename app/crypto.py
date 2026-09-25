"""Ed25519 signing keys for agent credentials.

DEMO ONLY: the private key is generated on first start and kept in a local PEM file
(``data/`` by default, mode 0600). It is never written to the database or logged.
A production system would keep it in an HSM/KMS and rotate it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.logging_config import get_logger

log = get_logger("crypto")


class KeyManager:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.kid = hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def generate(cls) -> KeyManager:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: Path) -> KeyManager:
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"Key at {path} is not an Ed25519 private key")
            manager = cls(key)
            log.info("signing_key_loaded", extra={"ctx": {"kid": manager.kid}})
            return manager

        path.parent.mkdir(parents=True, exist_ok=True)
        manager = cls.generate()
        pem = manager._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        log.info("signing_key_generated", extra={"ctx": {"kid": manager.kid}})
        return manager

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def __repr__(self) -> str:  # never expose key material via repr
        return f"KeyManager(kid={self.kid!r})"
