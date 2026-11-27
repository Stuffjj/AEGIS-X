
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

from backend.app.models.evidence import EvidenceRecord
from backend.app.core.integrity import canonicalize_evidence


def generate_key_pair():
    """Generate an Ed25519 private and public key pair."""

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return (
        base64.b64encode(private_bytes).decode("utf-8"),
        base64.b64encode(public_bytes).decode("utf-8")
    )


def sign_evidence(
    record: EvidenceRecord,
    private_key_b64: str
) -> str:
    """Sign canonical evidence using an Ed25519 private key."""

    private_bytes = base64.b64decode(
        private_key_b64,
        validate=True
    )

    private_key = Ed25519PrivateKey.from_private_bytes(
        private_bytes
    )

    message = canonicalize_evidence(record).encode("utf-8")

    signature = private_key.sign(message)

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(
    record: EvidenceRecord,
    signature_b64: str,
    public_key_b64: str
) -> bool:
    """Verify an evidence signature using its public key."""

    try:
        public_bytes = base64.b64decode(
            public_key_b64,
            validate=True
        )

        signature = base64.b64decode(
            signature_b64,
            validate=True
        )

        public_key = Ed25519PublicKey.from_public_bytes(
            public_bytes
        )

        message = canonicalize_evidence(record).encode("utf-8")

        public_key.verify(signature, message)

        return True

    except (InvalidSignature, ValueError, TypeError):
        return False
