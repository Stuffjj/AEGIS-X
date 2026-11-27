
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


def canonicalize_provenance(provenance) -> str:
    """
    Create deterministic JSON for provenance signing.
    Signature and public key are excluded.
    """

    data = {
        "provenance_id": provenance.provenance_id,
        "evidence_id": provenance.evidence_id,
        "source_id": provenance.source_id,
        "collector_identity": provenance.collector_identity,
        "collection_method": provenance.collection_method,
        "collected_at": provenance.collected_at,
        "transfer_details": provenance.transfer_details
    }

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def generate_provenance_key_pair():
    """Generate an Ed25519 provenance signing key pair."""

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


def sign_provenance(provenance, private_key_b64: str) -> str:
    """Sign canonical provenance using Ed25519."""

    private_bytes = base64.b64decode(
        private_key_b64,
        validate=True
    )

    private_key = Ed25519PrivateKey.from_private_bytes(
        private_bytes
    )

    message = canonicalize_provenance(provenance).encode("utf-8")

    signature = private_key.sign(message)

    return base64.b64encode(signature).decode("utf-8")


def verify_provenance_signature(
    provenance,
    signature_b64: str,
    public_key_b64: str
) -> bool:
    """Verify an Ed25519 provenance signature."""

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

        message = canonicalize_provenance(provenance).encode("utf-8")

        public_key.verify(signature, message)

        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError
    ):
        return False


def calculate_provenance_hash(provenance) -> str:
    """Calculate SHA-256 hash of canonical provenance."""

    message = canonicalize_provenance(provenance).encode("utf-8")

    return hashlib.sha256(message).hexdigest()
