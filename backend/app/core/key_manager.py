
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives import serialization

from backend.app.core.provenance_signing import (
    generate_provenance_key_pair
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SECRETS_DIR = PROJECT_ROOT / "secrets"

PRIVATE_KEY_FILE = SECRETS_DIR / "provenance_private_key.b64"
PUBLIC_KEY_FILE = SECRETS_DIR / "provenance_public_key.b64"


def load_or_create_provenance_keys() -> tuple[str, str]:
    """
    Load the existing Ed25519 key pair or create it once.

    Returns:
        (private_key_b64, public_key_b64)

    The private key must only be used internally.
    Never return it from an API endpoint.
    """
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_FILE.exists():
        private_key_b64 = PRIVATE_KEY_FILE.read_text(
            encoding="utf-8"
        ).strip()

        private_bytes = base64.b64decode(
            private_key_b64,
            validate=True
        )

        private_key = Ed25519PrivateKey.from_private_bytes(
            private_bytes
        )

        derived_public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        derived_public_b64 = base64.b64encode(
            derived_public_bytes
        ).decode("utf-8")

        if PUBLIC_KEY_FILE.exists():
            saved_public_b64 = PUBLIC_KEY_FILE.read_text(
                encoding="utf-8"
            ).strip()

            saved_public_bytes = base64.b64decode(
                saved_public_b64,
                validate=True
            )

            if saved_public_bytes != derived_public_bytes:
                raise ValueError(
                    "Saved public key does not match the private key."
                )
        else:
            PUBLIC_KEY_FILE.write_text(
                derived_public_b64,
                encoding="utf-8"
            )

        return private_key_b64, derived_public_b64

    if PUBLIC_KEY_FILE.exists():
        raise RuntimeError(
            "Public key exists but private key is missing. "
            "Restore the matching private key from a secure backup."
        )

    private_key_b64, public_key_b64 = (
        generate_provenance_key_pair()
    )

    # Create the private key file without overwriting an existing file.
    with PRIVATE_KEY_FILE.open("x", encoding="utf-8") as file:
        file.write(private_key_b64)

    with PUBLIC_KEY_FILE.open("x", encoding="utf-8") as file:
        file.write(public_key_b64)

    return private_key_b64, public_key_b64
