from cryptography.fernet import Fernet, InvalidToken
from typing import Optional
import base64


# ==================================================
# Exceptions
# ==================================================

class EncryptionError(Exception):
    """Base encryption exception"""


class DecryptionError(EncryptionError):
    pass


class InvalidEncryptionKey(EncryptionError):
    pass


# ==================================================
# Encryption Service
# ==================================================

class EncryptionService:
    """
    Handles encryption and decryption of sensitive data.
    Uses Fernet symmetric encryption (AES-128 + HMAC).
    """

    def __init__(self, encryption_key: str):
        if not encryption_key:
            raise InvalidEncryptionKey("Encryption key is required")

        try:
            # Fernet keys must be URL-safe base64-encoded 32 bytes
            key_bytes = encryption_key.encode("utf-8")
            base64.urlsafe_b64decode(key_bytes)
        except Exception as exc:
            raise InvalidEncryptionKey(
                "Invalid Fernet encryption key format"
            ) from exc

        self._fernet = Fernet(key_bytes)

    # ==================================================
    # Encrypt
    # ==================================================
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a UTF-8 string and return ciphertext.
        """
        if plaintext is None:
            raise EncryptionError("Cannot encrypt empty data")

        if not isinstance(plaintext, str):
            raise EncryptionError("Plaintext must be a string")

        encrypted = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")

    # ==================================================
    # Decrypt
    # ==================================================
    def decrypt(self, ciphertext: str, *, ttl: Optional[int] = None) -> str:
        """
        Decrypt ciphertext and return plaintext.

        Args:
            ttl (optional): seconds before token expires
        """
        if ciphertext is None:
            raise DecryptionError("Cannot decrypt empty data")

        if not isinstance(ciphertext, str):
            raise DecryptionError("Ciphertext must be a string")

        try:
            decrypted = self._fernet.decrypt(
                ciphertext.encode("utf-8"),
                ttl=ttl,
            )
            return decrypted.decode("utf-8")

        except InvalidToken as exc:
            raise DecryptionError(
                "Invalid, expired, or corrupted encrypted data"
            ) from exc

    # ==================================================
    # Utilities
    # ==================================================
    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet-compatible encryption key.
        Store this securely (env / vault).
        """
        return Fernet.generate_key().decode("utf-8")
