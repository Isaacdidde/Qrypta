import secrets
import string
from typing import List

from app.core.password_strength import (
    validate_password_strength,
    MIN_PASSWORD_LENGTH,
)


class PasswordGenerator:
    """
    Generates cryptographically secure, policy-compliant passwords.
    """

    def __init__(
        self,
        *,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ):
        if length < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Password length must be at least {MIN_PASSWORD_LENGTH}"
            )

        if not any([use_upper, use_lower, use_digits, use_symbols]):
            raise ValueError("At least one character set must be enabled")

        self.length = length
        self.use_upper = use_upper
        self.use_lower = use_lower
        self.use_digits = use_digits
        self.use_symbols = use_symbols

        self._charsets = self._build_charsets()
        self._combined_charset = "".join(self._charsets)

    # ==================================================
    # Charset Construction
    # ==================================================
    def _build_charsets(self) -> List[str]:
        charsets = []

        if self.use_upper:
            charsets.append(string.ascii_uppercase)
        if self.use_lower:
            charsets.append(string.ascii_lowercase)
        if self.use_digits:
            charsets.append(string.digits)
        if self.use_symbols:
            charsets.append(string.punctuation)

        return charsets

    # ==================================================
    # Password Generation
    # ==================================================
    def generate(self) -> str:
        """
        Generate a password that:
        - Uses CSPRNG
        - Contains at least one character from each enabled set
        - Passes backend strength validation
        """

        # Step 1: guarantee one char from each enabled charset
        password_chars = [
            secrets.choice(charset) for charset in self._charsets
        ]

        # Step 2: fill remaining length from combined charset
        remaining_length = self.length - len(password_chars)
        password_chars.extend(
            secrets.choice(self._combined_charset)
            for _ in range(remaining_length)
        )

        # Step 3: shuffle to avoid predictable positions
        secrets.SystemRandom().shuffle(password_chars)

        password = "".join(password_chars)

        # Step 4: final policy validation (defensive)
        validate_password_strength(password)

        return password
