import math
import string
import re


# ==================================================
# Configuration (tune once, enforce everywhere)
# ==================================================

MIN_PASSWORD_LENGTH = 12
MIN_ENTROPY_BITS = 60

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "password123",
    "admin",
    "letmein",
    "welcome",
}


# ==================================================
# Exceptions
# ==================================================

class PasswordStrengthError(ValueError):
    pass


# ==================================================
# Password Strength Checker
# ==================================================

class PasswordStrengthChecker:
    """
    Estimates password strength based on entropy and patterns.
    """

    def __init__(self, password: str):
        self.password = password or ""

    # -----------------------------
    # Character set size
    # -----------------------------
    def _charset_size(self) -> int:
        size = 0
        pwd = self.password

        if any(c in string.ascii_lowercase for c in pwd):
            size += 26
        if any(c in string.ascii_uppercase for c in pwd):
            size += 26
        if any(c in string.digits for c in pwd):
            size += 10
        if any(c in string.punctuation for c in pwd):
            size += len(string.punctuation)

        return size

    # -----------------------------
    # Entropy calculation
    # -----------------------------
    def entropy(self) -> float:
        charset = self._charset_size()
        if charset == 0:
            return 0.0

        return len(self.password) * math.log2(charset)

    # -----------------------------
    # Pattern penalties
    # -----------------------------
    def has_repeated_chars(self) -> bool:
        return bool(re.search(r"(.)\1{2,}", self.password))

    def has_sequential_chars(self) -> bool:
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
        ]

        for seq in sequences:
            for i in range(len(seq) - 3):
                if seq[i : i + 4] in self.password:
                    return True
        return False

    def is_common_password(self) -> bool:
        return self.password.lower() in COMMON_PASSWORDS

    # -----------------------------
    # Human-readable label
    # -----------------------------
    def strength_label(self) -> str:
        e = self.entropy()

        if e < 40:
            return "Very Weak"
        elif e < 60:
            return "Weak"
        elif e < 80:
            return "Moderate"
        elif e < 100:
            return "Strong"
        else:
            return "Very Strong"


# ==================================================
# Public Validation API (USED BY AuthService)
# ==================================================

def validate_password_strength(password: str) -> None:
    """
    Enforces password security policy.
    Raises PasswordStrengthError on failure.
    """

    if not password:
        raise PasswordStrengthError("Password cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordStrengthError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )

    checker = PasswordStrengthChecker(password)

    if checker.is_common_password():
        raise PasswordStrengthError("Password is too common")

    if checker.has_repeated_chars():
        raise PasswordStrengthError(
            "Password contains repeated characters"
        )

    if checker.has_sequential_chars():
        raise PasswordStrengthError(
            "Password contains sequential characters"
        )

    entropy = checker.entropy()
    if entropy < MIN_ENTROPY_BITS:
        raise PasswordStrengthError(
            "Password is too weak. Add more length or variety."
        )
