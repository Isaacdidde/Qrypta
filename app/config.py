import os
from datetime import timedelta
from dotenv import load_dotenv

# ==================================================
# Load environment variables (.env)
# ==================================================
load_dotenv()


# ==================================================
# Base Config
# ==================================================
class BaseConfig:
    """
    Base configuration shared across environments.
    """

    # --------------------------------------------------
    # Core App
    # --------------------------------------------------
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-key")
    DEBUG = False
    TESTING = False

    # Base URL (used for invitation links, emails)
    APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

    # --------------------------------------------------
    # Database
    # --------------------------------------------------
    MONGO_URI = os.getenv("MONGO_URI")

    # --------------------------------------------------
    # Encryption / Crypto
    # --------------------------------------------------
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

    # --------------------------------------------------
    # Session & Cookies
    # --------------------------------------------------
    SESSION_TIMEOUT_MINUTES = int(
        os.getenv("SESSION_TIMEOUT_MINUTES", 30)
    )

    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=SESSION_TIMEOUT_MINUTES
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv(
        "SESSION_COOKIE_SAMESITE", "Lax"
    )
    SESSION_COOKIE_SECURE = False  # overridden in prod

    # --------------------------------------------------
    # Password Policy
    # --------------------------------------------------
    MIN_PASSWORD_LENGTH = int(
        os.getenv("MIN_PASSWORD_LENGTH", 12)
    )
    MIN_PASSWORD_ENTROPY = int(
        os.getenv("MIN_PASSWORD_ENTROPY", 60)
    )

    # --------------------------------------------------
    # OTP Configuration
    # --------------------------------------------------
    OTP_LENGTH = int(os.getenv("OTP_LENGTH", 6))
    OTP_EXPIRY_MINUTES = int(
        os.getenv("OTP_EXPIRY_MINUTES", 5)
    )
    OTP_MAX_ATTEMPTS = int(
        os.getenv("OTP_MAX_ATTEMPTS", 5)
    )

    # --------------------------------------------------
    # Invitation Configuration
    # --------------------------------------------------
    INVITE_EXPIRY_HOURS = int(
        os.getenv("INVITE_EXPIRY_HOURS", 48)
    )

    # --------------------------------------------------
    # Email — Gmail SMTP (ACTIVE)
    # --------------------------------------------------
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    EMAIL_FROM = os.getenv(
        "EMAIL_FROM",
        "Qrypta Security <no-reply@qrypta.local>",
    )

    # --------------------------------------------------
    # Email — Resend (DISABLED / FUTURE)
    # --------------------------------------------------
    RESEND_API_KEY = os.getenv("RESEND_API_KEY")

    # --------------------------------------------------
    # Rate Limiting / Brute Force Protection
    # --------------------------------------------------
    MAX_LOGIN_ATTEMPTS = int(
        os.getenv("MAX_LOGIN_ATTEMPTS", 5)
    )
    LOGIN_COOLDOWN_SECONDS = int(
        os.getenv("LOGIN_COOLDOWN_SECONDS", 300)
    )

    # --------------------------------------------------
    # Audit & Logging
    # --------------------------------------------------
    AUDIT_ENABLED = True
    AUDIT_RETENTION_DAYS = int(
        os.getenv("AUDIT_RETENTION_DAYS", 180)
    )

    # --------------------------------------------------
    # Security Headers
    # --------------------------------------------------
    SECURITY_HEADERS = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


# ==================================================
# Development
# ==================================================
class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


# ==================================================
# Production
# ==================================================
class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"


# ==================================================
# Testing
# ==================================================
class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SESSION_COOKIE_SECURE = False

    # Relax limits for tests
    OTP_EXPIRY_MINUTES = 1
    OTP_MAX_ATTEMPTS = 10
