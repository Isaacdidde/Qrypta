from flask import current_app

from .encryption import EncryptionService
from .password_generator import PasswordGenerator
from .password_strength import PasswordStrengthChecker
from .captcha import CaptchaService
from .audit import AuditLogger


def get_audit_logger() -> AuditLogger:
    """
    Returns an AuditLogger instance bound to the application's
    audit_logs collection.
    """
    return AuditLogger(current_app.db.audit_logs)
