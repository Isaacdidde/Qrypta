import smtplib
from email.message import EmailMessage
from typing import Optional

from flask import current_app

from app.audit.services import AuditLogger


class EmailDeliveryError(Exception):
    pass


class AuthEmailService:
    """
    Gmail SMTP-based email service (temporary).
    Supports:
    - Login OTP
    - Password reset OTP
    """

    def __init__(self) -> None:
        self.smtp_host = current_app.config.get("SMTP_HOST")
        self.smtp_port = int(current_app.config.get("SMTP_PORT", 587))
        self.smtp_user = current_app.config.get("SMTP_USERNAME")
        self.smtp_pass = current_app.config.get("SMTP_PASSWORD")
        self.email_from = current_app.config.get("EMAIL_FROM")

        if not all([
            self.smtp_host,
            self.smtp_user,
            self.smtp_pass,
            self.email_from,
        ]):
            raise RuntimeError("SMTP email configuration is incomplete")

        self.otp_expiry_minutes = int(
            current_app.config.get("OTP_EXPIRY_MINUTES", 5)
        )

        self.audit = AuditLogger()

    # ==================================================
    # Public API
    # ==================================================

    def send_login_otp(
        self,
        *,
        to_email: str,
        otp: str,
        user_id: Optional[str],
        ip_address: Optional[str] = None,
    ) -> None:
        self._send_email(
            to_email=to_email,
            subject="Your Qrypta login verification code",
            html=self._login_otp_template(otp),
            action="auth.login.otp.sent",
            user_id=user_id,
            ip_address=ip_address,
        )

    def send_forgot_password_otp(
        self,
        *,
        to_email: str,
        otp: str,
        user_id: Optional[str],
        ip_address: Optional[str] = None,
    ) -> None:
        self._send_email(
            to_email=to_email,
            subject="Qrypta password reset verification code",
            html=self._forgot_password_template(otp),
            action="auth.password_reset.otp.sent",
            user_id=user_id,
            ip_address=ip_address,
        )

    # ==================================================
    # Core SMTP Logic
    # ==================================================

    def _send_email(
        self,
        *,
        to_email: str,
        subject: str,
        html: str,
        action: str,
        user_id: Optional[str],
        ip_address: Optional[str],
    ) -> None:
        msg = EmailMessage()
        msg["From"] = self.email_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content("Your email client does not support HTML.")
        msg.add_alternative(html, subtype="html")

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)

            self.audit.log_event(
                action=action,
                resource_type="email",
                resource_id=to_email,
                user_id=user_id,
                ip_address=ip_address,
            )

        except Exception as exc:
            self.audit.log_event(
                action="auth.email.failed",
                resource_type="email",
                resource_id=to_email,
                user_id=user_id,
                ip_address=ip_address,
                metadata={"error": str(exc)},
            )
            raise EmailDeliveryError(
                "Failed to send authentication email"
            ) from exc

    # ==================================================
    # Templates
    # ==================================================

    def _login_otp_template(self, otp: str) -> str:
        return f"""
        <html>
            <body style="font-family: Arial;">
                <h2>Qrypta Login Verification</h2>
                <p>Your one-time login code is:</p>
                <h1>{otp}</h1>
                <p>This code expires in {self.otp_expiry_minutes} minutes.</p>
            </body>
        </html>
        """

    def _forgot_password_template(self, otp: str) -> str:
        return f"""
        <html>
            <body style="font-family: Arial;">
                <h2>Reset Your Qrypta Password</h2>
                <p>Use the code below to reset your password:</p>
                <h1>{otp}</h1>
                <p>This code expires in {self.otp_expiry_minutes} minutes.</p>
            </body>
        </html>
        """
