import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import current_app
from app.core.audit import AuditLogger


# ==================================================
# Exceptions
# ==================================================

class InvitationEmailError(Exception):
    """Raised when invitation email sending fails"""


# ==================================================
# Invitation Email Service
# ==================================================

class InvitationEmailService:
    """
    Sends organization invitation emails via SMTP
    (Gmail App Password or compatible provider).
    """

    def __init__(self):
        cfg = current_app.config

        self.smtp_host = cfg.get("SMTP_HOST")
        self.smtp_port = cfg.get("SMTP_PORT")
        self.smtp_user = cfg.get("SMTP_USERNAME")
        self.smtp_password = cfg.get("SMTP_PASSWORD")
        self.email_from = cfg.get("EMAIL_FROM")

        if not all([
            self.smtp_host,
            self.smtp_port,
            self.smtp_user,
            self.smtp_password,
            self.email_from,
        ]):
            raise RuntimeError("SMTP email configuration is incomplete")

        self.audit = AuditLogger()

    # ==================================================
    # Public API
    # ==================================================

    def send_invitation(
        self,
        *,
        to_email: str,
        invite_url: str,
        org_name: str,
        invited_by: str | None = None,
        org_id: str | None = None,
    ) -> None:
        """
        Send organization invitation email.
        """

        subject = f"You’re invited to join {org_name} on Qrypta"
        html = self._invite_template(
            org_name=org_name,
            invite_url=invite_url,
        )

        try:
            self._send_email(
                to_email=to_email,
                subject=subject,
                html=html,
            )

            # ✅ Audit success (IP captured automatically)
            self.audit.log_event(
                user_id=invited_by,
                org_id=org_id,
                action="org.invite.email.sent",
                resource_type="organization",
                resource_id=org_id,
                metadata={
                    "email": to_email,
                },
            )

        except Exception as exc:
            # ✅ Audit failure (IP captured automatically)
            self.audit.log_event(
                user_id=invited_by,
                org_id=org_id,
                action="org.invite.email.failed",
                resource_type="organization",
                resource_id=org_id,
                metadata={
                    "email": to_email,
                    "error": str(exc),
                },
            )

            raise InvitationEmailError(
                "Failed to send invitation email"
            ) from exc

    # ==================================================
    # Internal Helpers
    # ==================================================

    def _send_email(self, *, to_email: str, subject: str, html: str) -> None:
        """
        Low-level SMTP send.
        """

        msg = MIMEMultipart("alternative")
        msg["From"] = self.email_from
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(html, "html"))

        context = ssl.create_default_context()

        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls(context=context)
            server.login(self.smtp_user, self.smtp_password)
            server.sendmail(
                self.email_from,
                [to_email],
                msg.as_string(),
            )

    # ==================================================
    # Email Template
    # ==================================================

    @staticmethod
    def _invite_template(*, org_name: str, invite_url: str) -> str:
        return f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>You’ve been invited to join <strong>{org_name}</strong></h2>

                <p>
                    You have been invited to collaborate on Qrypta.
                    Click the button below to accept the invitation.
                </p>

                <p style="margin: 24px 0;">
                    <a href="{invite_url}"
                       style="
                           background-color: #2563eb;
                           color: #ffffff;
                           padding: 12px 18px;
                           text-decoration: none;
                           border-radius: 6px;
                           font-weight: bold;
                       ">
                        Accept Invitation
                    </a>
                </p>

                <p>
                    This invitation link will expire automatically.
                    If you did not expect this email, you can safely ignore it.
                </p>

                <hr>
                <small>
                    Qrypta Security Team<br>
                    Secure access • Zero trust • Audited
                </small>
            </body>
        </html>
        """
