# alerts.py
# Builds and sends a security incident email when high-severity
# entity types are found. Pure stdlib - no new dependency needed.

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_FROM_ADDR = os.getenv("ALERT_FROM_ADDR", SMTP_USERNAME)
SECURITY_TEAM_RECIPIENTS = [
    addr.strip() for addr in os.getenv("SECURITY_TEAM_RECIPIENTS", "").split(",") if addr.strip()
]

HIGH_SEVERITY_TYPES = {
    "API_SECRET_KEY",
    "US_SSN",
    "ACCOUNT_REFERENCE_ID",
    "ENTERPRISE_ASSET_ID",
}


def get_severity(entity_types: list) -> str:
    """entity_types is the plain list of strings scanner.py already returns."""
    if any(t in HIGH_SEVERITY_TYPES for t in entity_types):
        return "HIGH"
    return "LOW"


def _build_alert_body(filename: str, record_id: int, entity_types: list, entity_count: int) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    high_hits = [t for t in entity_types if t in HIGH_SEVERITY_TYPES]
    hits_lines = "\n".join(f"  - {t}" for t in high_hits)

    return (
        "SECURITY INCIDENT ALERT - DLP Gateway\n"
        "=====================================\n\n"
        f"Record ID:        #{record_id}\n"
        f"Timestamp:        {timestamp}\n"
        f"Source File:      {filename}\n"
        f"Severity:         HIGH\n"
        f"Total Entities:   {entity_count}\n\n"
        f"High-Severity Types Detected:\n{hits_lines}\n\n"
        "-------------------------------------\n"
        "This is an automated notification from the DLP Gateway perimeter\n"
        "scanning service. The offending content was already redacted in\n"
        "the response returned to the requesting client. No raw sensitive\n"
        "values are included in this alert.\n"
    )


def send_security_alert(filename: str, record_id: int, entity_types: list, entity_count: int) -> bool:
    """
    Called from FastAPI BackgroundTasks. Never raises - any failure here
    is caught and logged so it can never crash the /upload endpoint.
    """
    try:
        high_hits = [t for t in entity_types if t in HIGH_SEVERITY_TYPES]
        if not high_hits:
            return False

        if not SMTP_USERNAME or not SMTP_PASSWORD or not SECURITY_TEAM_RECIPIENTS:
            print(f"[alerts] Alert needed for '{filename}' but SMTP env vars not fully set. Skipping.")
            return False

        subject = f"[DLP ALERT] High-Severity Leak Detected - {filename}"
        body = _build_alert_body(filename, record_id, entity_types, entity_count)

        message = MIMEMultipart()
        message["From"] = ALERT_FROM_ADDR
        message["To"] = ", ".join(SECURITY_TEAM_RECIPIENTS)
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM_ADDR, SECURITY_TEAM_RECIPIENTS, message.as_string())

        print(f"[alerts] Security alert sent for '{filename}' (record #{record_id})")
        return True

    except smtplib.SMTPException as e:
        print(f"[alerts] SMTP error for '{filename}': {e}")
        return False
    except Exception as e:
        print(f"[alerts] Unexpected alert error for '{filename}': {e}")
        return False
