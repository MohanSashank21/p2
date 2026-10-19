import pytest

from app.core.config import settings
from app.core.exceptions import EmailDeliveryError
from app.services import email_service


class FakeSMTP:
  def __init__(self, refused_recipients):
    self.refused_recipients = refused_recipients

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return None

  def ehlo(self):
    return None

  def starttls(self, **_kwargs):
    return None

  def send_message(self, _message):
    return self.refused_recipients


@pytest.mark.parametrize("use_ssl", [False, True])
def test_send_email_rejects_smtp_refused_recipient(monkeypatch, use_ssl):
  refused = {"person@example.com": (550, b"Mailbox unavailable")}
  smtp_client = FakeSMTP(refused)

  monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
  monkeypatch.setattr(settings, "SMTP_FROM", "noreply@example.com")
  monkeypatch.setattr(settings, "SMTP_USER", None)
  monkeypatch.setattr(settings, "SMTP_PASSWORD", None)
  monkeypatch.setattr(settings, "SMTP_USE_SSL", use_ssl)
  monkeypatch.setattr(settings, "SMTP_USE_STARTTLS", not use_ssl)
  monkeypatch.setattr(
    email_service.smtplib,
    "SMTP_SSL" if use_ssl else "SMTP",
    lambda *_args, **_kwargs: smtp_client,
  )

  with pytest.raises(EmailDeliveryError):
    email_service.send_email_sync(
      "person@example.com",
      "Subject",
      "Message",
    )


def test_send_email_accepts_smtp_delivery(monkeypatch):
  smtp_client = FakeSMTP({})

  monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
  monkeypatch.setattr(settings, "SMTP_FROM", "noreply@example.com")
  monkeypatch.setattr(settings, "SMTP_USER", None)
  monkeypatch.setattr(settings, "SMTP_PASSWORD", None)
  monkeypatch.setattr(settings, "SMTP_USE_SSL", False)
  monkeypatch.setattr(settings, "SMTP_USE_STARTTLS", True)
  monkeypatch.setattr(
    email_service.smtplib,
    "SMTP",
    lambda *_args, **_kwargs: smtp_client,
  )

  email_service.send_email_sync(
    "person@example.com",
    "Subject",
    "Message",
  )
