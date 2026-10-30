import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import settings
from app.core.exceptions import EmailDeliveryError

def send_message(server: smtplib.SMTP, message: EmailMessage) -> None:
  refused_recipients = server.send_message(message)
  if refused_recipients:
    raise EmailDeliveryError("Could not deliver email")

def send_email_sync(recipient: str, subject: str, body: str) -> None:
  if not settings.SMTP_HOST or not settings.SMTP_FROM:
    raise EmailDeliveryError("Email delivery is not configured")
  if not settings.SMTP_USE_SSL and not settings.SMTP_USE_STARTTLS:
    raise EmailDeliveryError("SMTP must use TLS")
  if bool(settings.SMTP_USER) != bool(settings.SMTP_PASSWORD):
    raise EmailDeliveryError("SMTP username and password must be configured together")

  message = EmailMessage()
  message["From"] = settings.SMTP_FROM
  message["To"] = recipient
  message["Subject"] = subject
  message.set_content(body)

  try:
    if settings.SMTP_USE_SSL:
      with smtplib.SMTP_SSL(
        settings.SMTP_HOST,
        settings.SMTP_PORT,
        timeout=settings.SMTP_TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
      ) as server:
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
          server.login(
            settings.SMTP_USER,
            settings.SMTP_PASSWORD.get_secret_value(),
          )
        send_message(server, message)
      return

    with smtplib.SMTP(
      settings.SMTP_HOST,
      settings.SMTP_PORT,
      timeout=settings.SMTP_TIMEOUT_SECONDS,
    ) as server:
      server.ehlo()
      server.starttls(context=ssl.create_default_context())
      server.ehlo()
      if settings.SMTP_USER and settings.SMTP_PASSWORD:
        server.login(
          settings.SMTP_USER,
          settings.SMTP_PASSWORD.get_secret_value(),
        )
      send_message(server, message)
  except (OSError, smtplib.SMTPException) as error:
    raise EmailDeliveryError("Could not deliver email") from error

async def send_email(recipient: str, subject: str, body: str) -> None:
  await asyncio.to_thread(send_email_sync, recipient, subject, body)

async def send_otp_email(recipient: str, code: str) -> None:
  await send_email(
    recipient,
    "Your OpsPilot verification code",
    (
      f"Your verification code is {code}.\n\n"
      f"It expires in {settings.OTP_EXPIRE_MINUTES} minutes. "
      "If you did not request this code, you can ignore this email."
    ),
  )
