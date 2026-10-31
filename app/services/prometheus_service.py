import ipaddress
import json
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.core.config import settings
from app.core.exceptions import PrometheusIntegrationError


def encrypt_prometheus_auth(
  auth_type: str,
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> str | None:
  if auth_type == "none":
    return None
  configured = settings.PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY must be configured for "
      "authenticated Prometheus sources",
    )
  try:
    fernet = Fernet(configured.get_secret_value().encode("ascii"))
  except (ValueError, UnicodeEncodeError) as error:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY is invalid",
    ) from error
  if auth_type == "bearer" and bearer_token is not None:
    value = {"token": bearer_token.get_secret_value()}
  elif auth_type == "basic" and username is not None and password is not None:
    value = {"username": username, "password": password.get_secret_value()}
  else:
    raise PrometheusIntegrationError(
      422,
      "Invalid Prometheus authentication configuration",
    )
  return fernet.encrypt(
    json.dumps(value, separators=(",", ":")).encode("utf-8"),
  ).decode("ascii")


def validate_prometheus_url(base_url: str) -> None:
  parsed = urlsplit(base_url)
  if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or "\\" in parsed.path
    or any(part in {".", ".."} for part in parsed.path.split("/"))
  ):
    raise PrometheusIntegrationError(422, "Invalid Prometheus base URL")
  try:
    port = parsed.port
  except ValueError as error:
    raise PrometheusIntegrationError(422, "Invalid Prometheus base URL port") from error
  if port == (443 if parsed.scheme == "https" else 80):
    port = None
  allowed_hosts = {
    host.strip().rstrip(".").lower()
    for host in settings.PROMETHEUS_ALLOWED_HOSTS.split(",")
    if host.strip()
  }
  if not allowed_hosts:
    raise PrometheusIntegrationError(
      503,
      "Prometheus connections are disabled until "
      "PROMETHEUS_ALLOWED_HOSTS is configured",
    )
  hostname = parsed.hostname.rstrip(".").lower()
  if port is not None:
    target = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
  else:
    target = hostname
  if target not in allowed_hosts:
    raise PrometheusIntegrationError(
      422,
      "Prometheus host is not included in the server's "
      "PROMETHEUS_ALLOWED_HOSTS",
    )
  try:
    address = ipaddress.ip_address(hostname)
  except ValueError:
    return
  if address.is_unspecified or address.is_multicast:
    raise PrometheusIntegrationError(
      422,
      "Prometheus URL cannot target this IP address",
    )
