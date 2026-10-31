import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr

from app.core.config import settings
from app.core.exceptions import PrometheusIntegrationError


@dataclass(frozen=True)
class PrometheusConnection:
  base_url: str
  auth_type: str
  auth_ciphertext: str | None


def _fernet() -> Fernet:
  configured = settings.PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY
  if configured is None:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY is not configured",
    )
  try:
    return Fernet(configured.get_secret_value().encode("ascii"))
  except (ValueError, UnicodeEncodeError) as error:
    raise PrometheusIntegrationError(
      503,
      "PROMETHEUS_CREDENTIAL_ENCRYPTION_KEY is invalid",
    ) from error


def encrypt_prometheus_auth(
  auth_type: str,
  username: str | None,
  password: SecretStr | None,
  bearer_token: SecretStr | None,
) -> str | None:
  if auth_type == "none":
    return None
  fernet = _fernet()
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


def _request_auth(connection: PrometheusConnection):
  if connection.auth_type == "none":
    if connection.auth_ciphertext is not None:
      raise PrometheusIntegrationError(
        503,
        "Stored Prometheus authentication configuration is invalid",
      )
    return {}, None
  if connection.auth_type not in {"bearer", "basic"}:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is invalid",
    )
  if connection.auth_ciphertext is None:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is missing",
    )
  try:
    credentials = json.loads(
      _fernet().decrypt(connection.auth_ciphertext.encode("ascii")),
    )
  except (
    InvalidToken,
    UnicodeDecodeError,
    UnicodeEncodeError,
    ValueError,
    json.JSONDecodeError,
  ) as error:
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus credentials cannot be decrypted; check the encryption key",
    ) from error
  if not isinstance(credentials, dict):
    raise PrometheusIntegrationError(
      503,
      "Stored Prometheus authentication configuration is invalid",
    )
  if (
    connection.auth_type == "bearer"
    and isinstance(credentials.get("token"), str)
    and credentials["token"]
  ):
    return {"Authorization": f"Bearer {credentials['token']}"}, None
  if (
    connection.auth_type == "basic"
    and isinstance(credentials.get("username"), str)
    and isinstance(credentials.get("password"), str)
  ):
    return {}, httpx.BasicAuth(
      credentials["username"],
      credentials["password"],
    )
  raise PrometheusIntegrationError(
    503,
    "Stored Prometheus authentication configuration is invalid",
  )


async def validate_prometheus_connection(
  connection: PrometheusConnection,
) -> None:
  validate_prometheus_url(connection.base_url)
  headers, auth = _request_auth(connection)
  timeout = httpx.Timeout(settings.PROMETHEUS_QUERY_TIMEOUT_SECONDS)
  try:
    async with httpx.AsyncClient(
      timeout=timeout,
      follow_redirects=False,
      trust_env=False,
    ) as client:
      async with client.stream(
        "GET",
        f"{connection.base_url.rstrip('/')}/-/ready",
        headers={"Accept": "text/plain", **headers},
        auth=auth,
      ) as response:
        status_code = response.status_code
  except httpx.TimeoutException as error:
    raise PrometheusIntegrationError(504, "Prometheus connection check timed out") from error
  except httpx.RequestError as error:
    raise PrometheusIntegrationError(
      502,
      "Could not connect to the configured Prometheus instance",
    ) from error
  if status_code in {401, 403}:
    raise PrometheusIntegrationError(
      502,
      "Prometheus rejected the configured credentials",
    )
  if status_code >= 500:
    raise PrometheusIntegrationError(503, "The Prometheus service is unavailable")
  if status_code < 200 or status_code >= 300:
    raise PrometheusIntegrationError(
      502,
      "Prometheus readiness endpoint returned an unexpected response",
    )


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
