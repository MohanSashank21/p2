from __future__ import annotations

import base64
import binascii
import io
import time
import zlib
import zipfile
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt

from app.core.config import settings
from app.core.exceptions import GitHubIntegrationError

_API_VERSION = "2022-11-28"
_MAX_FILE_BYTES = 1_048_576
_MAX_LOG_ARCHIVE_BYTES = 10 * 1_048_576
_MAX_LOG_TEXT_CHARS = 250_000
_MAX_LOG_FILES = 100
_MAX_LOG_FILE_NAME_CHARS = 256


def _github_configuration() -> tuple[str, str]:
  if (
    settings.GITHUB_APP_ID is None
    or settings.GITHUB_APP_PRIVATE_KEY is None
    or not settings.GITHUB_APP_ID.strip()
    or not settings.GITHUB_APP_PRIVATE_KEY.get_secret_value().strip()
  ):
    raise GitHubIntegrationError(
      503,
      "GitHub App integration is not configured",
    )
  return (
    settings.GITHUB_APP_ID,
    settings.GITHUB_APP_PRIVATE_KEY.get_secret_value().replace("\\n", "\n"),
  )


def create_app_jwt() -> str:
  app_id, private_key = _github_configuration()
  now = int(time.time())
  try:
    return jwt.encode(
      {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id},
      private_key,
      algorithm="RS256",
    )
  except (ValueError, TypeError) as error:
    raise GitHubIntegrationError(
      503,
      "GitHub App private key could not be used",
    ) from error


def _error_from_response(response: httpx.Response) -> GitHubIntegrationError:
  if response.status_code == 404:
    return GitHubIntegrationError(404, "GitHub resource not found")
  if response.status_code in (401, 403):
    if response.status_code == 403 and (
      response.headers.get("X-RateLimit-Remaining") == "0"
      or "Retry-After" in response.headers
    ):
      return GitHubIntegrationError(429, "GitHub API rate limit exceeded")
    return GitHubIntegrationError(
      403,
      "GitHub App does not have permission to access this resource",
    )
  if response.status_code == 429:
    return GitHubIntegrationError(429, "GitHub API rate limit exceeded")
  if response.status_code >= 500:
    return GitHubIntegrationError(502, "GitHub API is temporarily unavailable")
  return GitHubIntegrationError(502, "GitHub API request failed")


def _logs_from_archive(archive: bytes) -> dict[str, Any]:
  try:
    with zipfile.ZipFile(io.BytesIO(archive)) as archive_file:
      log_parts: list[str] = []
      remaining_chars = _MAX_LOG_TEXT_CHARS
      truncated = False
      for item in archive_file.infolist():
        if item.is_dir() or not item.filename.lower().endswith(".txt"):
          continue
        if len(log_parts) >= _MAX_LOG_FILES:
          truncated = True
          break
        if item.file_size > remaining_chars:
          truncated = True
        with archive_file.open(item) as log_file:
          content = log_file.read(remaining_chars + 1).decode(
            "utf-8",
            errors="replace",
          )
        if len(content) > remaining_chars:
          content = content[:remaining_chars]
          truncated = True
        log_parts.append(
          f"===== {item.filename[:_MAX_LOG_FILE_NAME_CHARS]} =====\n{content}",
        )
        remaining_chars -= len(content)
        if remaining_chars <= 0:
          truncated = True
          break
      return {
        "available": True,
        "logs": "\n\n".join(log_parts),
        "truncated": truncated,
      }
  except (OSError, zipfile.BadZipFile, RuntimeError, zlib.error) as error:
    raise GitHubIntegrationError(
      502,
      "GitHub returned an invalid workflow log archive",
    ) from error


class GitHubClient:
  def __init__(
    self,
    token: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
  ):
    self._token = token
    self._transport = transport

  async def request(
    self,
    method: str,
    path: str,
    *,
    params: Mapping[str, str | int | bool] | None = None,
    json_body: dict[str, Any] | None = None,
  ) -> httpx.Response:
    headers = {
      "Accept": "application/vnd.github+json",
      "Authorization": f"Bearer {self._token}",
      "X-GitHub-Api-Version": _API_VERSION,
    }
    try:
      async with httpx.AsyncClient(
        base_url=settings.GITHUB_API_URL.rstrip("/"),
        timeout=settings.GITHUB_API_TIMEOUT_SECONDS,
        transport=self._transport,
        follow_redirects=False,
      ) as client:
        response = await client.request(
          method,
          path,
          params=params,
          json=json_body,
          headers=headers,
        )
    except httpx.TimeoutException as error:
      raise GitHubIntegrationError(504, "GitHub API request timed out") from error
    except httpx.RequestError as error:
      raise GitHubIntegrationError(
        502,
        "Could not connect to the GitHub API",
      ) from error

    if response.status_code >= 400:
      raise _error_from_response(response)
    return response

  async def json(
    self,
    method: str,
    path: str,
    *,
    params: Mapping[str, str | int | bool] | None = None,
    json_body: dict[str, Any] | None = None,
  ) -> dict[str, Any]:
    response = await self.request(
      method,
      path,
      params=params,
      json_body=json_body,
    )
    try:
      result = response.json()
    except ValueError as error:
      raise GitHubIntegrationError(
        502,
        "GitHub API returned an invalid response",
      ) from error
    if not isinstance(result, dict):
      raise GitHubIntegrationError(
        502,
        "GitHub API returned an unexpected response",
      )
    return result

  async def items(
    self,
    path: str,
    *,
    page: int,
    per_page: int,
    params: Mapping[str, str | int | bool] | None = None,
  ) -> list[dict[str, Any]]:
    query: dict[str, str | int | bool] = {
      "page": page,
      "per_page": per_page,
    }
    if params:
      query.update(params)
    response = await self.request("GET", path, params=query)
    try:
      result = response.json()
    except ValueError as error:
      raise GitHubIntegrationError(
        502,
        "GitHub API returned an invalid response",
      ) from error
    if isinstance(result, dict):
      result = next(
        (
          result[key]
          for key in ("items", "repositories", "workflows", "workflow_runs", "jobs")
          if key in result
        ),
        None,
      )
    if not isinstance(result, list) or not all(
      isinstance(item, dict) for item in result
    ):
      raise GitHubIntegrationError(
        502,
        "GitHub API returned an unexpected list response",
      )
    return result


async def create_installation_token(installation_id: int) -> str:
  app_jwt = create_app_jwt()
  try:
    async with httpx.AsyncClient(
      base_url=settings.GITHUB_API_URL.rstrip("/"),
      timeout=settings.GITHUB_API_TIMEOUT_SECONDS,
    ) as client:
      response = await client.post(
        f"/app/installations/{installation_id}/access_tokens",
        headers={
          "Accept": "application/vnd.github+json",
          "Authorization": f"Bearer {app_jwt}",
          "X-GitHub-Api-Version": _API_VERSION,
        },
        json={
          "permissions": {
            "actions": "read",
            "contents": "read",
            "metadata": "read",
          },
        },
      )
  except httpx.TimeoutException as error:
    raise GitHubIntegrationError(504, "GitHub API request timed out") from error
  except httpx.RequestError as error:
    raise GitHubIntegrationError(
      502,
      "Could not connect to the GitHub API",
    ) from error

  if response.status_code >= 400:
    raise _error_from_response(response)
  try:
    body = response.json()
    token = body.get("token") if isinstance(body, dict) else None
  except ValueError as error:
    raise GitHubIntegrationError(
      502,
      "GitHub API returned an invalid token response",
    ) from error
  if not isinstance(token, str) or not token:
    raise GitHubIntegrationError(
      502,
      "GitHub API did not return an installation token",
    )
  return token


async def get_installation_details(installation_id: int) -> dict[str, Any]:
  client = GitHubClient(create_app_jwt())
  return await client.json("GET", f"/app/installations/{installation_id}")


async def list_installation_repositories(
  token: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    "/installation/repositories",
    page=page,
    per_page=per_page,
  )


async def get_repository_by_id(token: str, repository_id: int) -> dict[str, Any]:
  return await GitHubClient(token).json("GET", f"/repositories/{repository_id}")


async def get_repository(token: str, full_name: str) -> dict[str, Any]:
  return await GitHubClient(token).json("GET", f"/repos/{full_name}")


async def get_branches(
  token: str,
  full_name: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/branches",
    page=page,
    per_page=per_page,
  )


async def get_tree(
  token: str,
  full_name: str,
  ref: str,
) -> dict[str, Any]:
  return await GitHubClient(token).json(
    "GET",
    f"/repos/{full_name}/git/trees/{ref}",
    params={"recursive": "1"},
  )


async def get_file(
  token: str,
  full_name: str,
  path: str,
  ref: str | None,
) -> dict[str, Any]:
  params = {"ref": ref} if ref else None
  data = await GitHubClient(token).json(
    "GET",
    f"/repos/{full_name}/contents/{path}",
    params=params,
  )
  if data.get("type") != "file" or data.get("encoding") != "base64":
    raise GitHubIntegrationError(415, "Requested GitHub path is not a file")
  file_size = data.get("size")
  if isinstance(file_size, int) and file_size > _MAX_FILE_BYTES:
    raise GitHubIntegrationError(413, "GitHub file exceeds the 1 MiB limit")
  encoded = data.get("content")
  if not isinstance(encoded, str):
    raise GitHubIntegrationError(502, "GitHub did not return file content")
  try:
    content = base64.b64decode(encoded, validate=False)
  except (ValueError, binascii.Error) as error:
    raise GitHubIntegrationError(502, "GitHub returned invalid file content") from error
  if len(content) > _MAX_FILE_BYTES:
    raise GitHubIntegrationError(413, "GitHub file exceeds the 1 MiB limit")
  try:
    text = content.decode("utf-8")
  except UnicodeDecodeError as error:
    raise GitHubIntegrationError(415, "Binary files are not supported") from error
  return {
    "path": data.get("path"),
    "sha": data.get("sha"),
    "size": len(content),
    "content": text,
    "html_url": data.get("html_url"),
  }


async def get_commits(
  token: str,
  full_name: str,
  *,
  page: int,
  per_page: int,
  ref: str | None,
) -> list[dict[str, Any]]:
  params = {"sha": ref} if ref else None
  return await GitHubClient(token).items(
    f"/repos/{full_name}/commits",
    page=page,
    per_page=per_page,
    params=params,
  )


async def get_commit(token: str, full_name: str, sha: str) -> dict[str, Any]:
  return await GitHubClient(token).json(
    "GET",
    f"/repos/{full_name}/commits/{sha}",
  )


async def get_commit_pull_requests(
  token: str,
  full_name: str,
  sha: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/commits/{sha}/pulls",
    page=page,
    per_page=per_page,
  )


async def get_pull_request(
  token: str,
  full_name: str,
  number: int,
) -> dict[str, Any]:
  return await GitHubClient(token).json(
    "GET",
    f"/repos/{full_name}/pulls/{number}",
  )


async def get_pull_request_files(
  token: str,
  full_name: str,
  number: int,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/pulls/{number}/files",
    page=page,
    per_page=per_page,
  )


async def get_workflows(
  token: str,
  full_name: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/actions/workflows",
    page=page,
    per_page=per_page,
  )


async def get_workflow_runs(
  token: str,
  full_name: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/actions/runs",
    page=page,
    per_page=per_page,
  )


async def get_workflow_jobs(
  token: str,
  full_name: str,
  run_id: int,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/actions/runs/{run_id}/jobs",
    page=page,
    per_page=per_page,
  )


async def get_workflow_run(
  token: str,
  full_name: str,
  run_id: int,
) -> dict[str, Any]:
  return await GitHubClient(token).json(
    "GET",
    f"/repos/{full_name}/actions/runs/{run_id}",
  )


async def get_workflow_run_logs(
  token: str,
  full_name: str,
  run_id: int,
) -> dict[str, Any]:
  try:
    response = await GitHubClient(token).request(
      "GET",
      f"/repos/{full_name}/actions/runs/{run_id}/logs",
    )
  except GitHubIntegrationError as error:
    if error.status_code == 404:
      return {"available": False, "logs": None, "truncated": False}
    raise
  if response.status_code != 302:
    raise GitHubIntegrationError(
      502,
      "GitHub did not provide a workflow log download",
    )

  download_url = response.headers.get("Location")
  parsed_url = urlsplit(download_url or "")
  if (
    parsed_url.scheme != "https"
    or not parsed_url.hostname
    or parsed_url.username is not None
    or parsed_url.password is not None
  ):
    raise GitHubIntegrationError(
      502,
      "GitHub returned an invalid workflow log URL",
    )

  archive = bytearray()
  try:
    async with httpx.AsyncClient(
      timeout=settings.GITHUB_API_TIMEOUT_SECONDS,
      follow_redirects=False,
    ) as client:
      async with client.stream("GET", download_url) as download:
        if download.status_code != 200:
          raise GitHubIntegrationError(
            502,
            "Could not download workflow logs from GitHub",
          )
        content_length = download.headers.get("Content-Length")
        if content_length:
          try:
            declared_length = int(content_length)
          except ValueError as error:
            raise GitHubIntegrationError(
              502,
              "GitHub returned an invalid workflow log size",
            ) from error
          if declared_length > _MAX_LOG_ARCHIVE_BYTES:
            raise GitHubIntegrationError(
              413,
              "GitHub workflow log archive exceeds the download limit",
            )
        async for chunk in download.aiter_bytes():
          if len(archive) + len(chunk) > _MAX_LOG_ARCHIVE_BYTES:
            raise GitHubIntegrationError(
              413,
              "GitHub workflow log archive exceeds the download limit",
            )
          archive.extend(chunk)
  except httpx.TimeoutException as error:
    raise GitHubIntegrationError(504, "Workflow log download timed out") from error
  except httpx.RequestError as error:
    raise GitHubIntegrationError(
      502,
      "Could not download workflow logs from GitHub",
    ) from error

  return _logs_from_archive(bytes(archive))


async def get_deployments(
  token: str,
  full_name: str,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/deployments",
    page=page,
    per_page=per_page,
  )


async def get_deployment_statuses(
  token: str,
  full_name: str,
  deployment_id: int,
  *,
  page: int,
  per_page: int,
) -> list[dict[str, Any]]:
  return await GitHubClient(token).items(
    f"/repos/{full_name}/deployments/{deployment_id}/statuses",
    page=page,
    per_page=per_page,
  )
