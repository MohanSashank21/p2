from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.incident import Incident, IncidentEvidence
from app.db.investigation_run import InvestigationRun
from app.schemas.incident_context_schema import IncidentContextResponse
from app.schemas.investigation_synthesis_schema import InvestigationSynthesisResult
from app.services.gemini_synthesis_service import (
  SYNTHESIS_PROMPT_VERSION,
  SYNTHESIS_SCHEMA_VERSION,
  serialize_synthesis_context,
)
from app.services.incident_context_service import build_incident_context

SYNTHESIS_CONTEXT_STALE_SECONDS = 180

_SENSITIVE_KEY_PARTS = (
  "authorization",
  "cookie",
  "password",
  "passwd",
  "secret",
  "token",
  "api_key",
  "apikey",
  "credential",
  "private_key",
)
_SECRET_PATTERNS = (
  re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
  re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]+=*"),
  re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
  re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
  re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
  re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
  re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token)\s*[:=]\s*(['\"]?)[^\s,;}'\"]+",
  ),
  re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
  re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
  ),
)


class InvestigationSynthesisContextError(ValueError):
  def __init__(
    self,
    code: str,
    message: str,
    status_code: int,
  ) -> None:
    self.code = code
    self.message = message
    self.status_code = status_code
    super().__init__(message)


def _redact_text(value: str) -> str:
  redacted = value
  for pattern in _SECRET_PATTERNS:
    redacted = pattern.sub("[REDACTED]", redacted)
  return redacted


def _sanitize_evidence(value: Any, key: str | None = None) -> Any:
  if key is not None:
    normalized_key = key.lower().replace("-", "_")
    if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
      return "[REDACTED]"
  if isinstance(value, dict):
    return {
      str(item_key): _sanitize_evidence(item_value, str(item_key))
      for item_key, item_value in value.items()
    }
  if isinstance(value, list):
    return [_sanitize_evidence(item) for item in value]
  if isinstance(value, str):
    return _redact_text(value)
  if value is None or isinstance(value, (bool, int, float)):
    return value
  return _redact_text(str(value))


def _m4_context_for_evidence(
  context: IncidentContextResponse,
  evidence_ids: set[uuid.UUID],
) -> dict[str, Any]:
  return {
    "generated_at": context.generated_at.isoformat(),
    "timeline": [
      item.model_dump(mode="json")
      for item in context.timeline
      if (
        item.evidence_id in evidence_ids
        or (
          item.evidence_id is None
          and item.event_type == "incident_created"
        )
      )
    ],
    "correlations": [
      item.model_dump(mode="json")
      for item in context.correlations
      if (
        item.left_evidence_id in evidence_ids
        and item.right_evidence_id in evidence_ids
      )
    ],
    "projection_limited": (
      context.evidence_truncated
      or context.timeline_truncated
      or context.correlations_truncated
    ),
  }


async def build_run_synthesis_input(
  session: AsyncSession,
  incident: Incident,
  run: InvestigationRun,
) -> tuple[str, set[str]]:
  if run.incident_id != incident.id or run.project_id != incident.project_id:
    raise InvestigationSynthesisContextError(
      "run_scope_mismatch",
      "Investigation run does not belong to this incident and project.",
      404,
    )
  if not run.evidence_ids:
    raise InvestigationSynthesisContextError(
      "no_run_evidence",
      "This investigation run has no persisted evidence to synthesize.",
      409,
    )
  try:
    requested_ids = [uuid.UUID(value) for value in run.evidence_ids]
  except (TypeError, ValueError, AttributeError) as error:
    raise InvestigationSynthesisContextError(
      "invalid_run_evidence",
      "The investigation run contains invalid evidence references.",
      409,
    ) from error
  evidence_ids = set(requested_ids)
  if len(evidence_ids) != len(requested_ids):
    raise InvestigationSynthesisContextError(
      "duplicate_run_evidence",
      "The investigation run contains duplicate evidence references.",
      409,
    )

  evidence_result = await session.scalars(
    select(IncidentEvidence)
    .where(
      IncidentEvidence.incident_id == incident.id,
      IncidentEvidence.id.in_(evidence_ids),
    )
    .order_by(IncidentEvidence.created_at, IncidentEvidence.id),
  )
  evidence_rows = list(evidence_result)
  if {item.id for item in evidence_rows} != evidence_ids:
    raise InvestigationSynthesisContextError(
      "evidence_scope_mismatch",
      "Some run evidence is missing or does not belong to this incident.",
      409,
    )

  context = await build_incident_context(session, incident)
  context_evidence_ids = {item.id for item in context.evidence}
  if not evidence_ids.issubset(context_evidence_ids):
    raise InvestigationSynthesisContextError(
      "m4_context_truncated",
      "The complete run evidence is not available in the bounded M4 context.",
      413,
    )

  visible_data = {
    "incident": {
      "incident_type": incident.incident_type,
      "title": incident.title,
      "description": incident.description,
      "severity": incident.severity,
      "status": incident.status,
      "created_at": incident.created_at.isoformat(),
    },
    "run": {
      "status": run.status,
      "aggregate_status": run.aggregate_status,
      "requested_integrations": run.requested_integrations,
    },
    "m4_context": _m4_context_for_evidence(context, evidence_ids),
    "evidence": [
      {
        "id": str(item.id),
        "type": item.evidence_type,
        "persisted_at": item.created_at.isoformat(),
        "normalized_content": _sanitize_evidence(item.normalized_content),
      }
      for item in evidence_rows
    ],
  }
  try:
    serialized = serialize_synthesis_context(
      _sanitize_evidence(visible_data),
    )
  except ValueError as error:
    raise InvestigationSynthesisContextError(
      "context_too_large",
      "Selected incident evidence exceeds the configured model input limit; "
      "collect a narrower evidence set before synthesis.",
      413,
    ) from error
  return serialized, {str(item) for item in evidence_ids}


async def claim_run_synthesis(
  session: AsyncSession,
  run_id: uuid.UUID,
  max_attempts: int,
) -> bool:
  now = datetime.now(UTC)
  stale_before = now - timedelta(seconds=SYNTHESIS_CONTEXT_STALE_SECONDS)
  result = await session.execute(
    update(InvestigationRun)
    .where(
      InvestigationRun.id == run_id,
      InvestigationRun.status.in_(("succeeded", "partial")),
      InvestigationRun.synthesis_attempt_count < max_attempts,
      or_(
        InvestigationRun.synthesis_status.in_(("not_started", "failed")),
        and_(
          InvestigationRun.synthesis_status == "running",
          InvestigationRun.synthesis_started_at < stale_before,
        ),
      ),
    )
    .values(
      synthesis_status="running",
      synthesis_attempt_count=InvestigationRun.synthesis_attempt_count + 1,
      synthesis_started_at=now,
      synthesis_completed_at=None,
      synthesis_failure_code=None,
    ),
  )
  await session.commit()
  return result.rowcount == 1


async def complete_run_synthesis(
  session: AsyncSession,
  run_id: uuid.UUID,
  result: InvestigationSynthesisResult,
) -> InvestigationRun:
  run = await session.get(InvestigationRun, run_id)
  if run is None:
    raise RuntimeError("Investigation run disappeared before synthesis completion")
  run.synthesis_status = "succeeded"
  run.synthesis_report = result.report.model_dump(mode="json")
  run.synthesis_model = result.model
  run.synthesis_prompt_version = SYNTHESIS_PROMPT_VERSION
  run.synthesis_schema_version = SYNTHESIS_SCHEMA_VERSION
  run.synthesis_input_tokens = result.input_tokens
  run.synthesis_output_tokens = result.output_tokens
  run.synthesis_provider_attempts = result.provider_attempts
  run.synthesis_failure_code = None
  run.synthesis_completed_at = datetime.now(UTC)
  await session.commit()
  await session.refresh(run)
  return run


async def fail_run_synthesis(
  session: AsyncSession,
  run_id: uuid.UUID,
  failure_code: str,
  provider_attempts: int | None = None,
) -> None:
  run = await session.get(InvestigationRun, run_id)
  if run is None:
    raise RuntimeError("Investigation run disappeared before synthesis failure was recorded")
  run.synthesis_status = "failed"
  run.synthesis_report = None
  run.synthesis_failure_code = failure_code[:64]
  run.synthesis_provider_attempts = provider_attempts
  run.synthesis_completed_at = datetime.now(UTC)
  await session.commit()


def synthesis_run_response(run: InvestigationRun) -> dict[str, Any]:
  return {
    "run_id": run.id,
    "incident_id": run.incident_id,
    "status": run.synthesis_status,
    "report": run.synthesis_report,
    "model": run.synthesis_model,
    "prompt_version": run.synthesis_prompt_version,
    "schema_version": run.synthesis_schema_version,
    "input_tokens": run.synthesis_input_tokens,
    "output_tokens": run.synthesis_output_tokens,
    "provider_attempts": run.synthesis_provider_attempts,
    "attempt_count": run.synthesis_attempt_count,
    "failure_code": run.synthesis_failure_code,
    "completed_at": run.synthesis_completed_at,
  }
