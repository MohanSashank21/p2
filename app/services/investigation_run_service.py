import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.incident import IncidentEvidence
from app.db.investigation_run import InvestigationRun
from app.db.user import User
from app.schemas.investigation_schema import (
  CombinedIncidentInvestigationRequest,
  CombinedIncidentInvestigationResponse,
  IntegrationInvestigationResult,
)
from app.schemas.incident_schema import IncidentEvidenceResponse

RUN_TIMEOUT_SECONDS = 300
STALE_RUN_TIMEOUT_SECONDS = RUN_TIMEOUT_SECONDS + 60


class IdempotencyKeyConflictError(Exception):
  pass


def _request_data(
  request: CombinedIncidentInvestigationRequest,
) -> dict:
  return request.model_dump(mode="json", exclude_none=True)


def _request_hash(request_data: dict) -> str:
  serialized = json.dumps(
    request_data,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
  )
  return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


async def fail_stale_investigation_runs(
  session: AsyncSession,
  incident_id: uuid.UUID,
) -> None:
  now = datetime.now(UTC)
  result = await session.execute(
    update(InvestigationRun)
    .where(
      InvestigationRun.incident_id == incident_id,
      InvestigationRun.status == "running",
      InvestigationRun.started_at
      < now - timedelta(seconds=STALE_RUN_TIMEOUT_SECONDS),
    )
    .values(
      status="failed",
      failure_code="execution_interrupted",
      failure_detail=(
        "The run exceeded its execution deadline or its process stopped "
        "before finalizing results."
      ),
      completed_at=now,
    ),
  )
  if result.rowcount:
    await session.commit()


async def reserve_investigation_run(
  session: AsyncSession,
  project_id: uuid.UUID,
  incident_id: uuid.UUID,
  user: User,
  request: CombinedIncidentInvestigationRequest,
  idempotency_key: str | None,
) -> tuple[InvestigationRun, bool]:
  await fail_stale_investigation_runs(session, incident_id)
  request_data = _request_data(request)
  request_hash = _request_hash(request_data)
  if idempotency_key is not None:
    existing = await session.scalar(
      select(InvestigationRun).where(
        InvestigationRun.project_id == project_id,
        InvestigationRun.incident_id == incident_id,
        InvestigationRun.requested_by_user_id == user.id,
        InvestigationRun.idempotency_key == idempotency_key,
      ),
    )
    if existing is not None:
      if existing.request_hash != request_hash:
        raise IdempotencyKeyConflictError
      return existing, False

  run = InvestigationRun(
    project_id=project_id,
    incident_id=incident_id,
    requested_by_user_id=user.id,
    idempotency_key=idempotency_key,
    request_hash=request_hash,
    requested_integrations=sorted(request_data),
    request_criteria=request_data,
    status="running",
    attempt_count=1,
  )
  session.add(run)
  try:
    await session.commit()
  except IntegrityError:
    await session.rollback()
    if idempotency_key is None:
      raise
    existing = await session.scalar(
      select(InvestigationRun).where(
        InvestigationRun.project_id == project_id,
        InvestigationRun.incident_id == incident_id,
        InvestigationRun.requested_by_user_id == user.id,
        InvestigationRun.idempotency_key == idempotency_key,
      ),
    )
    if existing is None:
      raise
    if existing.request_hash != request_hash:
      raise IdempotencyKeyConflictError
    return existing, False
  await session.refresh(run)
  return run, True


async def complete_investigation_run(
  session: AsyncSession,
  run_id: uuid.UUID,
  aggregate_status: str,
  integrations: dict[str, IntegrationInvestigationResult],
  evidence_ids: list[uuid.UUID],
) -> InvestigationRun:
  run = await session.get(InvestigationRun, run_id)
  if run is None:
    raise RuntimeError("Investigation run disappeared before completion")
  run.aggregate_status = aggregate_status
  run.integration_results = {
    name: result.model_dump(mode="json")
    for name, result in integrations.items()
  }
  run.evidence_ids = [str(identifier) for identifier in evidence_ids]
  run.status = {
    "success": "succeeded",
    "partial": "partial",
    "unavailable": "failed",
  }[aggregate_status]
  run.completed_at = datetime.now(UTC)
  await session.commit()
  await session.refresh(run)
  return run


async def fail_investigation_run(
  session: AsyncSession,
  run_id: uuid.UUID,
  failure_code: str,
  failure_detail: str,
  status: str = "failed",
) -> InvestigationRun:
  run = await session.get(InvestigationRun, run_id)
  if run is None:
    raise RuntimeError("Investigation run disappeared before failure was recorded")
  run.status = status
  run.failure_code = failure_code[:64]
  run.failure_detail = failure_detail
  run.completed_at = datetime.now(UTC)
  await session.commit()
  await session.refresh(run)
  return run


async def list_investigation_runs(
  session: AsyncSession,
  incident_id: uuid.UUID,
  limit: int,
  offset: int,
) -> list[InvestigationRun]:
  await fail_stale_investigation_runs(session, incident_id)
  result = await session.scalars(
    select(InvestigationRun)
    .where(InvestigationRun.incident_id == incident_id)
    .order_by(
      InvestigationRun.started_at.desc(),
      InvestigationRun.id.desc(),
    )
    .limit(limit)
    .offset(offset),
  )
  return list(result)


async def get_investigation_run(
  session: AsyncSession,
  incident_id: uuid.UUID,
  run_id: uuid.UUID,
) -> InvestigationRun | None:
  await fail_stale_investigation_runs(session, incident_id)
  return await session.scalar(
    select(InvestigationRun).where(
      InvestigationRun.id == run_id,
      InvestigationRun.incident_id == incident_id,
    ),
  )


async def replay_investigation_response(
  session: AsyncSession,
  run: InvestigationRun,
) -> CombinedIncidentInvestigationResponse:
  if run.aggregate_status is None or run.integration_results is None:
    raise RuntimeError("Investigation run has no completed response")
  identifiers = [uuid.UUID(value) for value in run.evidence_ids]
  evidence_by_id: dict[uuid.UUID, IncidentEvidence] = {}
  if identifiers:
    evidence = await session.scalars(
      select(IncidentEvidence).where(
        IncidentEvidence.incident_id == run.incident_id,
        IncidentEvidence.id.in_(identifiers),
      ),
    )
    evidence_by_id = {item.id: item for item in evidence}
  return CombinedIncidentInvestigationResponse(
    status=run.aggregate_status,
    incident_id=run.incident_id,
    integrations={
      name: IntegrationInvestigationResult.model_validate(result)
      for name, result in run.integration_results.items()
    },
    evidence=[
      IncidentEvidenceResponse(
        id=evidence_by_id[identifier].id,
        incident_id=evidence_by_id[identifier].incident_id,
        source_event_id=evidence_by_id[identifier].source_event_id,
        evidence_type=evidence_by_id[identifier].evidence_type,
        incident_source_id=evidence_by_id[identifier].incident_source_id,
        original_content=evidence_by_id[identifier].original_content,
        normalized_content=evidence_by_id[identifier].normalized_content,
        created_at=evidence_by_id[identifier].created_at,
      )
      for identifier in identifiers
      if identifier in evidence_by_id
    ],
  )
