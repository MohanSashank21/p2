import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import SourceConfigurationError
from app.db.incident import Incident, IncidentEvidence
from app.db.incident_source import IncidentSource, ProviderAlert
from app.schemas.source_schema import (
  AlertmanagerAlertPayload,
  AlertmanagerAlertResult,
  AlertmanagerWebhookPayload,
)

_ZERO_TIMESTAMP_YEAR = 1
AlertProvider = Literal["alertmanager", "grafana"]


def _utc(value: datetime) -> datetime:
  if value.tzinfo is None:
    return value.replace(tzinfo=UTC)
  return value.astimezone(UTC)


def _severity(labels: dict[str, str]) -> Literal["low", "medium", "high", "critical"]:
  value = labels.get("severity", "").strip().lower()
  if value in {"critical", "fatal"}:
    return "critical"
  if value in {"high", "error", "major"}:
    return "high"
  if value in {"low", "info", "informational"}:
    return "low"
  return "medium"


def _title(alert: AlertmanagerAlertPayload, provider: AlertProvider) -> str:
  return (
    alert.labels.get("alertname", "").strip()
    or alert.annotations.get("summary", "").strip()
    or f"{provider.title()} alert"
  )[:255]


def _description(alert: AlertmanagerAlertPayload) -> str | None:
  return (
    alert.annotations.get("description", "").strip()
    or alert.annotations.get("summary", "").strip()
    or None
  )


def _resolved_at(alert: AlertmanagerAlertPayload, now: datetime) -> datetime:
  if alert.ends_at is not None and alert.ends_at.year != _ZERO_TIMESTAMP_YEAR:
    return _utc(alert.ends_at)
  return now


def _end_time(alert: AlertmanagerAlertPayload) -> datetime | None:
  if alert.ends_at is None or alert.ends_at.year == _ZERO_TIMESTAMP_YEAR:
    return None
  return _utc(alert.ends_at)


def _notification_content(
  payload: AlertmanagerWebhookPayload,
  original_payload: dict,
  alert_index: int,
  provider: AlertProvider,
) -> tuple[dict, dict]:
  raw_alerts = original_payload.get("alerts")
  if not isinstance(raw_alerts, list) or alert_index >= len(raw_alerts):
    raise ValueError("Provider payload is missing its original alert data")
  batch = {key: value for key, value in original_payload.items() if key != "alerts"}
  original = {"batch": batch, "alert": raw_alerts[alert_index]}
  normalized = {
    "fingerprint": payload.alerts[alert_index].fingerprint,
    "status": payload.alerts[alert_index].status,
    "alert_name": _title(payload.alerts[alert_index], provider),
    "severity": _severity(payload.alerts[alert_index].labels),
    "summary": payload.alerts[alert_index].annotations.get("summary"),
    "description": payload.alerts[alert_index].annotations.get("description"),
    "labels": payload.alerts[alert_index].labels,
    "annotations": payload.alerts[alert_index].annotations,
    "provider_metadata": payload.alerts[alert_index].model_extra or {},
  }
  return original, normalized


def _payload_hash(original: dict) -> str:
  serialized = json.dumps(
    original,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
  )
  return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


async def _record_evidence(
  session: AsyncSession,
  alert: ProviderAlert,
  original: dict,
  normalized: dict,
  provider: AlertProvider,
) -> None:
  digest = _payload_hash(original)
  existing_id = await session.scalar(
    select(IncidentEvidence.id).where(
      IncidentEvidence.alertmanager_alert_id == alert.id,
      IncidentEvidence.payload_hash == digest,
    ),
  )
  if existing_id is not None:
    return
  session.add(
    IncidentEvidence(
      incident_id=alert.incident_id,
      alertmanager_alert_id=alert.id,
      payload_hash=digest,
      evidence_type=f"{provider}_notification",
      original_content=original,
      normalized_content=normalized,
    ),
  )


async def _create_alert(
  session: AsyncSession,
  source: IncidentSource,
  incoming: AlertmanagerAlertPayload,
  original: dict,
  normalized: dict,
  now: datetime,
  provider: AlertProvider,
) -> ProviderAlert:
  title = _title(incoming, provider)
  description = _description(incoming)
  severity = _severity(incoming.labels)
  incident = Incident(
    project_id=source.project_id,
    environment_id=source.environment_id,
    source_type=provider,
    incident_type="monitoring_alert",
    title=title,
    description=description,
    severity=severity,
    status="open",
  )
  session.add(incident)
  await session.flush()

  starts_at = _utc(incoming.starts_at)
  alert = ProviderAlert(
    source_id=source.id,
    project_id=source.project_id,
    incident_id=incident.id,
    fingerprint=incoming.fingerprint,
    status=incoming.status,
    alert_name=title,
    severity=severity,
    summary=incoming.annotations.get("summary"),
    description=incoming.annotations.get("description"),
    labels=incoming.labels,
    annotations=incoming.annotations,
    starts_at=starts_at,
    ends_at=_end_time(incoming),
    generator_url=incoming.generator_url,
    latest_payload={"batch": original["batch"], "alert": original["alert"]},
    first_received_at=now,
    last_received_at=now,
    resolved_at=(
      _resolved_at(incoming, now) if incoming.status == "resolved" else None
    ),
  )
  session.add(alert)
  await session.flush()
  await _record_evidence(session, alert, original, normalized, provider)
  return alert


async def _update_alert(
  session: AsyncSession,
  alert: ProviderAlert,
  incoming: AlertmanagerAlertPayload,
  original: dict,
  normalized: dict,
  now: datetime,
  provider: AlertProvider,
) -> Literal["updated", "resolved"]:
  previous_status = alert.status
  alert.status = incoming.status
  alert.alert_name = _title(incoming, provider)
  alert.severity = _severity(incoming.labels)
  alert.summary = incoming.annotations.get("summary")
  alert.description = incoming.annotations.get("description")
  alert.labels = incoming.labels
  alert.annotations = incoming.annotations
  alert.ends_at = _end_time(incoming)
  alert.generator_url = incoming.generator_url
  alert.latest_payload = {"batch": original["batch"], "alert": original["alert"]}
  alert.last_received_at = now

  incident = await session.scalar(
    select(Incident).where(
      Incident.id == alert.incident_id,
      Incident.project_id == alert.project_id,
    ),
  )
  if incident is None:
    raise SourceConfigurationError(
      f"{provider.title()} alert references a missing project incident",
    )

  outcome: Literal["updated", "resolved"] = "updated"
  if incoming.status == "firing":
    if alert.resolved_at is not None or incident.status == "resolved":
      alert.resolved_at = None
      incident.status = "open"
      incident.resolved_at = None
    incident.title = alert.alert_name
    incident.description = _description(incoming)
    incident.severity = alert.severity
  else:
    if previous_status == "firing":
      outcome = "resolved"
      alert.resolved_at = _resolved_at(incoming, now)
      active_count = await session.scalar(
        select(func.count())
        .select_from(ProviderAlert)
        .where(
          ProviderAlert.incident_id == alert.incident_id,
          ProviderAlert.status == "firing",
          ProviderAlert.id != alert.id,
        ),
      )
      if active_count == 0:
        incident.status = "resolved"
        incident.resolved_at = alert.resolved_at
      elif incident.status == "resolved":
        incident.status = "open"
        incident.resolved_at = None
    elif alert.resolved_at is None:
      alert.resolved_at = _resolved_at(incoming, now)

  await _record_evidence(session, alert, original, normalized, provider)
  return outcome


async def receive_provider_alert_payload(
  session: AsyncSession,
  source: IncidentSource,
  payload: AlertmanagerWebhookPayload,
  original_payload: dict,
  provider: AlertProvider,
) -> list[AlertmanagerAlertResult]:
  locked_source = await session.scalar(
    select(IncidentSource)
    .where(IncidentSource.id == source.id)
    .with_for_update(),
  )
  if (
    locked_source is None
    or not locked_source.enabled
    or locked_source.source_type != provider
    or locked_source.project_id != source.project_id
  ):
    raise SourceConfigurationError(
      f"{provider.title()} source changed while processing notification",
    )

  now = datetime.now(UTC)
  results: list[AlertmanagerAlertResult] = []
  for index, incoming in enumerate(payload.alerts):
    original, normalized = _notification_content(
      payload,
      original_payload,
      index,
      provider,
    )
    alert = await session.scalar(
      select(ProviderAlert)
      .where(
        ProviderAlert.source_id == locked_source.id,
        ProviderAlert.fingerprint == incoming.fingerprint,
      )
      .with_for_update(),
    )
    if alert is None:
      if incoming.status == "resolved":
        results.append(
          AlertmanagerAlertResult(
            fingerprint=incoming.fingerprint,
            status=incoming.status,
            outcome="ignored",
          ),
        )
        continue
      alert = await _create_alert(
        session,
        locked_source,
        incoming,
        original,
        normalized,
        now,
        provider,
      )
      results.append(
        AlertmanagerAlertResult(
          fingerprint=alert.fingerprint,
          status=alert.status,
          outcome="created",
          alert_id=alert.id,
          incident_id=alert.incident_id,
        ),
      )
      continue

    outcome = await _update_alert(
      session,
      alert,
      incoming,
      original,
      normalized,
      now,
      provider,
    )
    results.append(
      AlertmanagerAlertResult(
        fingerprint=alert.fingerprint,
        status=alert.status,
        outcome=outcome,
        alert_id=alert.id,
        incident_id=alert.incident_id,
      ),
    )

  await session.commit()
  return results
