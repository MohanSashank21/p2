import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

import pytest
import pytest_asyncio
from sqlalchemy import event as sqlalchemy_event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
  AsyncSession,
  async_sessionmaker,
  create_async_engine,
)

import app.db
from app.db.base import Base
from app.db.github import (
  GitHubIncidentCorrelation,
  GitHubInstallation,
  GitHubRepository,
  GitHubWebhookEvent,
)
from app.db.incident import Incident, IncidentEvidence
from app.services import github_event_worker
from app.services.github_event_processing_service import (
  process_github_workflow_event,
)


@pytest_asyncio.fixture
async def github_event_session_factory(tmp_path):
  engine = create_async_engine(
    f"sqlite+aiosqlite:///{tmp_path / 'github-events.sqlite3'}",
  )

  @sqlalchemy_event.listens_for(engine.sync_engine, "connect")
  def enable_sqlite_foreign_keys(connection, _connection_record):
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

  async with engine.begin() as connection:
    await connection.run_sync(Base.metadata.create_all)

  session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
  )
  try:
    yield session_factory
  finally:
    await engine.dispose()


@pytest_asyncio.fixture
async def postgres_github_event_session_factory():
  target = os.environ.get("OPSPILOT_TEST_POSTGRES_URL")
  if not target:
    pytest.skip("Set OPSPILOT_TEST_POSTGRES_URL to a disposable PostgreSQL test database")
  url = make_url(target)
  if url.get_backend_name() != "postgresql":
    pytest.fail("OPSPILOT_TEST_POSTGRES_URL must use PostgreSQL")
  async_url = url.set(drivername="postgresql+asyncpg")
  admin_engine = create_async_engine(async_url)
  schema_name = f"opspilot_test_{uuid.uuid4().hex}"
  engine = None
  try:
    async with admin_engine.begin() as connection:
      await connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    engine = create_async_engine(
      async_url,
      connect_args={"server_settings": {"search_path": schema_name}},
    )
    async with engine.begin() as connection:
      await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(
      bind=engine,
      class_=AsyncSession,
      expire_on_commit=False,
    )
  finally:
    if engine is not None:
      await engine.dispose()
    async with admin_engine.begin() as connection:
      await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
    await admin_engine.dispose()


async def _create_repository(
  session_factory: async_sessionmaker[AsyncSession],
  *,
  github_repo_id: int = 123,
) -> tuple[uuid.UUID, GitHubRepository]:
  async with session_factory() as session:
    created_project = app.db.project.Project(name="event processing")
    session.add(created_project)
    await session.flush()
    installation = GitHubInstallation(
      project_id=created_project.id,
      installation_id=456,
      account_login="example",
    )
    session.add(installation)
    await session.flush()
    repository = GitHubRepository(
      project_id=created_project.id,
      installation_id=installation.id,
      github_repo_id=github_repo_id,
      full_name=f"example/repo-{github_repo_id}",
      owner="example",
      html_url=f"https://github.com/example/repo-{github_repo_id}",
    )
    session.add(repository)
    await session.commit()
    return created_project.id, repository


async def _create_webhook_event(
  session_factory: async_sessionmaker[AsyncSession],
  *,
  project_id: uuid.UUID,
  repository: GitHubRepository,
  delivery_id: str,
  workflow_run_id: int,
  commit_sha: str,
) -> uuid.UUID:
  async with session_factory() as session:
    record = GitHubWebhookEvent(
      project_id=project_id,
      github_repository_id=repository.id,
      delivery_id=delivery_id,
      event_name="workflow_run",
      action="completed",
      payload={
        "repository": {"id": repository.github_repo_id},
        "workflow_run": {
          "id": workflow_run_id,
          "name": "CI",
          "conclusion": "failure",
          "head_sha": commit_sha,
        },
      },
    )
    session.add(record)
    await session.commit()
    return record.id


async def _count(session_factory, model) -> int:
  async with session_factory() as session:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


@pytest.mark.asyncio
async def test_events_exactly_correlate_by_repository_and_commit(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  commit_sha = "a" * 40
  first_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-1",
    workflow_run_id=10,
    commit_sha=commit_sha,
  )
  assert await github_event_worker.process_next_github_event(session_factory)

  second_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-2",
    workflow_run_id=11,
    commit_sha=commit_sha,
  )
  assert await github_event_worker.process_next_github_event(session_factory)
  third_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-3",
    workflow_run_id=10,
    commit_sha="b" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)

  async with session_factory() as session:
    first = await session.get(GitHubWebhookEvent, first_id)
    second = await session.get(GitHubWebhookEvent, second_id)
    third = await session.get(GitHubWebhookEvent, third_id)
    assert first is not None and second is not None and third is not None
    assert first.incident_id == second.incident_id == third.incident_id
    assert first.processing_status == second.processing_status == "processed"
    assert await session.scalar(select(func.count()).select_from(Incident)) == 1
    assert await session.scalar(
      select(func.count()).select_from(IncidentEvidence),
    ) == 3
    assert await session.scalar(
      select(func.count()).select_from(GitHubIncidentCorrelation),
    ) == 4


@pytest.mark.asyncio
async def test_matching_identifiers_from_different_incidents_are_ambiguous(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  first_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-1",
    workflow_run_id=10,
    commit_sha="a" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)
  second_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-2",
    workflow_run_id=11,
    commit_sha="b" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)
  ambiguous_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-3",
    workflow_run_id=10,
    commit_sha="b" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)

  async with session_factory() as session:
    first = await session.get(GitHubWebhookEvent, first_id)
    second = await session.get(GitHubWebhookEvent, second_id)
    ambiguous = await session.get(GitHubWebhookEvent, ambiguous_id)
    assert first is not None and second is not None and ambiguous is not None
    assert first.incident_id != second.incident_id
    assert ambiguous.incident_id not in {first.incident_id, second.incident_id}
    assert await session.scalar(select(func.count()).select_from(Incident)) == 3


@pytest.mark.asyncio
async def test_exact_correlation_is_scoped_to_the_project_repository(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  first_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="delivery-1",
    workflow_run_id=10,
    commit_sha="a" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)

  other_project_id, other_repository = await _create_repository(
    session_factory,
    github_repo_id=123,
  )
  second_id = await _create_webhook_event(
    session_factory,
    project_id=other_project_id,
    repository=other_repository,
    delivery_id="delivery-2",
    workflow_run_id=10,
    commit_sha="a" * 40,
  )
  assert await github_event_worker.process_next_github_event(session_factory)

  async with session_factory() as session:
    first = await session.get(GitHubWebhookEvent, first_id)
    second = await session.get(GitHubWebhookEvent, second_id)
    assert first is not None and second is not None
    assert first.incident_id != second.incident_id
    assert await session.scalar(select(func.count()).select_from(Incident)) == 2


@pytest.mark.asyncio
async def test_invalid_workflow_event_is_terminal_and_visible(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  event_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="invalid-delivery",
    workflow_run_id=1,
    commit_sha="c" * 40,
  )
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    record.payload = {
      **record.payload,
      "workflow_run": {
        key: value
        for key, value in record.payload["workflow_run"].items()
        if key != "id"
      },
    }
    await session.commit()

  assert await github_event_worker.process_next_github_event(session_factory)
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    assert record.processing_status == "failed"
    assert record.last_failure_code == "invalid_event"
    assert record.attempt_count == 1
    assert await session.scalar(select(func.count()).select_from(Incident)) == 0


@pytest.mark.asyncio
async def test_transient_worker_failure_retries_without_duplicate_incidents(
  github_event_session_factory,
  monkeypatch,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  event_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="retry-delivery",
    workflow_run_id=12,
    commit_sha="d" * 40,
  )
  original = github_event_worker.process_github_workflow_event

  async def transient_failure(_session, _event_id):
    raise RuntimeError("sensitive exception details are not persisted")

  monkeypatch.setattr(
    github_event_worker,
    "process_github_workflow_event",
    transient_failure,
  )
  assert await github_event_worker.process_next_github_event(session_factory)
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    assert record.processing_status == "retry"
    assert record.last_failure_code == "processing_error"
    assert record.attempt_count == 1
    record.available_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()

  monkeypatch.setattr(github_event_worker, "process_github_workflow_event", original)
  assert await github_event_worker.process_next_github_event(session_factory)
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    assert record.processing_status == "processed"
    assert record.attempt_count == 2
    assert await session.scalar(select(func.count()).select_from(Incident)) == 1


@pytest.mark.asyncio
async def test_expired_processing_lease_is_reclaimed(github_event_session_factory):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  event_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="expired-lease",
    workflow_run_id=13,
    commit_sha="e" * 40,
  )
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    record.processing_status = "processing"
    record.attempt_count = 1
    record.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()

  assert await github_event_worker.process_next_github_event(session_factory)
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    assert record.processing_status == "processed"
    assert record.attempt_count == 2
    assert await session.scalar(select(func.count()).select_from(Incident)) == 1


@pytest.mark.asyncio
async def test_repeated_worker_crashes_exhaust_the_attempt_limit(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  event_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="exhausted-lease",
    workflow_run_id=15,
    commit_sha="1" * 40,
  )
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    record.processing_status = "processing"
    record.attempt_count = 5
    record.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()

  assert not await github_event_worker.process_next_github_event(session_factory)
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    assert record.processing_status == "failed"
    assert record.last_failure_code == "attempt_limit"
    assert record.attempt_count == 5
    assert await session.scalar(select(func.count()).select_from(Incident)) == 0


@pytest.mark.asyncio
async def test_postgres_workers_claim_and_correlate_concurrent_events(
  postgres_github_event_session_factory,
):
  session_factory = postgres_github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  claim_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="claim-lock",
    workflow_run_id=20,
    commit_sha="2" * 40,
  )

  claims = await asyncio.gather(
    github_event_worker._claim_next_event(session_factory),
    github_event_worker._claim_next_event(session_factory),
  )
  successful_claims = [claim for claim in claims if claim is not None]
  assert len(successful_claims) == 1
  assert successful_claims[0][0] == claim_id

  first_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="concurrent-1",
    workflow_run_id=21,
    commit_sha="3" * 40,
  )
  second_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="concurrent-2",
    workflow_run_id=22,
    commit_sha="3" * 40,
  )
  assert all(
    await asyncio.gather(
      github_event_worker.process_next_github_event(session_factory),
      github_event_worker.process_next_github_event(session_factory),
    ),
  )

  async with session_factory() as session:
    retrying_events = list(
      await session.scalars(
        select(GitHubWebhookEvent).where(
          GitHubWebhookEvent.processing_status == "retry",
        ),
      ),
    )
    for event_record in retrying_events:
      event_record.available_at = datetime.now(UTC) - timedelta(seconds=1)
    await session.commit()

  if retrying_events:
    assert await github_event_worker.process_next_github_event(session_factory)

  async with session_factory() as session:
    first = await session.get(GitHubWebhookEvent, first_id)
    second = await session.get(GitHubWebhookEvent, second_id)
    assert first is not None and second is not None
    assert first.processing_status == second.processing_status == "processed"
    assert first.incident_id == second.incident_id
    assert await session.scalar(
      select(func.count()).select_from(Incident).where(
        Incident.source_type == "github",
      ),
    ) == 1


@pytest.mark.asyncio
async def test_processing_service_is_idempotent_for_completed_event(
  github_event_session_factory,
):
  session_factory = github_event_session_factory
  project_id, repository = await _create_repository(session_factory)
  event_id = await _create_webhook_event(
    session_factory,
    project_id=project_id,
    repository=repository,
    delivery_id="idempotent-delivery",
    workflow_run_id=14,
    commit_sha="f" * 40,
  )
  async with session_factory() as session:
    record = await session.get(GitHubWebhookEvent, event_id)
    assert record is not None
    record.processing_status = "processing"
    incident_id = await process_github_workflow_event(session, event_id)
    await session.commit()
    assert incident_id is not None

  async with session_factory() as session:
    assert await process_github_workflow_event(session, event_id) == incident_id
    await session.commit()
  assert await _count(session_factory, Incident) == 1
  assert await _count(session_factory, IncidentEvidence) == 1
