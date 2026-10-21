import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
  PermissionDeniedError,
  ProjectConflictError,
  ProjectNotFoundError,
)
from app.db.project import Project
from app.db.project_membership import ProjectMembership
from app.db.user import User
from app.schemas.project_schema import ProjectCreateRequest, ProjectUpdateRequest


async def create_project(
  session: AsyncSession,
  owner: User,
  request: ProjectCreateRequest,
) -> Project:
  project = Project(
    name=request.name,
    description=request.description,
  )
  session.add(project)
  await session.flush()
  session.add(
    ProjectMembership(
      project_id=project.id,
      user_id=owner.id,
      role="owner",
    ),
  )
  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise ProjectConflictError(
      "The project or project ownership conflicts with existing data",
    ) from error
  await session.refresh(project)
  return project


async def list_accessible_projects(
  session: AsyncSession,
  user: User,
) -> list[tuple[Project, str]]:
  result = await session.execute(
    select(Project, ProjectMembership.role)
    .join(
      ProjectMembership,
      ProjectMembership.project_id == Project.id,
    )
    .where(ProjectMembership.user_id == user.id)
    .order_by(Project.name, Project.id),
  )
  return list(result)


async def get_accessible_project(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> tuple[Project, str]:
  result = await session.execute(
    select(Project, ProjectMembership.role)
    .join(
      ProjectMembership,
      ProjectMembership.project_id == Project.id,
    )
    .where(
      Project.id == project_id,
      ProjectMembership.user_id == user.id,
    ),
  )
  project_and_role = result.one_or_none()
  if project_and_role is None:
    raise ProjectNotFoundError("Project not found")
  return project_and_role


async def update_project(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
  request: ProjectUpdateRequest,
) -> tuple[Project, str]:
  project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can update this project")

  if request.name is not None:
    project.name = request.name
  if "description" in request.model_fields_set:
    project.description = request.description
  try:
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise ProjectConflictError("The project update conflicts with existing data") from error
  await session.refresh(project)
  return project, role


async def delete_project(
  session: AsyncSession,
  project_id: uuid.UUID,
  user: User,
) -> None:
  project, role = await get_accessible_project(session, project_id, user)
  if role != "owner":
    raise PermissionDeniedError("Only project owners can delete this project")
  try:
    await session.delete(project)
    await session.commit()
  except IntegrityError as error:
    await session.rollback()
    raise ProjectConflictError(
      "The project cannot be deleted while dependent resources still exist",
    ) from error
