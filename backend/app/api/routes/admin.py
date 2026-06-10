from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.auth import AdminTaskSummary, AdminUserSummary, AdminUserUpdateRequest
from backend.app.services.auth_service import require_admin


router = APIRouter(prefix="/admin")


@router.get("/users", response_model=list[AdminUserSummary])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[AdminUserSummary]:
    task_counts = (
        select(AuditTask.user_id, func.count(AuditTask.id).label("task_count"))
        .group_by(AuditTask.user_id)
        .subquery()
    )
    rows = db.execute(
        select(User, func.coalesce(task_counts.c.task_count, 0))
        .outerjoin(task_counts, task_counts.c.user_id == User.id)
        .order_by(User.created_at.desc())
    ).all()
    return [
        AdminUserSummary.model_validate(user).model_copy(update={"task_count": int(task_count)})
        for user, task_count in rows
    ]


@router.patch("/users/{user_id}", response_model=AdminUserSummary)
def update_user(
    user_id: str,
    payload: AdminUserUpdateRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
) -> AdminUserSummary:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_admin.id and payload.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot disable your own administrator account")
    if user.id == current_admin.id and payload.role == "user":
        raise HTTPException(status_code=400, detail="You cannot demote your own administrator account")

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.commit()
    db.refresh(user)
    task_count = db.execute(select(func.count(AuditTask.id)).where(AuditTask.user_id == user.id)).scalar_one()
    return AdminUserSummary.model_validate(user).model_copy(update={"task_count": int(task_count)})


@router.get("/users/{user_id}/tasks", response_model=list[AdminTaskSummary])
def list_user_tasks(
    user_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[AdminTaskSummary]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    tasks = db.execute(
        select(AuditTask)
        .where(AuditTask.user_id == user_id)
        .order_by(AuditTask.created_at.desc())
    ).scalars().all()
    return [
        AdminTaskSummary(
            id=task.id,
            user_id=task.user_id,
            task_name=task.task_name,
            status=task.status,
            upload_name=task.upload_name,
            language=task.language,
            framework=task.framework,
            created_at=task.created_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            finding_count=len(task.findings),
        )
        for task in tasks
    ]
