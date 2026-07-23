from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AdminAuditLog, AuditTask, AuthSession, User
from backend.app.schemas.auth import (
    AdminAuditLogResponse,
    AdminAuditLogClearRequest,
    AdminQuotaUpdateRequest,
    AdminTaskSummary,
    AdminUserSummary,
    AdminUserUpdateRequest,
    LLMUsageResponse,
)
from backend.app.services.audit_service import stop_audit
from backend.app.services.auth_service import record_admin_action, require_admin
from backend.app.services.llm_usage import usage_summary


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

    before = {"role": user.role, "is_active": user.is_active}
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.commit()
    db.refresh(user)
    record_admin_action(
        db,
        admin_user_id=current_admin.id,
        action="user.update",
        target_type="user",
        target_id=user.id,
        details={"before": before, "after": {"role": user.role, "is_active": user.is_active}},
    )
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


@router.post("/tasks/{task_id}/stop", response_model=AdminTaskSummary)
async def stop_user_task(
    task_id: str,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
) -> AdminTaskSummary:
    task = db.get(AuditTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    owner = db.get(User, task.user_id)
    if owner is None or owner.role != "user":
        raise HTTPException(status_code=400, detail="Only ordinary user audit tasks can be stopped here")
    if task.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Only queued or running tasks can be stopped")

    stopped = await stop_audit(task_id)
    if stopped is None:
        raise HTTPException(status_code=409, detail="Task is no longer running")
    record_admin_action(
        db,
        admin_user_id=current_admin.id,
        action="task.stop",
        target_type="audit_task",
        target_id=stopped.id,
        details={"owner_id": stopped.user_id, "status": stopped.status},
    )
    return AdminTaskSummary(
        id=stopped.id,
        user_id=stopped.user_id,
        task_name=stopped.task_name,
        status=stopped.status,
        upload_name=stopped.upload_name,
        language=stopped.language,
        framework=stopped.framework,
        created_at=stopped.created_at,
        started_at=stopped.started_at,
        finished_at=stopped.finished_at,
        finding_count=0,
    )


@router.patch("/users/{user_id}/llm-quota", response_model=LLMUsageResponse)
def update_user_llm_quota(
    user_id: str,
    payload: AdminQuotaUpdateRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
) -> LLMUsageResponse:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    previous = user.monthly_token_limit
    user.monthly_token_limit = payload.monthly_token_limit
    db.commit()
    record_admin_action(
        db,
        admin_user_id=current_admin.id,
        action="user.llm_quota.update",
        target_type="user",
        target_id=user.id,
        details={"before": previous, "after": payload.monthly_token_limit},
    )
    return LLMUsageResponse.model_validate(usage_summary(db, user.id))


@router.post("/users/{user_id}/sessions/revoke", status_code=204)
def revoke_user_sessions(
    user_id: str,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    sessions = db.execute(
        select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    ).scalars().all()
    now = datetime.now(timezone.utc)
    for session in sessions:
        session.revoked_at = now
    db.commit()
    record_admin_action(
        db,
        admin_user_id=current_admin.id,
        action="user.sessions.revoke",
        target_type="user",
        target_id=user.id,
        details={"revoked_count": len(sessions)},
    )
    from fastapi import Response

    return Response(status_code=204)


@router.get("/audit-logs", response_model=list[AdminAuditLogResponse])
def list_admin_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[AdminAuditLogResponse]:
    rows = db.execute(
        select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(limit)
    ).scalars().all()
    result: list[AdminAuditLogResponse] = []
    for row in rows:
        try:
            details = json.loads(row.details_json or "{}")
        except json.JSONDecodeError:
            details = {"raw": row.details_json}
        result.append(
            AdminAuditLogResponse(
                id=row.id,
                admin_user_id=row.admin_user_id,
                action=row.action,
                target_type=row.target_type,
                target_id=row.target_id,
                details=details if isinstance(details, dict) else {"value": details},
                created_at=row.created_at,
            )
        )
    return result


@router.delete("/audit-logs")
def clear_admin_audit_logs(
    payload: AdminAuditLogClearRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, int]:
    if payload.clear_all:
        statement = delete(AdminAuditLog)
    else:
        log_ids = list(dict.fromkeys(payload.ids))
        statement = delete(AdminAuditLog).where(AdminAuditLog.id.in_(log_ids))

    result = db.execute(statement)
    db.commit()
    return {"deleted_count": int(result.rowcount or 0)}
