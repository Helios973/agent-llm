from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.audit import SandboxCreateResponse
from backend.app.services.auth_service import can_access_user_content, get_current_user
from backend.app.services.sandbox import get_sandbox_runner


router = APIRouter()


@router.post("/sandbox/session", response_model=SandboxCreateResponse)
async def create_sandbox_session(
    task_id: str = Query(..., description="Audit task id"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SandboxCreateResponse:
    task = db.get(AuditTask, task_id)
    if task is None or not can_access_user_content(current_user, task.user_id):
        raise HTTPException(status_code=404, detail="Task not found")

    session = await get_sandbox_runner().create(task_id)
    return SandboxCreateResponse(
        sandbox_id=session.sandbox_id,
        status=session.status,
        message=session.message,
    )

