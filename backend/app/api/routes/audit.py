from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.audit import AuditTaskResponse, StartAuditRequest, StartAuditResponse
from backend.app.services.audit_service import schedule_audit, serialize_task
from backend.app.services.auth_service import can_access_user_content, get_current_user, get_user_from_token
from backend.app.services.events import event_bus


router = APIRouter()


def get_accessible_task(db: Session, task_id: str, current_user: User) -> AuditTask:
    task = db.get(AuditTask, task_id)
    if task is None or not can_access_user_content(current_user, task.user_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.post("/audit/start", response_model=StartAuditResponse)
async def start_audit(
    payload: StartAuditRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StartAuditResponse:
    task = get_accessible_task(db, payload.task_id, current_user)
    if task.status == "running":
        raise HTTPException(status_code=409, detail="Task is already running")
    if not task.upload_path:
        raise HTTPException(status_code=400, detail="Task upload is missing")

    task.status = "queued"
    db.commit()
    schedule_audit(task.id)

    return StartAuditResponse(task_id=task.id, status="running")


@router.get("/audit/{task_id}", response_model=AuditTaskResponse)
def get_audit_result(
    task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditTaskResponse:
    task = get_accessible_task(db, task_id, current_user)
    return AuditTaskResponse.model_validate(serialize_task(task))


@router.websocket("/ws/audit/{task_id}")
async def audit_stream(websocket: WebSocket, task_id: str, db: Session = Depends(get_db)) -> None:
    current_user = get_user_from_token(db, websocket.query_params.get("access_token"))
    task = db.get(AuditTask, task_id)
    if current_user is None or task is None or not can_access_user_content(current_user, task.user_id):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    history = await event_bus.read_history(task_id)
    for item in history:
        await websocket.send_json(item)

    try:
        async for item in event_bus.subscribe(task_id):
            await websocket.send_json(item)
    except WebSocketDisconnect:
        return

