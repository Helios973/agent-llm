from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.audit import (
    AuditComparisonResponse,
    AuditTaskBulkDeleteRequest,
    AuditTaskBulkDeleteResponse,
    AuditTaskListResponse,
    AuditTaskResponse,
    AuditTaskSummary,
    AuditTaskUpdateRequest,
    StartAuditRequest,
    StartAuditResponse,
)
from backend.app.services.audit_service import delete_task_data, schedule_audit, serialize_task, utcnow
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
    if task.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Task is already queued or running")
    if not task.upload_path:
        raise HTTPException(status_code=400, detail="Task upload is missing")

    if payload.baseline_task_id:
        baseline = get_accessible_task(db, payload.baseline_task_id, current_user)
        if baseline.id == task.id or baseline.status != "completed":
            raise HTTPException(status_code=400, detail="Baseline must be a different completed task")
        task.baseline_task_id = baseline.id
    task.status = "queued"
    task.queued_at = utcnow()
    db.commit()
    schedule_audit(task.id)

    return StartAuditResponse(task_id=task.id, status="queued")


@router.get("/audit/tasks", response_model=AuditTaskListResponse)
def list_audit_tasks(
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditTaskListResponse:
    filters = [AuditTask.user_id == current_user.id]
    if status_filter:
        filters.append(AuditTask.status == status_filter)
    if search:
        term = f"%{search.strip()}%"
        filters.append(or_(AuditTask.task_name.ilike(term), AuditTask.upload_name.ilike(term)))
    total = db.execute(select(func.count(AuditTask.id)).where(*filters)).scalar_one()
    tasks = db.execute(
        select(AuditTask)
        .where(*filters)
        .order_by(AuditTask.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).scalars().all()
    return AuditTaskListResponse(
        items=[
            AuditTaskSummary(
                id=task.id,
                task_name=task.task_name,
                status=task.status,
                upload_name=task.upload_name,
                language=task.language,
                framework=task.framework,
                baseline_task_id=task.baseline_task_id,
                retry_count=task.retry_count,
                finding_count=len(task.findings),
                created_at=task.created_at,
                updated_at=task.updated_at,
                started_at=task.started_at,
                finished_at=task.finished_at,
            )
            for task in tasks
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/audit/tasks/bulk-delete", response_model=AuditTaskBulkDeleteResponse)
def bulk_delete_audit_tasks(
    payload: AuditTaskBulkDeleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditTaskBulkDeleteResponse:
    requested_ids = list(dict.fromkeys(payload.task_ids))
    tasks = db.execute(
        select(AuditTask).where(
            AuditTask.user_id == current_user.id,
            AuditTask.id.in_(requested_ids),
        )
    ).scalars().all()
    tasks_by_id = {task.id: task for task in tasks}
    deleted_ids: list[str] = []
    skipped_ids: list[str] = []
    for task_id in requested_ids:
        task = tasks_by_id.get(task_id)
        if task is None or task.status in {"queued", "running"}:
            skipped_ids.append(task_id)
            continue
        delete_task_data(task)
        db.delete(task)
        deleted_ids.append(task_id)
    db.commit()
    return AuditTaskBulkDeleteResponse(deleted_ids=deleted_ids, skipped_ids=skipped_ids)


@router.patch("/audit/{task_id}", response_model=AuditTaskResponse)
def update_audit_task(
    task_id: str,
    payload: AuditTaskUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditTaskResponse:
    task = get_accessible_task(db, task_id, current_user)
    task.task_name = payload.task_name.strip()
    db.commit()
    db.refresh(task)
    return AuditTaskResponse.model_validate(serialize_task(task))


@router.post("/audit/{task_id}/retry", response_model=StartAuditResponse)
def retry_audit_task(
    task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StartAuditResponse:
    task = get_accessible_task(db, task_id, current_user)
    if task.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Task is already active")
    task.status = "queued"
    task.retry_count += 1
    task.queued_at = utcnow()
    task.finished_at = None
    task.error_message = None
    db.commit()
    schedule_audit(task.id)
    return StartAuditResponse(task_id=task.id, status="queued")


@router.delete("/audit/{task_id}", status_code=204)
def delete_audit_task(
    task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = get_accessible_task(db, task_id, current_user)
    if task.status in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Stop the task before deleting it")
    delete_task_data(task)
    db.delete(task)
    db.commit()
    return Response(status_code=204)


@router.get("/audit/{task_id}/compare/{baseline_task_id}", response_model=AuditComparisonResponse)
def compare_audit_tasks(
    task_id: str,
    baseline_task_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditComparisonResponse:
    task = get_accessible_task(db, task_id, current_user)
    baseline = get_accessible_task(db, baseline_task_id, current_user)
    from backend.app.services.incremental import compare_findings

    comparison = compare_findings(
        [item.as_dict() for item in task.findings],
        [item.as_dict() for item in baseline.findings],
    )
    try:
        import json

        changed_files = json.loads(task.changed_files_json or "[]")
    except (ValueError, TypeError):
        changed_files = []
    return AuditComparisonResponse(
        task_id=task.id,
        baseline_task_id=baseline.id,
        changed_files=changed_files,
        **comparison,
    )


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

