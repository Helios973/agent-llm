from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.audit import UploadResponse
from backend.app.services.auth_service import get_current_user
from backend.app.services.files import SavedUploadBundle, build_demo_upload, save_uploads


router = APIRouter()


def _summarize_upload_name(upload_names: list[str]) -> str:
    if not upload_names:
        return "upload"
    if len(upload_names) == 1:
        return upload_names[0]
    return f"{upload_names[0]} + {len(upload_names) - 1} more"


def _create_task_record(
    *,
    task_id: str,
    user_id: str,
    task_name: str,
    upload_bundle: SavedUploadBundle,
    db: Session,
) -> UploadResponse:
    upload_name = _summarize_upload_name(upload_bundle.names)
    task = AuditTask(
        id=task_id,
        user_id=user_id,
        task_name=task_name,
        status="uploaded",
        upload_name=upload_name,
        upload_path=str(upload_bundle.path),
    )
    db.add(task)
    db.commit()
    return UploadResponse(
        task_id=task_id,
        status=task.status,
        upload_name=upload_name,
        upload_count=len(upload_bundle.names),
        upload_names=upload_bundle.names,
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_source_code(
    files: list[UploadFile] | None = File(default=None),
    file: UploadFile | None = File(default=None),
    task_name: str | None = Form(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UploadResponse:
    uploads: list[UploadFile] = []
    if files:
        uploads.extend(files)
    if file is not None:
        uploads.append(file)
    if not uploads:
        raise HTTPException(status_code=400, detail="No files uploaded")

    task_id = str(uuid4())

    try:
        upload_bundle = await save_uploads(task_id, uploads)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    default_task_name = (
        upload_bundle.names[0]
        if len(upload_bundle.names) == 1
        else f"{len(upload_bundle.names)}-file-audit"
    )
    return _create_task_record(
        task_id=task_id,
        user_id=current_user.id,
        task_name=task_name or default_task_name,
        upload_bundle=upload_bundle,
        db=db,
    )


@router.post("/upload/demo", response_model=UploadResponse)
async def upload_demo_project(
    task_name: str | None = Form(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UploadResponse:
    task_id = str(uuid4())
    upload_path = build_demo_upload(task_id)
    upload_bundle = SavedUploadBundle(path=upload_path, names=[upload_path.name])

    return _create_task_record(
        task_id=task_id,
        user_id=current_user.id,
        task_name=task_name or "vulnerable_python_app",
        upload_bundle=upload_bundle,
        db=db,
    )
