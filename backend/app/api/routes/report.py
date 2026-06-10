from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import AuditTask, User
from backend.app.schemas.report import ReportSummaryResponse
from backend.app.services.audit_service import report_paths
from backend.app.services.auth_service import can_access_user_content, get_current_user


router = APIRouter()


@router.get("/report/{task_id}", response_model=ReportSummaryResponse)
def get_report(
    task_id: str,
    format: Literal["json", "markdown", "html"] | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = db.get(AuditTask, task_id)
    if task is None or not can_access_user_content(current_user, task.user_id):
        raise HTTPException(status_code=404, detail="Task not found")

    paths = report_paths(task)
    if not paths:
        raise HTTPException(status_code=404, detail="Report not generated yet")

    if format is not None:
        format_to_path = {
            "json": paths["json"],
            "markdown": paths["markdown"],
            "html": paths["html"],
        }
        file_path = Path(format_to_path[format])
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"{format} report not found")
        media_type = {
            "json": "application/json",
            "markdown": "text/markdown",
            "html": "text/html",
        }[format]
        return FileResponse(file_path, media_type=media_type, filename=file_path.name)

    return ReportSummaryResponse(
        task_id=task_id,
        available_formats=["json", "markdown", "html"],
        report_dir=str(paths["report_dir"]),
        markdown_path=str(paths["markdown"]),
        html_path=str(paths["html"]),
        json_path=str(paths["json"]),
    )

