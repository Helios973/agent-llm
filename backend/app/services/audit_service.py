from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.app.agent.graph import build_audit_graph
from backend.app.core.database import SessionLocal
from backend.app.models import AuditTask, Finding, User
from backend.app.services.events import event_bus

_background_tasks: set[asyncio.Task[None]] = set()
_active_audits: dict[str, asyncio.Task[None]] = {}
_FINDING_CORE_FIELDS = {
    "source",
    "severity",
    "title",
    "description",
    "file_path",
    "line_number",
    "cvss_score",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_user(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None:
        user = User(
            id=user_id,
            username="local-demo",
            email="local-demo@example.com",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


def serialize_task(task: AuditTask) -> dict[str, object]:
    return {
        "id": task.id,
        "user_id": task.user_id,
        "task_name": task.task_name,
        "status": task.status,
        "language": task.language,
        "framework": task.framework,
        "upload_name": task.upload_name,
        "project_path": task.project_path,
        "report_dir": task.report_dir,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "findings": [item.as_dict() for item in task.findings],
    }


def _serialize_finding_meta(item: dict[str, object]) -> str | None:
    extra = {
        key: value
        for key, value in item.items()
        if key not in _FINDING_CORE_FIELDS and value not in (None, "", [], {})
    }
    if not extra:
        return None
    return json.dumps(extra, ensure_ascii=False)


async def run_audit_task(task_id: str) -> None:
    db = SessionLocal()
    try:
        task = db.get(AuditTask, task_id)
        if task is None or task.status not in {"queued", "running"}:
            return

        task.status = "running"
        task.started_at = utcnow()
        db.commit()

        await event_bus.publish(task_id, {"event": "progress", "value": 5, "message": "审计任务已进入队列"})

        graph = build_audit_graph()
        initial_state = {
            "task_id": task.id,
            "user_id": task.user_id,
            "task_name": task.task_name,
            "file_path": task.upload_path or "",
            "project_path": task.project_path or "",
            "language": task.language or "",
            "framework": task.framework or "",
            "entrypoint": "",
            "sandbox_id": "",
            "scan_results": [],
            "llm_results": [],
            "findings": [],
            "report_paths": {},
            "status": "running",
            "logs": [],
        }

        result = await graph.ainvoke(initial_state)

        # Another session may have stopped the task while the graph was awaiting I/O.
        db.refresh(task)
        if task.status == "stopped":
            return
        task.language = result["language"] or None
        task.framework = result["framework"] or None
        task.project_path = result["project_path"] or None
        task.report_dir = result["report_paths"].get("report_dir")
        task.status = "completed"
        task.finished_at = utcnow()

        db.query(Finding).filter(Finding.task_id == task.id).delete()
        for item in result["findings"]:
            db.add(
                Finding(
                    id=str(uuid4()),
                    task_id=task.id,
                    source=str(item["source"]),
                    severity=str(item["severity"]),
                    title=str(item["title"]),
                    description=str(item["description"]),
                    file_path=str(item["file_path"]),
                    line_number=int(item["line_number"]),
                    cvss_score=float(item["cvss_score"]),
                    meta_json=_serialize_finding_meta(dict(item)),
                )
            )
        db.commit()

        await event_bus.publish(
            task_id,
            {
                "event": "progress",
                "value": 100,
                "message": f"审计完成，共发现 {len(result['findings'])} 条漏洞",
            },
        )
    except asyncio.CancelledError:
        db.rollback()
        task = db.get(AuditTask, task_id)
        if task is not None and task.status != "stopped":
            task.status = "stopped"
            task.finished_at = utcnow()
            db.commit()
        await event_bus.publish(task_id, {"event": "progress", "value": 0, "message": "Audit task stopped by administrator"})
        raise
    except Exception as exc:
        task = db.get(AuditTask, task_id)
        if task is not None:
            task.status = "failed"
            task.finished_at = utcnow()
            db.commit()
        await event_bus.publish(task_id, {"event": "log", "message": f"审计失败: {exc}"})
    finally:
        db.close()


def schedule_audit(task_id: str) -> asyncio.Task[None]:
    task = asyncio.create_task(run_audit_task(task_id))
    _background_tasks.add(task)
    _active_audits[task_id] = task
    task.add_done_callback(_background_tasks.discard)
    task.add_done_callback(lambda _: _active_audits.pop(task_id, None))
    return task


async def stop_audit(task_id: str) -> AuditTask | None:
    """Cancel an in-process audit and persist its terminal stopped state."""
    task = _active_audits.get(task_id)
    if task is not None and not task.done():
        task.cancel()

    db = SessionLocal()
    try:
        record = db.get(AuditTask, task_id)
        if record is None or record.status not in {"queued", "running"}:
            return None
        record.status = "stopped"
        record.finished_at = utcnow()
        db.commit()
        db.refresh(record)
    finally:
        db.close()

    await event_bus.publish(task_id, {"event": "progress", "value": 0, "message": "Audit task stopped by administrator"})
    return record


def report_paths(task: AuditTask) -> dict[str, Path]:
    if not task.report_dir:
        return {}
    report_dir = Path(task.report_dir)
    return {
        "report_dir": report_dir,
        "markdown": report_dir / "report.md",
        "html": report_dir / "report.html",
        "json": report_dir / "report.json",
    }
