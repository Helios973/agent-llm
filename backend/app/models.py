from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, index=True, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True, unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    tasks: Mapped[list["AuditTask"]] = relationship(back_populates="user")


class AuditTask(Base):
    __tablename__ = "audit_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False, index=True)
    language: Mapped[str | None] = mapped_column(String(50))
    framework: Mapped[str | None] = mapped_column(String(50))
    upload_name: Mapped[str | None] = mapped_column(String(255))
    upload_path: Mapped[str | None] = mapped_column(Text)
    project_path: Mapped[str | None] = mapped_column(Text)
    report_dir: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="tasks")
    findings: Mapped[list["Finding"]] = relationship(back_populates="task", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("audit_tasks.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    meta_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    task: Mapped[AuditTask] = relationship(back_populates="findings")

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cvss_score": self.cvss_score,
        }

        if self.meta_json:
            try:
                extra = json.loads(self.meta_json)
            except json.JSONDecodeError:
                extra = {"meta_json": self.meta_json}
            if isinstance(extra, dict):
                payload.update(extra)

        payload.setdefault("metadata", {})
        payload.setdefault("reproduction_steps", [])
        payload.setdefault("related_files", [])
        payload.setdefault("related_cves", [])
        payload.setdefault("ctf_scenarios", [])
        payload.setdefault("references", [])
        return payload
