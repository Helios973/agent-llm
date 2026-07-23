from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    task_id: str
    status: str
    upload_name: str
    upload_count: int = 1
    upload_names: list[str] = Field(default_factory=list)


class StartAuditRequest(BaseModel):
    task_id: str
    baseline_task_id: str | None = None


class StartAuditResponse(BaseModel):
    task_id: str
    status: str


class AuditTaskSummary(BaseModel):
    id: str
    task_name: str
    status: str
    upload_name: str | None = None
    language: str | None = None
    framework: str | None = None
    baseline_task_id: str | None = None
    retry_count: int = 0
    finding_count: int = 0
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class AuditTaskListResponse(BaseModel):
    items: list[AuditTaskSummary]
    total: int
    page: int
    page_size: int


class AuditTaskUpdateRequest(BaseModel):
    task_name: str = Field(min_length=1, max_length=255)


class AuditTaskBulkDeleteRequest(BaseModel):
    task_ids: list[str] = Field(min_length=1, max_length=100)


class AuditTaskBulkDeleteResponse(BaseModel):
    deleted_ids: list[str] = Field(default_factory=list)
    skipped_ids: list[str] = Field(default_factory=list)


class AuditComparisonResponse(BaseModel):
    task_id: str
    baseline_task_id: str
    changed_files: list[str] = Field(default_factory=list)
    new_findings: list[FindingResponse] = Field(default_factory=list)
    unchanged_findings: list[FindingResponse] = Field(default_factory=list)
    resolved_findings: list[FindingResponse] = Field(default_factory=list)


class FindingResponse(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    cvss_score: float
    owasp_id: str | None = None
    owasp_name: str | None = None
    owasp_label: str | None = None
    cwe_id: str | None = None
    impact: str | None = None
    recommendation: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    evidence: str | None = None
    code_snippet: str | None = None
    related_files: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    ctf_scenarios: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditTaskResponse(BaseModel):
    id: str
    user_id: str
    task_name: str
    status: str
    language: str | None = None
    framework: str | None = None
    upload_name: str | None = None
    project_path: str | None = None
    report_dir: str | None = None
    baseline_task_id: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    source_digest: str | None = None
    retry_count: int = 0
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[FindingResponse] = Field(default_factory=list)


class EventPayload(BaseModel):
    event: str
    message: str | None = None
    agent: str | None = None
    status: str | None = None
    value: int | None = None
    data: dict[str, Any] | None = None
    created_at: datetime | None = None


class HealthResponse(BaseModel):
    app: str
    database: str
    redis: str


class SandboxCreateResponse(BaseModel):
    sandbox_id: str
    status: str
    message: str
