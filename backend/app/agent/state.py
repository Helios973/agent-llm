from __future__ import annotations

from typing import Any

from typing_extensions import TypedDict


class AuditFinding(TypedDict, total=False):
    source: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    cvss_score: float
    owasp_id: str
    owasp_name: str
    owasp_label: str
    cwe_id: str
    impact: str
    recommendation: str
    reproduction_steps: list[str]
    evidence: str
    code_snippet: str
    related_cves: list[str]
    ctf_scenarios: list[str]
    references: list[str]
    metadata: dict[str, Any]


class AuditState(TypedDict):
    task_id: str
    user_id: str
    task_name: str
    file_path: str
    project_path: str
    language: str
    framework: str
    entrypoint: str
    sandbox_id: str
    scan_results: list[AuditFinding]
    llm_results: list[AuditFinding]
    findings: list[AuditFinding]
    report_paths: dict[str, str]
    status: str
    logs: list[str]
    baseline_project_path: str
    changed_files: list[str]
