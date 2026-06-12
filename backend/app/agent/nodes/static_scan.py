from __future__ import annotations

from pathlib import Path

from backend.app.agent.nodes.helpers import append_log, publish_agent_state
from backend.app.agent.state import AuditState
from backend.app.scanners import bandit, baseline, gitleaks, java_dependencies, semgrep, top10, trivy


async def run(state: AuditState) -> dict[str, object]:
    await publish_agent_state(
        state["task_id"],
        "StaticScan",
        "running",
        "正在执行静态扫描，包括 Semgrep、Bandit、Gitleaks、Trivy、Java 依赖漏洞扫描和启发式规则。",
        60,
    )

    project_path = Path(state["project_path"])
    results = [
        *semgrep.run(project_path),
        *bandit.run(project_path),
        *gitleaks.run(project_path),
        *trivy.run(project_path),
        *java_dependencies.run(project_path),
        *baseline.run(project_path),
        *top10.run(project_path),
    ]
    message = f"静态扫描完成，发现 {len(results)} 条候选结果"

    await publish_agent_state(state["task_id"], "StaticScan", "completed", message, 65)
    return {
        "scan_results": results,
        "logs": append_log(state, message),
    }
