from __future__ import annotations

from pathlib import Path

from backend.app.agent.nodes.helpers import append_log, publish_agent_state
from backend.app.agent.state import AuditState
from backend.app.services.taint_analysis import analyze_project


async def run(state: AuditState) -> dict[str, object]:
    await publish_agent_state(state["task_id"], "TaintAnalysis", "running", "正在构建调用链并检查 Source-to-Sink 数据流。", 68)
    changed_files = state.get("changed_files") if state.get("baseline_project_path") else None
    results = analyze_project(Path(state["project_path"]), changed_files)
    merged = [*state["scan_results"], *results]
    message = f"调用链分析完成，生成 {len(results)} 条数据流候选。"
    await publish_agent_state(state["task_id"], "TaintAnalysis", "completed", message, 72)
    return {"scan_results": merged, "logs": append_log(state, message)}
