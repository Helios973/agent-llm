from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from backend.app.agent.state import AuditFinding


SOURCE_PATTERN = re.compile(r"\b(?:request\.|input\s*\(|sys\.argv|os\.environ|req\.(?:body|query|params)|getParameter\s*\()")
SINK_PATTERN = re.compile(
    r"\b(?:execute\s*\(|executemany\s*\(|os\.system\s*\(|subprocess\.|Runtime\.getRuntime|eval\s*\(|exec\s*\(|requests\.(?:get|post)\s*\(|open\s*\()"
)


@dataclass
class FunctionFlow:
    name: str
    file_path: str
    line: int
    calls: set[str] = field(default_factory=set)
    has_source: bool = False
    has_sink: bool = False
    evidence: list[str] = field(default_factory=list)


def _python_flows(path: Path, relative: str) -> list[FunctionFlow]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content)
    except (OSError, SyntaxError):
        return []
    lines = content.splitlines()
    flows: list[FunctionFlow] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno)
        block = "\n".join(lines[node.lineno - 1 : end])
        calls: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    calls.add(child.func.attr)
        evidence = []
        if SOURCE_PATTERN.search(block):
            evidence.append("untrusted input source")
        if SINK_PATTERN.search(block):
            evidence.append("sensitive sink")
        flows.append(
            FunctionFlow(
                name=node.name,
                file_path=relative,
                line=node.lineno,
                calls=calls,
                has_source="untrusted input source" in evidence,
                has_sink="sensitive sink" in evidence,
                evidence=evidence,
            )
        )
    return flows


def _generic_flow(path: Path, relative: str) -> list[FunctionFlow]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    source = SOURCE_PATTERN.search(content)
    sink = SINK_PATTERN.search(content)
    if not source or not sink:
        return []
    line = content[: sink.start()].count("\n") + 1
    return [FunctionFlow(name=path.stem, file_path=relative, line=line, has_source=True, has_sink=True)]


def analyze_project(project_path: Path, changed_files: list[str] | None = None) -> list[AuditFinding]:
    changed = {item.replace("\\", "/") for item in changed_files or []}
    flows: list[FunctionFlow] = []
    for path in project_path.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".py", ".java", ".js", ".ts", ".php"}:
            continue
        relative = path.relative_to(project_path).as_posix()
        if changed_files is not None and relative not in changed:
            continue
        flows.extend(_python_flows(path, relative) if path.suffix.lower() == ".py" else _generic_flow(path, relative))

    sink_names = {flow.name for flow in flows if flow.has_sink}
    findings: list[AuditFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for flow in flows:
        direct = flow.has_source and flow.has_sink
        linked = flow.has_source and bool(flow.calls & sink_names)
        if not direct and not linked:
            continue
        path_description = (
            f"函数 {flow.name} 同时包含外部输入源和敏感操作点，存在数据流风险。"
            if direct
            else f"函数 {flow.name} 接收外部输入，并调用敏感函数：{', '.join(sorted(flow.calls & sink_names))}。"
        )
        key = (flow.file_path, flow.line, flow.name)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "source": "TaintFlow",
                "severity": "HIGH",
                "title": "潜在的输入源到危险操作点数据流",
                "description": path_description,
                "file_path": flow.file_path,
                "line_number": flow.line,
                "cvss_score": 0.0,
                "cwe_id": "CWE-20",
                "evidence": "source -> call chain -> sink",
                "metadata": {"function": flow.name, "calls": sorted(flow.calls), "analysis_type": "call-graph"},
            }
        )
    return findings
