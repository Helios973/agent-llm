from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import httpx

from backend.app.agent.state import AuditFinding
from backend.app.core.config import settings
from backend.app.services.code_security_skill import (
    CodeSecuritySkillResources,
    apply_hard_exclusion_filters,
    load_code_security_skill_resources,
)
from backend.app.services.java_audit_skill import build_java_audit_prompt_addendum


SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".php",
    ".java",
    ".rb",
    ".rs",
}
JAVA_CONTEXT_SUFFIXES = {
    ".java",
    ".xml",
    ".jsp",
    ".jspx",
    ".properties",
    ".yml",
    ".yaml",
}
JS_LIKE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
PYTHON_KEYWORDS = {
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "false",
    "finally",
    "for",
    "from",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "none",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "self",
    "true",
    "try",
    "while",
    "with",
    "yield",
}
JAVA_KEYWORDS = {
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "record",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
}
SEVERITY_BONUS = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
}
IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
PYTHON_IMPORT_PATTERN = re.compile(r"^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))", re.MULTILINE)
JAVA_IMPORT_PATTERN = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z0-9_.*]+)\s*;", re.MULTILINE)
JAVA_PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)
JS_IMPORT_PATTERN = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"])|(?:require\(\s*['"]([^'"]+)['"]\s*\))|(?:import\(\s*['"]([^'"]+)['"]\s*\))"""
)
PYTHON_DEFINITION_PATTERN = re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
JAVA_TYPE_PATTERN = re.compile(
    r"^\s*(?:public|protected|private|abstract|final|static|\s)*(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
JAVA_METHOD_PATTERN = re.compile(
    r"^\s*(?:public|protected|private|static|final|synchronized|abstract|native|default|\s)+[\w<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
JS_FUNCTION_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)",
    re.MULTILINE,
)
JS_VARIABLE_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ReviewContextFile:
    path: str
    content: str
    reasons: tuple[str, ...] = ()
    linked_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewContextMemory:
    files: tuple[ReviewContextFile, ...]
    relationship_notes: tuple[str, ...]
    summary: str


@dataclass
class _ContextCandidate:
    score: int = 0
    line_numbers: set[int] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    linked_files: set[str] = field(default_factory=set)


def _is_java_review(language: str) -> bool:
    return language.lower() == "java"


def llm_is_configured() -> bool:
    return settings.llm_enabled and bool(settings.deepseek_api_key and settings.deepseek_model)


def _merge_snippet_windows(line_numbers: list[int], total_lines: int, radius: int = 6) -> list[tuple[int, int]]:
    windows: list[tuple[int, int]] = []
    for line_number in sorted(set(line_number for line_number in line_numbers if line_number > 0)):
        start = max(line_number - radius, 1)
        end = min(line_number + radius, total_lines)
        if windows and start <= windows[-1][1] + 1:
            windows[-1] = (windows[-1][0], max(windows[-1][1], end))
        else:
            windows.append((start, end))
    return windows


def _build_file_excerpt(content: str, line_numbers: list[int], max_chars: int) -> str:
    lines = content.splitlines()
    if not lines:
        return ""

    if not line_numbers:
        return content[:max_chars]

    windows = _merge_snippet_windows(line_numbers, len(lines))
    excerpts: list[str] = []
    for start, end in windows:
        for index in range(start - 1, end):
            excerpts.append(f"{index + 1:04d}: {lines[index]}")
        excerpts.append("...")

    excerpt = "\n".join(excerpts[:-1] if excerpts else [])
    return excerpt[:max_chars] if excerpt else content[:max_chars]


def _build_full_file_content(content: str) -> str:
    lines = content.splitlines()
    if not lines:
        return ""
    return "\n".join(f"{index + 1:04d}: {line}" for index, line in enumerate(lines))


def _iter_source_files(project_path: Path, language: str) -> list[Path]:
    allowed_suffixes = SOURCE_SUFFIXES | JAVA_CONTEXT_SUFFIXES if _is_java_review(language) else SOURCE_SUFFIXES
    files = [
        path
        for path in project_path.rglob("*")
        if path.is_file() and path.suffix.lower() in allowed_suffixes and "__pycache__" not in path.parts
    ]
    files.sort(key=lambda path: path.as_posix())
    return files[: settings.llm_context_index_max_files]


def _read_source_map(project_path: Path, language: str) -> dict[str, str]:
    source_map: dict[str, str] = {}
    for file_path in _iter_source_files(project_path, language):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        source_map[file_path.relative_to(project_path).as_posix()] = content
    return source_map


def _module_names_for_path(path: str) -> set[str]:
    pure_path = PurePosixPath(path)
    without_suffix = pure_path.with_suffix("")
    parts = without_suffix.parts
    names: set[str] = set()
    if not parts:
        return names

    if parts[-1] == "__init__":
        package_name = ".".join(parts[:-1])
        if package_name:
            names.add(package_name)
        if len(parts) >= 2:
            names.add(parts[-2])
        return names

    dotted_name = ".".join(parts)
    if dotted_name:
        names.add(dotted_name)
    names.add(parts[-1])
    if len(parts) >= 2:
        names.add(".".join(parts[-2:]))
    return names


def _build_python_module_index(source_map: dict[str, str]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for path in source_map:
        if not path.endswith(".py"):
            continue
        for module_name in _module_names_for_path(path):
            index[module_name].add(path)
    return index


def _java_package_name(content: str) -> str:
    match = JAVA_PACKAGE_PATTERN.search(content)
    return match.group(1).strip() if match else ""


def _build_java_module_indexes(source_map: dict[str, str]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    class_index: dict[str, set[str]] = defaultdict(set)
    package_index: dict[str, set[str]] = defaultdict(set)
    for path, content in source_map.items():
        if not path.endswith(".java"):
            continue
        package_name = _java_package_name(content)
        class_name = PurePosixPath(path).stem
        if class_name:
            class_index[class_name].add(path)
            if package_name:
                class_index[f"{package_name}.{class_name}"].add(path)
        if package_name:
            package_index[package_name].add(path)
    return class_index, package_index


def _resolve_python_import(module_name: str, current_path: str, module_index: dict[str, set[str]]) -> set[str]:
    normalized_name = module_name.strip()
    if not normalized_name:
        return set()

    leading_dots = len(normalized_name) - len(normalized_name.lstrip("."))
    body = normalized_name.lstrip(".")
    candidates: set[str] = set()

    if leading_dots:
        current_parts = list(PurePosixPath(current_path).with_suffix("").parts)
        if current_parts and current_parts[-1] == "__init__":
            current_parts = current_parts[:-1]
        package_parts = current_parts[:-1]
        keep_count = max(len(package_parts) - (leading_dots - 1), 0)
        prefix = package_parts[:keep_count]
        if body:
            prefix.extend(body.split("."))
        if prefix:
            candidates.add(".".join(prefix))
    else:
        candidates.add(body or normalized_name)

    resolved: set[str] = set()
    for candidate in candidates:
        resolved.update(module_index.get(candidate, set()))
    return resolved


def _resolve_java_import(
    module_name: str,
    class_index: dict[str, set[str]],
    package_index: dict[str, set[str]],
) -> set[str]:
    normalized_name = module_name.strip()
    if not normalized_name:
        return set()

    if normalized_name.endswith(".*"):
        return set(package_index.get(normalized_name[:-2], set()))

    simple_name = normalized_name.rsplit(".", 1)[-1]
    return set(class_index.get(normalized_name, set())) | set(class_index.get(simple_name, set()))


def _resolve_js_import(module_name: str, current_path: str, source_paths: set[str]) -> set[str]:
    normalized_name = module_name.strip()
    if not normalized_name.startswith("."):
        return set()

    base_path = PurePosixPath(current_path).parent.joinpath(normalized_name)
    candidate_paths = {
        base_path.as_posix(),
        base_path.with_suffix(".js").as_posix(),
        base_path.with_suffix(".jsx").as_posix(),
        base_path.with_suffix(".ts").as_posix(),
        base_path.with_suffix(".tsx").as_posix(),
        base_path.joinpath("index.js").as_posix(),
        base_path.joinpath("index.jsx").as_posix(),
        base_path.joinpath("index.ts").as_posix(),
        base_path.joinpath("index.tsx").as_posix(),
    }
    return {path for path in candidate_paths if path in source_paths}


def _extract_local_imports(
    path: str,
    content: str,
    python_module_index: dict[str, set[str]],
    java_class_index: dict[str, set[str]],
    java_package_index: dict[str, set[str]],
    source_paths: set[str],
) -> set[str]:
    imports: set[str] = set()

    if path.endswith(".py"):
        for match in PYTHON_IMPORT_PATTERN.finditer(content):
            module_name = match.group(1) or match.group(2) or ""
            imports.update(_resolve_python_import(module_name, path, python_module_index))
        imports.discard(path)
        return imports

    if path.endswith(".java"):
        for match in JAVA_IMPORT_PATTERN.finditer(content):
            imports.update(_resolve_java_import(match.group(1), java_class_index, java_package_index))
        imports.discard(path)
        return imports

    if Path(path).suffix.lower() in JS_LIKE_SUFFIXES:
        for match in JS_IMPORT_PATTERN.finditer(content):
            module_name = next((group for group in match.groups() if group), "")
            imports.update(_resolve_js_import(module_name, path, source_paths))
        imports.discard(path)
        return imports

    return imports


def _build_import_graph(source_map: dict[str, str]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    source_paths = set(source_map)
    python_module_index = _build_python_module_index(source_map)
    java_class_index, java_package_index = _build_java_module_indexes(source_map)
    import_graph: dict[str, set[str]] = {}
    reverse_graph: dict[str, set[str]] = defaultdict(set)

    for path, content in source_map.items():
        imports = _extract_local_imports(
            path,
            content,
            python_module_index,
            java_class_index,
            java_package_index,
            source_paths,
        )
        import_graph[path] = imports
        for imported in imports:
            reverse_graph[imported].add(path)

    return import_graph, reverse_graph


def _extract_definitions(path: str, content: str) -> dict[str, list[int]]:
    patterns = [PYTHON_DEFINITION_PATTERN]
    if path.endswith(".java"):
        patterns.extend([JAVA_TYPE_PATTERN, JAVA_METHOD_PATTERN])
    if Path(path).suffix.lower() in JS_LIKE_SUFFIXES:
        patterns.extend([JS_FUNCTION_PATTERN, JS_VARIABLE_PATTERN])

    definitions: dict[str, list[int]] = defaultdict(list)
    lines = content.splitlines()
    for index, line in enumerate(lines, start=1):
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                definitions[match.group(1)].append(index)
    return definitions


def _build_definition_index(source_map: dict[str, str]) -> dict[str, list[tuple[str, int]]]:
    index: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for path, content in source_map.items():
        for symbol, line_numbers in _extract_definitions(path, content).items():
            for line_number in line_numbers:
                index[symbol].append((path, line_number))
    return index


def _interesting_identifiers(content: str, line_numbers: list[int], limit: int = 10) -> list[str]:
    lines = content.splitlines()
    if not lines:
        return []

    selected_chunks: list[str] = []
    if line_numbers:
        for start, end in _merge_snippet_windows(line_numbers, len(lines), radius=2):
            selected_chunks.extend(lines[start - 1 : end])
    else:
        selected_chunks.extend(lines[:40])

    counts: Counter[str] = Counter()
    chunk_text = "\n".join(selected_chunks)
    reserved_keywords = PYTHON_KEYWORDS | (JAVA_KEYWORDS if any(marker in chunk_text for marker in ("package ", "import java.", "public class")) else set())
    for token in IDENTIFIER_PATTERN.findall(chunk_text):
        lowered = token.lower()
        if lowered in reserved_keywords:
            continue
        counts[token] += 1

    return [identifier for identifier, _ in counts.most_common(limit)]


def _find_identifier_references(
    identifier: str,
    source_map: dict[str, str],
    *,
    exclude_paths: set[str],
    limit: int,
) -> list[tuple[str, int]]:
    pattern = re.compile(rf"\b{re.escape(identifier)}\b")
    references: list[tuple[str, int]] = []

    for path, content in source_map.items():
        if path in exclude_paths:
            continue
        for index, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                references.append((path, index))
                break
        if len(references) >= limit:
            break

    return references


def _add_candidate(
    candidates: dict[str, _ContextCandidate],
    path: str,
    *,
    score: int,
    reason: str,
    line_numbers: set[int] | None = None,
    linked_files: set[str] | None = None,
) -> None:
    candidate = candidates.setdefault(path, _ContextCandidate())
    candidate.score += score
    candidate.reasons.add(reason)
    if line_numbers:
        candidate.line_numbers.update(line_numbers)
    if linked_files:
        candidate.linked_files.update(linked_files)


def build_review_context_memory(
    *,
    project_path: Path,
    language: str,
    entrypoint: str,
    scan_results: list[AuditFinding],
) -> ReviewContextMemory:
    source_map = _read_source_map(project_path, language)
    if not source_map:
        return ReviewContextMemory(files=(), relationship_notes=(), summary="No source files available.")

    import_graph, reverse_graph = _build_import_graph(source_map)
    definition_index = _build_definition_index(source_map)
    candidates: dict[str, _ContextCandidate] = {}
    anchor_lines: dict[str, list[int]] = defaultdict(list)

    for result in scan_results:
        file_path = str(result.get("file_path", "")).strip()
        if file_path not in source_map:
            continue
        line_number = max(int(result.get("line_number", 1) or 1), 1)
        severity = str(result.get("severity", "LOW")).upper()
        anchor_lines[file_path].append(line_number)
        _add_candidate(
            candidates,
            file_path,
            score=120 + SEVERITY_BONUS.get(severity, 0),
            reason=f"scan anchor ({severity})",
            line_numbers={line_number},
        )

    if entrypoint in source_map:
        _add_candidate(
            candidates,
            entrypoint,
            score=60,
            reason="detected entrypoint",
            line_numbers={1},
        )

    for anchor_path, line_numbers in anchor_lines.items():
        linked_imports = sorted(import_graph.get(anchor_path, set()))
        for linked_path in linked_imports[: settings.llm_context_reference_limit]:
            _add_candidate(
                candidates,
                linked_path,
                score=28,
                reason=f"imported by {anchor_path}",
                linked_files={anchor_path},
            )

        callers = sorted(reverse_graph.get(anchor_path, set()))
        for caller_path in callers[: settings.llm_context_reference_limit]:
            _add_candidate(
                candidates,
                caller_path,
                score=24,
                reason=f"references {anchor_path}",
                linked_files={anchor_path},
            )

        for identifier in _interesting_identifiers(source_map[anchor_path], line_numbers):
            symbol_definitions = definition_index.get(identifier, [])
            for definition_path, definition_line in symbol_definitions:
                if definition_path == anchor_path:
                    continue
                _add_candidate(
                    candidates,
                    definition_path,
                    score=22,
                    reason=f"defines {identifier}",
                    line_numbers={definition_line},
                    linked_files={anchor_path},
                )

            reference_hits = _find_identifier_references(
                identifier,
                source_map,
                exclude_paths={anchor_path, *(path for path, _ in symbol_definitions)},
                limit=settings.llm_context_reference_limit,
            )
            for reference_path, reference_line in reference_hits:
                _add_candidate(
                    candidates,
                    reference_path,
                    score=16,
                    reason=f"references {identifier}",
                    line_numbers={reference_line},
                    linked_files={anchor_path},
                )

    if not candidates:
        fallback_path = entrypoint if entrypoint in source_map else next(iter(source_map))
        _add_candidate(
            candidates,
            fallback_path,
            score=50,
            reason="project context fallback",
            line_numbers={1},
        )
        selected_limit = settings.java_llm_max_review_files if _is_java_review(language) else settings.llm_max_review_files
        for linked_path in sorted(import_graph.get(fallback_path, set()))[: max(selected_limit - 1, 0)]:
            _add_candidate(
                candidates,
                linked_path,
                score=20,
                reason=f"linked from {fallback_path}",
                linked_files={fallback_path},
            )

    ordered_paths = sorted(
        candidates,
        key=lambda path: (-candidates[path].score, path),
    )
    selected_limit = settings.java_llm_max_review_files if _is_java_review(language) else settings.llm_max_review_files
    selected_paths = ordered_paths[: selected_limit]
    selected_set = set(selected_paths)

    relationship_notes: list[str] = []
    context_files: list[ReviewContextFile] = []
    for path in selected_paths:
        candidate = candidates[path]
        content = source_map[path]
        linked_files = sorted(
            (
                import_graph.get(path, set())
                | reverse_graph.get(path, set())
                | candidate.linked_files
            )
            & selected_set
            - {path}
        )
        relationship_bits = ", ".join(linked_files[:4]) or "none"
        relationship_notes.append(f"{path} -> {relationship_bits}")
        if _is_java_review(language) and settings.java_llm_full_file_context and Path(path).suffix.lower() in JAVA_CONTEXT_SUFFIXES:
            excerpt = _build_full_file_content(content)
        else:
            excerpt = _build_file_excerpt(
                content,
                sorted(candidate.line_numbers),
                settings.llm_max_file_chars,
            )
        context_files.append(
            ReviewContextFile(
                path=path,
                content=excerpt,
                reasons=tuple(sorted(candidate.reasons)),
                linked_files=tuple(linked_files),
            )
        )

    anchor_list = sorted(anchor_lines)
    summary_parts = [
        f"selected {len(context_files)} linked files",
        f"anchors: {', '.join(anchor_list[:4]) or 'none'}",
    ]
    if _is_java_review(language) and settings.java_llm_full_file_context:
        summary_parts.append("java full-file context enabled")
    if entrypoint:
        summary_parts.append(f"entrypoint: {entrypoint}")
    return ReviewContextMemory(
        files=tuple(context_files),
        relationship_notes=tuple(relationship_notes),
        summary="; ".join(summary_parts),
    )


def _serialize_scan_results(scan_results: list[AuditFinding]) -> str:
    rows: list[str] = []
    for item in scan_results[: settings.llm_max_findings * 3]:
        rows.append(
            f"- [{item.get('severity', 'LOW')}] {item.get('title', '')} "
            f"@ {item.get('file_path', '')}:{item.get('line_number', 1)} "
            f"(source={item.get('source', 'unknown')}) {item.get('description', '')}"
        )
    return "\n".join(rows)


def _serialize_excluded_scan_summaries(excluded_scan_summaries: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in excluded_scan_summaries[:10]:
        rows.append(
            f"- {item.get('title', '')} @ {item.get('file_path', '')} "
            f"(reason={item.get('reason', 'hard exclusion')})"
        )
    return "\n".join(rows)


def _build_user_prompt(
    *,
    task_name: str,
    language: str,
    framework: str,
    entrypoint: str,
    scan_results: list[AuditFinding],
    context_memory: ReviewContextMemory,
    resources: CodeSecuritySkillResources,
    excluded_scan_summaries: list[dict[str, Any]],
    java_skill_addendum: str,
) -> str:
    relationship_notes = "\n".join(f"- {note}" for note in context_memory.relationship_notes) or "- none"
    file_blocks = "\n\n".join(
        [
            "\n".join(
                [
                    f"### File: {context_file.path}",
                    f"Reasons: {', '.join(context_file.reasons) or 'project context'}",
                    f"Linked Files: {', '.join(context_file.linked_files) or 'none'}",
                    "```text",
                    context_file.content,
                    "```",
                ]
            )
            for context_file in context_memory.files
        ]
    )

    java_skill_block = ""
    if java_skill_addendum:
        java_skill_block = (
            "Installed Java Audit Skill Guidance:\n"
            f"```text\n{java_skill_addendum}\n```\n\n"
        )

    language_specific_instructions = ""
    if _is_java_review(language):
        language_specific_instructions = (
            "Java review rule: read every provided Java/XML/JSP/properties context file completely before deciding.\n"
            "For Java findings, exclude anything that lacks a concrete request-to-sink path, auth bypass path, or component-version proof.\n"
        )

    return (
        "Follow the bundled Code Security Review skill exactly.\n"
        "Execute the workflow strictly in order: Phase 1 audit, Phase 2 filter, then Phase 3 report.\n"
        "Treat the provided files as one linked code context and trace data flow across file boundaries.\n"
        f"{language_specific_instructions}"
        "Do not keep any finding that violates the hard exclusions or has confidence_score < 7.\n"
        "Return exactly one JSON object with this shape: {\"findings\": [...], \"filter_summary\": [...]}.\n"
        "Only include KEPT findings in findings.\n"
        "Each finding must contain: severity,title,description,file_path,line_number,owasp_id,cwe_id,impact,recommendation,"
        "reproduction_steps,evidence,related_files,related_cves,ctf_scenarios,references,confidence_score,category,attack_path.\n"
        "Each filter_summary item must contain: title,file_path,decision,confidence_score,reason,hard_exclusion,precedent_hit,concrete_attack_path.\n"
        "If a finding spans multiple files, set file_path to the most security-critical file/line and list the rest in related_files.\n"
        "Write description, impact, recommendation, reproduction_steps, evidence, and attack_path in Chinese.\n"
        "Return at most "
        f"{settings.llm_max_findings} findings with strong exploitability value.\n\n"
        f"Task Name: {task_name}\n"
        f"Language: {language or 'unknown'}\n"
        f"Framework: {framework or 'unknown'}\n"
        f"Entrypoint: {entrypoint or 'unknown'}\n"
        f"Context Memory Summary: {context_memory.summary}\n\n"
        "Static Scan Findings After Local Hard Exclusions:\n"
        f"{_serialize_scan_results(scan_results) or '- none'}\n\n"
        "Static Scan Findings Excluded By Local Hard Rules:\n"
        f"{_serialize_excluded_scan_summaries(excluded_scan_summaries) or '- none'}\n\n"
        "Cross-File Relationships:\n"
        f"{relationship_notes}\n\n"
        "Relevant Linked Code Context:\n"
        f"{file_blocks or 'No code context available.'}\n\n"
        f"{java_skill_block}"
        "Bundled Audit Methodology:\n"
        f"```text\n{resources.audit_prompt}\n```\n\n"
        "Bundled Filtering Rules:\n"
        f"```text\n{resources.filtering_rules}\n```\n\n"
        "Bundled Hard Exclusion Patterns:\n"
        f"```text\n{resources.hard_exclusion_patterns}\n```\n"
    )


def _build_request_payload(system_prompt: str, user_prompt: str, user_identifier: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": settings.deepseek_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "stream": False,
        "temperature": 0.2,
        "max_tokens": settings.llm_max_output_tokens,
        "reasoning_effort": settings.deepseek_reasoning_effort,
        "user_id": user_identifier,
    }
    payload["thinking"] = {"type": "enabled" if settings.deepseek_thinking_enabled else "disabled"}
    return payload


def _extract_response_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return ""

    message = first_choice.get("message")
    if not isinstance(message, dict):
        return ""

    content = message.get("content")
    return content.strip() if isinstance(content, str) else ""


def _coerce_int(raw_value: Any, default: int = 0) -> int:
    try:
        return int(float(raw_value))
    except (TypeError, ValueError):
        return default


def _normalize_string_list(raw_value: Any) -> list[str]:
    if isinstance(raw_value, str):
        items = [part.strip() for part in raw_value.split(",")]
        return [item for item in items if item]
    if isinstance(raw_value, list):
        return [str(item).strip() for item in raw_value if str(item).strip()]
    return []


def _normalize_filter_summary(raw_filter_summary: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_filter_summary, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_filter_summary:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "title": str(item.get("title", "")).strip(),
                "file_path": str(item.get("file_path", "")).strip(),
                "decision": str(item.get("decision", "")).upper().strip(),
                "confidence_score": _coerce_int(item.get("confidence_score"), 0),
                "reason": str(item.get("reason", "")).strip(),
                "hard_exclusion": str(item.get("hard_exclusion", "")).strip(),
                "precedent_hit": str(item.get("precedent_hit", "")).strip(),
                "concrete_attack_path": bool(item.get("concrete_attack_path", False)),
            }
        )
    return normalized


def _normalize_findings(
    raw_findings: list[dict[str, Any]],
    filter_summary: list[dict[str, Any]],
) -> list[AuditFinding]:
    filter_summary_index = {
        (str(item.get("title", "")).strip(), str(item.get("file_path", "")).strip()): item
        for item in filter_summary
    }
    normalized: list[AuditFinding] = []
    for raw_item in raw_findings[: settings.llm_max_findings]:
        file_path = str(raw_item.get("file_path", "")).strip()
        title = str(raw_item.get("title", "")).strip()
        if not file_path or not title:
            continue

        filter_item = filter_summary_index.get((title, file_path), {})
        severity = str(raw_item.get("severity", "MEDIUM")).upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = "MEDIUM"

        related_cves = _normalize_string_list(raw_item.get("related_cves"))
        related_files = _normalize_string_list(raw_item.get("related_files"))
        ctf_scenarios = _normalize_string_list(raw_item.get("ctf_scenarios"))
        reproduction_steps = _normalize_string_list(raw_item.get("reproduction_steps"))
        references = _normalize_string_list(raw_item.get("references"))
        confidence_score = _coerce_int(
            raw_item.get("confidence_score"),
            _coerce_int(filter_item.get("confidence_score"), 7),
        )
        if confidence_score < 7:
            continue
        category = str(raw_item.get("category", "")).strip()
        attack_path = str(raw_item.get("attack_path", raw_item.get("exploit_scenario", ""))).strip()
        evidence = str(raw_item.get("evidence", "")).strip() or attack_path
        filter_reason = str(filter_item.get("reason", "")).strip()

        normalized.append(
            {
                "source": "LLMReview",
                "severity": severity,
                "title": title,
                "description": str(raw_item.get("description", "")).strip(),
                "file_path": file_path,
                "line_number": int(raw_item.get("line_number", 1) or 1),
                "cvss_score": 0.0,
                "owasp_id": str(raw_item.get("owasp_id", "")).strip(),
                "cwe_id": str(raw_item.get("cwe_id", "")).strip(),
                "impact": str(raw_item.get("impact", "")).strip(),
                "recommendation": str(raw_item.get("recommendation", "")).strip(),
                "reproduction_steps": reproduction_steps,
                "evidence": evidence,
                "related_files": related_files,
                "related_cves": related_cves,
                "ctf_scenarios": ctf_scenarios,
                "references": references,
                "metadata": {
                    "analysis_type": "model",
                    "model": settings.deepseek_model,
                    "provider": "deepseek",
                    "cross_file": bool(related_files),
                    "review_skill": "code-security-review",
                    "confidence_score": confidence_score,
                    "category": category,
                    "attack_path": attack_path,
                    "filter_reason": filter_reason,
                },
            }
        )
    return normalized


async def review_project_with_llm(
    *,
    task_id: str,
    user_id: str,
    task_name: str,
    project_path: Path,
    language: str,
    framework: str,
    entrypoint: str,
    scan_results: list[AuditFinding],
) -> tuple[list[AuditFinding], str]:
    if not settings.llm_enabled:
        return [], "LLM review is disabled"

    if not settings.deepseek_api_key:
        return [], "DEEPSEEK_API_KEY is not configured"

    resources = load_code_security_skill_resources()
    filtered_scan_results, excluded_scan_summaries = apply_hard_exclusion_filters(scan_results)
    context_memory = build_review_context_memory(
        project_path=project_path,
        language=language,
        entrypoint=entrypoint,
        scan_results=filtered_scan_results,
    )
    java_skill_addendum = ""
    if language.lower() == "java":
        java_skill_addendum = build_java_audit_prompt_addendum(
            framework=framework,
            entrypoint=entrypoint,
        )
    if not context_memory.files:
        return [], "No usable cross-file context was collected for the model"

    system_prompt = (
        "You are a senior application security reviewer. "
        "Use the bundled Code Security Review skill. "
        "Complete audit, filter, and report phases in sequence. "
        "Return valid JSON only. "
        "Use accurate vulnerability names and CWE/OWASP identifiers when possible."
    )
    user_prompt = _build_user_prompt(
        task_name=task_name,
        language=language,
        framework=framework,
        entrypoint=entrypoint,
        scan_results=filtered_scan_results,
        context_memory=context_memory,
        resources=resources,
        excluded_scan_summaries=excluded_scan_summaries,
        java_skill_addendum=java_skill_addendum,
    )
    payload = _build_request_payload(system_prompt, user_prompt, user_id or task_id)

    timeout = httpx.Timeout(settings.llm_timeout_seconds)
    base_url = settings.deepseek_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.deepseek_api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        body = response.json()

    raw_text = _extract_response_text(body)
    if not raw_text:
        return [], "DeepSeek returned an empty review payload"

    parsed = json.loads(raw_text)
    raw_findings = parsed.get("findings", [])
    if not isinstance(raw_findings, list):
        return [], "DeepSeek returned an invalid findings payload"

    filter_summary = _normalize_filter_summary(parsed.get("filter_summary", []))
    findings = _normalize_findings(raw_findings, filter_summary)
    findings, excluded_model_findings = apply_hard_exclusion_filters(findings)
    excluded_summary_count = sum(1 for item in filter_summary if item.get("decision") == "EXCLUDE")
    message_bits = [
        "Code security skill review completed with "
        f"{len(context_memory.files)} linked context files",
        f"{len(findings)} kept findings",
    ]
    if filter_summary:
        message_bits.append(f"{len(filter_summary)} reviewed candidates")
    if excluded_summary_count or excluded_scan_summaries or excluded_model_findings:
        message_bits.append(
            "local/global exclusions="
            f"{excluded_summary_count + len(excluded_scan_summaries) + len(excluded_model_findings)}"
        )
    return (
        findings,
        ", ".join(message_bits),
    )
