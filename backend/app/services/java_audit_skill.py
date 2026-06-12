from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from backend.app.core.config import settings


SKILL_NAMES = (
    "java-route-mapper",
    "java-auth-audit",
    "java-vuln-scanner",
    "java-route-tracer",
    "java-sql-audit",
    "java-xxe-audit",
    "java-file-upload-audit",
    "java-file-read-audit",
    "java-deserialization-audit",
    "java-audit-pipeline",
)
FRONT_MATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
FIELD_PATTERN = re.compile(r"^(?P<key>[A-Za-z0-9_-]+):\s*(?P<value>.+?)\s*$")


@dataclass(frozen=True)
class JavaAuditSkillSummary:
    name: str
    description: str


@dataclass(frozen=True)
class JavaAuditSkillResources:
    root: Path
    summaries: tuple[JavaAuditSkillSummary, ...]
    severity_rating_excerpt: str
    decompile_strategy_excerpt: str


def _default_skill_root() -> Path:
    return Path.home() / ".codex" / "skills"


def _normalize_excerpt(text: str, *, max_lines: int) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    compact = [line for line in lines if line.strip()]
    return "\n".join(compact[:max_lines]).strip()


def _shorten_description(text: str, *, max_chars: int = 160) -> str:
    normalized = " ".join(text.split())
    first_sentence = re.split(r"(?<=[。.!?])\s*", normalized, maxsplit=1)[0].strip()
    candidate = first_sentence or normalized
    if len(candidate) <= max_chars:
        return candidate
    return f"{candidate[: max_chars - 3].rstrip()}..."


def _parse_front_matter(text: str) -> dict[str, str]:
    match = FRONT_MATTER_PATTERN.match(text)
    if not match:
        return {}

    payload: dict[str, str] = {}
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        field_match = FIELD_PATTERN.match(line)
        if field_match:
            payload[field_match.group("key")] = field_match.group("value").strip()
    return payload


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def resolve_java_audit_skills_root() -> Path | None:
    if not settings.java_audit_skills_enabled:
        return None

    configured = settings.java_audit_skills_root or _default_skill_root()
    root = Path(configured)
    return root if root.exists() else None


@lru_cache(maxsize=1)
def load_java_audit_skill_resources() -> JavaAuditSkillResources | None:
    root = resolve_java_audit_skills_root()
    if root is None:
        return None

    summaries: list[JavaAuditSkillSummary] = []
    for skill_name in SKILL_NAMES:
        skill_md = root / skill_name / "SKILL.md"
        if not skill_md.exists():
            continue
        front_matter = _parse_front_matter(_read_text(skill_md))
        description = front_matter.get("description", "").strip()
        if not description:
            continue
        summaries.append(JavaAuditSkillSummary(name=skill_name, description=_shorten_description(description)))

    shared_root = root / "java-shared"
    severity_excerpt = ""
    decompile_excerpt = ""
    if shared_root.exists():
        severity_file = shared_root / "SEVERITY_RATING.md"
        if severity_file.exists():
            severity_excerpt = _normalize_excerpt(_read_text(severity_file), max_lines=18)
        decompile_file = shared_root / "DECOMPILE_STRATEGY.md"
        if decompile_file.exists():
            decompile_excerpt = _normalize_excerpt(_read_text(decompile_file), max_lines=18)

    if not summaries and not severity_excerpt and not decompile_excerpt:
        return None

    return JavaAuditSkillResources(
        root=root,
        summaries=tuple(summaries),
        severity_rating_excerpt=severity_excerpt,
        decompile_strategy_excerpt=decompile_excerpt,
    )


def build_java_audit_prompt_addendum(*, framework: str, entrypoint: str) -> str:
    resources = load_java_audit_skill_resources()
    if resources is None:
        return ""

    lines = [
        "Use the installed Java audit skill set as additional review guidance for Java projects.",
        "Prefer HTTP-route-to-sink evidence over isolated code smells, and keep only high-confidence findings.",
        "Read each provided Java or Java-related context file completely before deciding.",
        "Exclude findings that do not show a concrete request parameter, call chain, or sink-level exploit path.",
    ]

    if framework and framework != "java":
        lines.append(f"Detected Java framework: {framework}. Prioritize framework-specific routing, auth, and sink behavior.")
    if entrypoint:
        lines.append(f"Detected entrypoint: {entrypoint}. Treat it as a likely framework/bootstrap anchor.")

    if resources.summaries:
        lines.append("Available Java audit skills:")
        for item in resources.summaries:
            lines.append(f"- {item.name}: {item.description}")

    lines.extend(
        [
            "Java review workflow:",
            "1. Reconstruct routes, request parameters, and controller/service/DAO call chains before finalizing findings.",
            "2. Check auth boundaries and component-version risks alongside direct code issues.",
            "3. Focus sink categories with concrete reachability: SQL, XXE, file upload, file read, deserialization.",
            "4. When only compiled artifacts are available, decompile only the necessary .class/.jar targets first, then expand selectively.",
        ]
    )

    if resources.severity_rating_excerpt:
        lines.append("Shared Java severity guidance:")
        lines.append(resources.severity_rating_excerpt)

    if resources.decompile_strategy_excerpt:
        lines.append("Shared Java decompile guidance:")
        lines.append(resources.decompile_strategy_excerpt)

    return "\n".join(lines).strip()
