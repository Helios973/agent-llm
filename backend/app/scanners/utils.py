from __future__ import annotations

from pathlib import Path


IGNORED_SUFFIXES = {".pyc", ".pyo", ".so", ".dll", ".exe", ".class", ".png", ".jpg", ".jpeg", ".gif", ".pdf"}
IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    "__pycache__",
    "__macosx",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    ".venv",
    "venv",
}
TEXT_MINIFIED_SUFFIXES = {".js", ".css"}
THIRD_PARTY_PATH_MARKERS = {
    ("static", "ajax", "libs"),
    ("static", "vendor"),
    ("public", "vendor"),
    ("webjars",),
}


def is_probably_minified(file_path: Path, content: str) -> bool:
    lowered_name = file_path.name.lower()
    if any(lowered_name.endswith(f".min{suffix}") for suffix in TEXT_MINIFIED_SUFFIXES):
        return True

    if file_path.suffix.lower() not in TEXT_MINIFIED_SUFFIXES:
        return False

    lines = content.splitlines() or [content]
    if len(lines) <= 3 and max((len(line) for line in lines), default=0) > 2000:
        return True

    total_chars = sum(len(line) for line in lines)
    average_line_length = total_chars / max(len(lines), 1)
    return total_chars > 4000 and average_line_length > 300


def should_skip_text_scan(file_path: Path, content: str | None = None) -> bool:
    lowered_parts = tuple(part.lower() for part in file_path.parts)
    lowered_part_set = set(lowered_parts)
    if lowered_part_set & IGNORED_DIR_NAMES:
        return True
    if any(marker == lowered_parts[index : index + len(marker)] for marker in THIRD_PARTY_PATH_MARKERS for index in range(len(lowered_parts) - len(marker) + 1)):
        return True
    if file_path.suffix.lower() in IGNORED_SUFFIXES:
        return True
    if content is not None and is_probably_minified(file_path, content):
        return True
    return False


def scan_text_patterns(
    project_path: Path,
    source: str,
    patterns: list[tuple[str, str, str, str]],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    for file_path in project_path.rglob("*"):
        if not file_path.is_file():
            continue
        if should_skip_text_scan(file_path):
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if should_skip_text_scan(file_path, content):
            continue

        lowered_content = content.lower()
        lines = content.splitlines()
        relative_path = file_path.relative_to(project_path).as_posix()

        for needle, severity, title, description in patterns:
            lowered_needle = needle.lower()
            if lowered_needle not in lowered_content:
                continue

            matched_line = 1
            for index, line in enumerate(lines, start=1):
                if lowered_needle in line.lower():
                    matched_line = index
                    break

            results.append(
                {
                    "source": source,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "file_path": relative_path,
                    "line_number": matched_line,
                    "cvss_score": 0.0,
                    "metadata": {"needle": needle},
                }
            )

    return results
