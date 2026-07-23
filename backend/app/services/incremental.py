from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def project_hashes(project_path: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if not project_path.exists():
        return hashes
    for path in sorted(project_path.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        hashes[path.relative_to(project_path).as_posix()] = digest
    return hashes


def changed_project_files(current_path: Path, baseline_path: Path | None) -> list[str]:
    current = project_hashes(current_path)
    if baseline_path is None or not baseline_path.exists():
        return sorted(current)
    baseline = project_hashes(baseline_path)
    return sorted(path for path, digest in current.items() if baseline.get(path) != digest)


def project_digest(project_path: Path) -> str:
    payload = json.dumps(project_hashes(project_path), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finding_fingerprint(item: dict[str, Any]) -> str:
    fields = (
        str(item.get("source", "")).lower(),
        str(item.get("title", "")).lower(),
        str(item.get("file_path", "")).replace("\\", "/").lower(),
        str(item.get("cwe_id", "")).lower(),
    )
    return hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()


def compare_findings(current: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    current_map = {finding_fingerprint(item): item for item in current}
    baseline_map = {finding_fingerprint(item): item for item in baseline}
    return {
        "new_findings": [current_map[key] for key in sorted(current_map.keys() - baseline_map.keys())],
        "unchanged_findings": [current_map[key] for key in sorted(current_map.keys() & baseline_map.keys())],
        "resolved_findings": [baseline_map[key] for key in sorted(baseline_map.keys() - current_map.keys())],
    }
