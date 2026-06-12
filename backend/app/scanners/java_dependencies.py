from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import yaml

from backend.app.services.java_audit_skill import resolve_java_audit_skills_root


SKILL_RULES_RELATIVE_PATH = Path("java-vuln-scanner") / "references" / "java-vulnerability.yaml"
PLACEHOLDER_PATTERN = re.compile(r"\$\{([^}]+)\}")
CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
GRADLE_COORDINATE_PATTERNS = (
    re.compile(
        r"""(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly)\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly)\s+group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    ),
)


@dataclass(frozen=True)
class Dependency:
    group_id: str
    artifact_id: str
    version: str
    file_path: str
    line_number: int

    @property
    def coordinate(self) -> str:
        return f"{self.group_id}:{self.artifact_id}:{self.version}".strip(":")


@dataclass(frozen=True)
class Rule:
    severity: str
    name: str
    description: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class PomModel:
    properties: dict[str, str]
    managed_versions: dict[tuple[str, str], str]
    dependencies: tuple[Dependency, ...]
    group_id: str
    artifact_id: str
    version: str


@dataclass(frozen=True)
class SupplementalRule:
    artifact_names: frozenset[str]
    max_version: tuple[int, ...]
    severity: str
    title: str
    description: str
    owasp_id: str
    cwe_id: str


SUPPLEMENTAL_RULES = (
    SupplementalRule(
        artifact_names=frozenset({"commons-io"}),
        max_version=(2, 14, 0),
        severity="MEDIUM",
        title="Apache Commons IO 路径遍历漏洞 (CVE-2024-47554)",
        description="Apache Commons IO 低版本存在路径遍历风险，建议升级到 2.15.0 及以上版本。",
        owasp_id="A01:2021",
        cwe_id="CWE-22",
    ),
    SupplementalRule(
        artifact_names=frozenset({"poi", "poi-ooxml"}),
        max_version=(5, 2, 3),
        severity="MEDIUM",
        title="Apache POI XXE 漏洞 (CVE-2024-26308)",
        description="Apache POI 低版本存在 XXE 风险，建议升级到 5.2.4 及以上版本。",
        owasp_id="A05:2021",
        cwe_id="CWE-611",
    ),
)


def _skill_rules_path() -> Path | None:
    root = resolve_java_audit_skills_root()
    if root is None:
        return None
    path = root / SKILL_RULES_RELATIVE_PATH
    return path if path.exists() else None


def _normalize_severity(value: str) -> str:
    severity = value.strip().upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"


@lru_cache(maxsize=1)
def _load_rules() -> tuple[Rule, ...]:
    rules_path = _skill_rules_path()
    if rules_path is None:
        return ()

    try:
        payload = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ()

    rules: list[Rule] = []
    for severity, entries in (payload or {}).get("rules", {}).items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            pattern = str(entry.get("pattern", "")).strip()
            name = str(entry.get("name", "")).strip()
            description = str(entry.get("description", "")).strip()
            if not pattern or not name:
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            rules.append(
                Rule(
                    severity=_normalize_severity(severity),
                    name=name,
                    description=description,
                    pattern=compiled,
                )
            )
    return tuple(rules)


def _pom_namespace(root: ET.Element) -> str:
    return root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""


def _find_child_text(element: ET.Element, tag: str, namespace: str) -> str:
    return (element.findtext(f"{namespace}{tag}") or "").strip()


def _resolve_parent_pom(pom_path: Path, root: ET.Element, namespace: str) -> Path | None:
    parent = root.find(f"{namespace}parent")
    if parent is None:
        return None

    relative_path = _find_child_text(parent, "relativePath", namespace) or "../pom.xml"
    candidate = (pom_path.parent / relative_path).resolve()
    return candidate if candidate.exists() else None


def _resolve_placeholders(value: str, properties: dict[str, str]) -> str:
    resolved = value
    for _ in range(10):
        match = PLACEHOLDER_PATTERN.search(resolved)
        if match is None:
            break
        replacement = properties.get(match.group(1), "")
        if not replacement or replacement == resolved:
            break
        resolved = resolved.replace(match.group(0), replacement)
    return resolved.strip()


def _line_number_for_dependency(pom_path: Path, artifact_id: str, version: str) -> int:
    try:
        lines = pom_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 1

    artifact_marker = f"<artifactId>{artifact_id}</artifactId>"
    version_marker = f"<version>{version}</version>"
    artifact_line = 0
    for index, line in enumerate(lines, start=1):
        lowered_line = line.lower()
        if artifact_marker.lower() in lowered_line:
            artifact_line = index
            break
    if not artifact_line:
        return 1

    for index in range(artifact_line, min(artifact_line + 6, len(lines) + 1)):
        if version_marker.lower() in lines[index - 1].lower():
            return index
    return artifact_line


@lru_cache(maxsize=512)
def _parse_pom(pom_path: Path) -> PomModel:
    tree = ET.parse(pom_path)
    root = tree.getroot()
    namespace = _pom_namespace(root)

    parent_model: PomModel | None = None
    parent_path = _resolve_parent_pom(pom_path, root, namespace)
    if parent_path is not None:
        parent_model = _parse_pom(parent_path)

    properties = dict(parent_model.properties) if parent_model is not None else {}
    managed_versions = dict(parent_model.managed_versions) if parent_model is not None else {}

    group_id = _find_child_text(root, "groupId", namespace) or (parent_model.group_id if parent_model else "")
    artifact_id = _find_child_text(root, "artifactId", namespace)
    version = _find_child_text(root, "version", namespace) or (parent_model.version if parent_model else "")

    properties.update(
        {
            "project.groupId": group_id,
            "project.artifactId": artifact_id,
            "project.version": version,
            "groupId": group_id,
            "artifactId": artifact_id,
            "version": version,
        }
    )

    properties_node = root.find(f"{namespace}properties")
    if properties_node is not None:
        for child in properties_node:
            properties[child.tag.replace(namespace, "")] = (child.text or "").strip()

    for _ in range(10):
        changed = False
        for key, current in list(properties.items()):
            resolved = _resolve_placeholders(current, properties)
            if resolved != current:
                properties[key] = resolved
                changed = True
        if not changed:
            break

    def resolve_version(value: str) -> str:
        return _resolve_placeholders(value, properties)

    dependency_sections = (
        root.findall(f"{namespace}dependencyManagement/{namespace}dependencies/{namespace}dependency"),
        root.findall(f"{namespace}dependencies/{namespace}dependency"),
    )

    for dependency in dependency_sections[0]:
        group = _find_child_text(dependency, "groupId", namespace)
        artifact = _find_child_text(dependency, "artifactId", namespace)
        version_value = resolve_version(_find_child_text(dependency, "version", namespace))
        if group and artifact and version_value:
            managed_versions[(group, artifact)] = version_value

    dependencies: list[Dependency] = []
    relative_path = pom_path.as_posix()
    for dependency in dependency_sections[1]:
        group = _find_child_text(dependency, "groupId", namespace)
        artifact = _find_child_text(dependency, "artifactId", namespace)
        version_value = resolve_version(_find_child_text(dependency, "version", namespace))
        if not version_value and group and artifact:
            version_value = managed_versions.get((group, artifact), "")
        if not artifact or not version_value:
            continue
        dependencies.append(
            Dependency(
                group_id=group,
                artifact_id=artifact,
                version=version_value,
                file_path=relative_path,
                line_number=_line_number_for_dependency(pom_path, artifact, version_value),
            )
        )

    return PomModel(
        properties=properties,
        managed_versions=managed_versions,
        dependencies=tuple(dependencies),
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
    )


def _iter_pom_dependencies(project_path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for pom_path in sorted(project_path.rglob("pom.xml")):
        if any(part.lower() in {"target", "build", ".idea", "__macosx"} for part in pom_path.parts):
            continue
        try:
            relative_path = pom_path.relative_to(project_path).as_posix()
            dependencies.extend(
                Dependency(
                    group_id=item.group_id,
                    artifact_id=item.artifact_id,
                    version=item.version,
                    file_path=relative_path,
                    line_number=item.line_number,
                )
                for item in _parse_pom(pom_path).dependencies
            )
        except (ET.ParseError, OSError):
            continue
    return dependencies


def _iter_gradle_dependencies(project_path: Path) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for gradle_path in sorted([*project_path.rglob("build.gradle"), *project_path.rglob("build.gradle.kts")]):
        if any(part.lower() in {"target", "build", ".idea", "__macosx"} for part in gradle_path.parts):
            continue
        try:
            content = gradle_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative_path = gradle_path.relative_to(project_path).as_posix()
        lines = content.splitlines()
        for pattern in GRADLE_COORDINATE_PATTERNS:
            for match in pattern.finditer(content):
                group_id, artifact_id, version = (item.strip() for item in match.groups())
                line_number = content[: match.start()].count("\n") + 1
                if not line_number and lines:
                    line_number = 1
                dependencies.append(
                    Dependency(
                        group_id=group_id,
                        artifact_id=artifact_id,
                        version=version,
                        file_path=relative_path,
                        line_number=line_number,
                    )
                )
    return dependencies


def _infer_owasp_id(rule_name: str, description: str) -> str:
    haystack = f"{rule_name} {description}".lower()
    if any(token in haystack for token in ("sql", "注入")):
        return "A03:2021"
    if any(token in haystack for token in ("xxe", "xml")):
        return "A05:2021"
    if any(token in haystack for token in ("ssrf",)):
        return "A10:2021"
    if any(token in haystack for token in ("rememberme", "deserialization", "反序列化", "jndi", "gadget")):
        return "A08:2021"
    if any(token in haystack for token in ("authorization", "access control", "权限", "越权")):
        return "A01:2021"
    if any(token in haystack for token in ("authentication", "认证", "login", "jwt")):
        return "A07:2021"
    if any(token in haystack for token in ("path traversal", "文件读取", "download", "directory traversal")):
        return "A01:2021"
    return "A06:2021"


def _infer_cwe_id(owasp_id: str, rule_name: str, description: str) -> str:
    haystack = f"{rule_name} {description}".lower()
    if "sql" in haystack:
        return "CWE-89"
    if "xxe" in haystack:
        return "CWE-611"
    if "ssrf" in haystack:
        return "CWE-918"
    if any(token in haystack for token in ("deserialization", "反序列化", "rememberme")):
        return "CWE-502"
    if owasp_id == "A01:2021":
        return "CWE-284"
    if owasp_id == "A07:2021":
        return "CWE-287"
    return "CWE-1104"


def _references_for_rule(rule_name: str) -> list[str]:
    references: list[str] = []
    for cve_id in CVE_PATTERN.findall(rule_name):
        references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}")
    return references


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    parts = [int(item) for item in re.findall(r"\d+", version)]
    return tuple(parts[:4]) if parts else (0,)


def _matches_supplemental_rule(dependency: Dependency, rule: SupplementalRule) -> bool:
    if dependency.artifact_id.lower() not in rule.artifact_names:
        return False
    return _parse_version_tuple(dependency.version) <= rule.max_version


def _deduplicate_dependencies(items: list[Dependency]) -> list[Dependency]:
    deduped: dict[tuple[str, str, str, str, int], Dependency] = {}
    for item in items:
        key = (item.group_id, item.artifact_id, item.version, item.file_path, item.line_number)
        deduped[key] = item
    return list(deduped.values())


def run(project_path: Path) -> list[dict[str, object]]:
    rules = _load_rules()
    if not rules:
        return []

    dependencies = _deduplicate_dependencies(
        [
            *_iter_pom_dependencies(project_path),
            *_iter_gradle_dependencies(project_path),
        ]
    )

    findings: list[dict[str, object]] = []
    for dependency in dependencies:
        check_value = f"{dependency.artifact_id}:{dependency.version}"
        for rule in rules:
            if not rule.pattern.search(check_value):
                continue
            owasp_id = _infer_owasp_id(rule.name, rule.description)
            findings.append(
                {
                    "source": "JavaVulnSkill",
                    "severity": rule.severity,
                    "title": rule.name,
                    "description": rule.description,
                    "file_path": dependency.file_path,
                    "line_number": dependency.line_number,
                    "cvss_score": 0.0,
                    "owasp_id": owasp_id,
                    "cwe_id": _infer_cwe_id(owasp_id, rule.name, rule.description),
                    "references": _references_for_rule(rule.name),
                    "evidence": dependency.coordinate,
                    "metadata": {
                        "coordinate": dependency.coordinate,
                        "dependency": dependency.artifact_id,
                        "version": dependency.version,
                        "group_id": dependency.group_id,
                        "rule_source": "java-vuln-scanner",
                        "scanner": "java_dependencies",
                        "marker": f"{dependency.artifact_id}:{dependency.version}",
                    },
                }
            )

        for supplemental_rule in SUPPLEMENTAL_RULES:
            if not _matches_supplemental_rule(dependency, supplemental_rule):
                continue
            findings.append(
                {
                    "source": "JavaVulnSkill",
                    "severity": supplemental_rule.severity,
                    "title": supplemental_rule.title,
                    "description": supplemental_rule.description,
                    "file_path": dependency.file_path,
                    "line_number": dependency.line_number,
                    "cvss_score": 0.0,
                    "owasp_id": supplemental_rule.owasp_id,
                    "cwe_id": supplemental_rule.cwe_id,
                    "references": _references_for_rule(supplemental_rule.title),
                    "evidence": dependency.coordinate,
                    "metadata": {
                        "coordinate": dependency.coordinate,
                        "dependency": dependency.artifact_id,
                        "version": dependency.version,
                        "group_id": dependency.group_id,
                        "rule_source": "java-vuln-scanner-supplemental",
                        "scanner": "java_dependencies",
                        "marker": f"{dependency.artifact_id}:{dependency.version}",
                    },
                }
            )

    return findings
