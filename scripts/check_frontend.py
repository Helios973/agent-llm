"""Dependency-free frontend contract checks for the static AuditPilot UI."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
MOJIBAKE_MARKERS = ("鐧诲", "绠＄", "瀹¤", "浠诲", "婕忔", "锛", "銆", "鈥", "�")


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.duplicate_ids: set[str] = set()
        self.module_sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            if element_id in self.ids:
                self.duplicate_ids.add(element_id)
            self.ids.add(element_id)
        if tag == "script" and values.get("type") == "module" and values.get("src"):
            self.module_sources.append(values["src"])


def check_document(html_name: str, script_name: str) -> list[str]:
    failures: list[str] = []
    html_path = FRONTEND / html_name
    script_path = FRONTEND / "assets" / script_name
    parser = DocumentParser()
    parser.feed(html_path.read_text(encoding="utf-8"))

    if parser.duplicate_ids:
        failures.append(f"{html_name}: duplicate ids: {sorted(parser.duplicate_ids)}")

    script = script_path.read_text(encoding="utf-8")
    referenced_ids = set(re.findall(r'document\.getElementById\(["\']([^"\']+)["\']\)', script))
    missing_ids = sorted(referenced_ids - parser.ids)
    if missing_ids:
        failures.append(f"{html_name}: ids referenced by {script_name} are missing: {missing_ids}")

    expected_source = f"./assets/{script_name}"
    if not any(source.split("?", 1)[0] == expected_source for source in parser.module_sources):
        failures.append(f"{html_name}: {script_name} is not loaded as an ES module")
    return failures


def main() -> int:
    failures = [
        *check_document("index.html", "app.js"),
        *check_document("admin.html", "admin.js"),
    ]

    text_assets = [
        *FRONTEND.glob("*.html"),
        *FRONTEND.glob("*.md"),
        *FRONTEND.joinpath("assets").glob("*.js"),
        *FRONTEND.joinpath("assets").glob("*.css"),
    ]
    for path in text_assets:
        content = path.read_text(encoding="utf-8")
        markers = sorted({marker for marker in MOJIBAKE_MARKERS if marker in content})
        if markers:
            failures.append(f"{path.relative_to(ROOT)}: possible mojibake markers: {markers}")

    node = shutil.which("node")
    if node:
        for path in FRONTEND.joinpath("assets").glob("*.js"):
            result = subprocess.run(
                [node, "--check", str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode:
                failures.append(f"{path.relative_to(ROOT)}: {result.stderr.strip()}")

    if failures:
        print("Frontend checks failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"Frontend checks passed ({len(text_assets)} text assets validated).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
