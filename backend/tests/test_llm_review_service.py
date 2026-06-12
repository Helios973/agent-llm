from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.app.services.code_security_skill import apply_hard_exclusion_filters, load_code_security_skill_resources
from backend.app.services.llm_review_service import (
    _build_user_prompt,
    _normalize_filter_summary,
    _normalize_findings,
    ReviewContextMemory,
    build_review_context_memory,
)


class ReviewContextMemoryTests(unittest.TestCase):
    def test_build_review_context_memory_collects_linked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            (project_path / "api.py").write_text(
                "\n".join(
                    [
                        "from service import process_user",
                        "",
                        "def handle(payload):",
                        "    return process_user(payload['name'])",
                    ]
                ),
                encoding="utf-8",
            )
            (project_path / "service.py").write_text(
                "\n".join(
                    [
                        "from db import run_query",
                        "",
                        "def process_user(name):",
                        "    sql = f\"select * from users where name = '{name}'\"",
                        "    return run_query(sql)",
                    ]
                ),
                encoding="utf-8",
            )
            (project_path / "db.py").write_text(
                "\n".join(
                    [
                        "def run_query(sql):",
                        "    return cursor.execute(sql)",
                    ]
                ),
                encoding="utf-8",
            )

            memory = build_review_context_memory(
                project_path=project_path,
                language="python",
                entrypoint="api.py",
                scan_results=[
                    {
                        "source": "Semgrep",
                        "severity": "HIGH",
                        "title": "Possible SQL injection",
                        "description": "user input reaches SQL string construction",
                        "file_path": "service.py",
                        "line_number": 4,
                        "cvss_score": 0.0,
                    }
                ],
            )

        selected_paths = {context_file.path for context_file in memory.files}
        self.assertIn("service.py", selected_paths)
        self.assertIn("api.py", selected_paths)
        self.assertIn("db.py", selected_paths)
        self.assertIn("entrypoint: api.py", memory.summary)
        self.assertTrue(any(note.startswith("service.py ->") for note in memory.relationship_notes))

    def test_bundled_skill_resources_are_injected_into_prompt(self) -> None:
        resources = load_code_security_skill_resources()
        memory = ReviewContextMemory(files=(), relationship_notes=(), summary="selected 0 linked files")

        prompt = _build_user_prompt(
            task_name="demo-audit",
            language="python",
            framework="fastapi",
            entrypoint="main.py",
            scan_results=[],
            context_memory=memory,
            resources=resources,
            excluded_scan_summaries=[],
            java_skill_addendum="",
        )

        self.assertIn("Bundled Filtering Rules:", prompt)
        self.assertIn("Only keep findings with confidence score", prompt)
        self.assertIn("Hard Exclusion Patterns", prompt)

    def test_hard_exclusion_filters_markdown_and_rate_limit_findings(self) -> None:
        findings = [
            {
                "title": "Missing rate limit on login",
                "description": "Add rate limiting to prevent abuse",
                "file_path": "api.py",
            },
            {
                "title": "Potential SSRF",
                "description": "User controls outbound request host",
                "file_path": "README.md",
            },
            {
                "title": "SQL Injection",
                "description": "User input reaches SQL string construction",
                "file_path": "service.py",
            },
        ]

        kept, excluded = apply_hard_exclusion_filters(findings)

        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["title"], "SQL Injection")
        self.assertEqual(len(excluded), 2)
        self.assertTrue(any(item["reason"] == "Generic rate limiting recommendation" for item in excluded))
        self.assertTrue(any(item["reason"] == "Finding in Markdown documentation file" for item in excluded))

    def test_low_confidence_findings_are_removed_after_filtering(self) -> None:
        filter_summary = _normalize_filter_summary(
            [
                {
                    "title": "Potential SQL injection",
                    "file_path": "service.py",
                    "decision": "EXCLUDE",
                    "confidence_score": 5,
                    "reason": "Needs stronger exploit path",
                },
                {
                    "title": "Command injection",
                    "file_path": "worker.py",
                    "decision": "KEEP",
                    "confidence_score": 9,
                    "reason": "Concrete untrusted shell input",
                },
            ]
        )

        findings = _normalize_findings(
            [
                {
                    "title": "Potential SQL injection",
                    "description": "desc",
                    "file_path": "service.py",
                    "line_number": 12,
                    "severity": "HIGH",
                },
                {
                    "title": "Command injection",
                    "description": "desc",
                    "file_path": "worker.py",
                    "line_number": 8,
                    "severity": "HIGH",
                    "confidence_score": 9,
                    "attack_path": "attacker controls shell args",
                },
            ],
            filter_summary,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Command injection")
        self.assertEqual(findings[0]["metadata"]["confidence_score"], 9)
        self.assertEqual(findings[0]["metadata"]["review_skill"], "code-security-review")


if __name__ == "__main__":
    unittest.main()
