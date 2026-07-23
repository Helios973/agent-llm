from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Session

from backend.app.core.database import Base
from backend.app.api.routes.admin import clear_admin_audit_logs
from backend.app.models import AdminAuditLog, AuditTask, LLMUsage, User
from backend.app.schemas.auth import AdminAuditLogClearRequest
from backend.app.services.auth_service import create_access_token, get_user_from_token, revoke_session, token_session_id
from backend.app.services.incremental import changed_project_files, compare_findings, project_digest
from backend.app.services.llm_providers import extract_model_ids, get_provider_adapter
from backend.app.services.llm_usage import usage_analytics
from backend.app.services.taint_analysis import analyze_project


class PlatformUpgradeTests(unittest.TestCase):
    def test_changed_file_inventory_uses_mysql_longtext(self) -> None:
        column_type = AuditTask.__table__.c.changed_files_json.type.compile(dialect=mysql.dialect())
        self.assertEqual(column_type.upper(), "LONGTEXT")

    def test_incremental_hash_and_finding_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            baseline = root_path / "baseline"
            current = root_path / "current"
            baseline.mkdir()
            current.mkdir()
            (baseline / "same.py").write_text("x = 1\n", encoding="utf-8")
            (current / "same.py").write_text("x = 1\n", encoding="utf-8")
            (current / "new.py").write_text("x = 2\n", encoding="utf-8")
            self.assertEqual(changed_project_files(current, baseline), ["new.py"])
            self.assertEqual(len(project_digest(current)), 64)

        old = {"source": "S", "title": "A", "file_path": "a.py", "cwe_id": "CWE-1"}
        new = {"source": "S", "title": "B", "file_path": "b.py", "cwe_id": "CWE-2"}
        result = compare_findings([old, new], [old])
        self.assertEqual(result["unchanged_findings"], [old])
        self.assertEqual(result["new_findings"], [new])
        self.assertEqual(result["resolved_findings"], [])

    def test_taint_call_chain_marks_source_to_sink(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            project = Path(root)
            (project / "app.py").write_text(
                "def sink(value):\n    return eval(value)\n\n"
                "def endpoint(request):\n    value = request.query_params['q']\n    return sink(value)\n",
                encoding="utf-8",
            )
            findings = analyze_project(project)
        self.assertTrue(any(item["source"] == "TaintFlow" for item in findings))
        self.assertTrue(any(item["metadata"]["function"] == "endpoint" for item in findings))

    def test_provider_adapters_and_model_formats(self) -> None:
        azure = get_provider_adapter("azure-openai")
        self.assertEqual(azure.auth_headers("secret")["api-key"], "secret")
        ollama = get_provider_adapter("ollama")
        self.assertNotIn("Authorization", ollama.auth_headers(""))
        self.assertEqual(
            extract_model_ids({"models": [{"name": "qwen3"}, {"model": "llama3"}]}),
            ["llama3", "qwen3"],
        )

    def test_persisted_session_can_be_revoked(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine, expire_on_commit=False) as db:
            user = User(
                id="10000000-0000-0000-0000-000000000001",
                username="session-user",
                email="session@example.com",
                is_active=True,
            )
            db.add(user)
            db.commit()
            token = create_access_token(user, db, user_agent="unit-test", ip_address="127.0.0.1")
            self.assertEqual(get_user_from_token(db, token).id, user.id)
            session_id = token_session_id(token)
            self.assertIsNotNone(session_id)
            self.assertTrue(revoke_session(db, session_id or "", user.id))
            self.assertIsNone(get_user_from_token(db, token))

    def test_usage_analytics_aggregates_models_and_heatmap(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        now = datetime.now(timezone.utc)
        with Session(engine) as db:
            user = User(id="usage-user", username="usage-user", email="usage@example.com", is_active=True)
            db.add(user)
            db.add_all(
                [
                    LLMUsage(id="usage-1", user_id=user.id, task_id="task-1", provider="openai", model="gpt-test", input_tokens=80, output_tokens=20, total_tokens=100, created_at=now - timedelta(days=1)),
                    LLMUsage(id="usage-2", user_id=user.id, task_id="task-1", provider="openai", model="gpt-test", input_tokens=40, output_tokens=10, total_tokens=50, created_at=now),
                    LLMUsage(id="usage-3", user_id=user.id, task_id="task-2", provider="ollama", model="qwen-test", input_tokens=25, output_tokens=25, total_tokens=50, created_at=now),
                ]
            )
            db.commit()
            result = usage_analytics(db, user.id, "7d")
        self.assertEqual(result["sessions"], 2)
        self.assertEqual(result["messages"], 6)
        self.assertEqual(result["total_tokens"], 200)
        self.assertEqual(result["active_days"], 2)
        self.assertEqual(len(result["heatmap"]), 7)
        self.assertEqual(result["favorite_model"], "gpt-test")
        self.assertEqual(result["models"][0]["total_tokens"], 150)

    def test_admin_can_clear_selected_or_all_operation_logs(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            admin = User(id="admin-user", username="admin-user", email="admin@example.com", role="admin", is_active=True)
            db.add_all([
                admin,
                AdminAuditLog(id="log-1", admin_user_id=admin.id, action="user.update", target_type="user"),
                AdminAuditLog(id="log-2", admin_user_id=admin.id, action="task.stop", target_type="audit_task"),
            ])
            db.commit()
            result = clear_admin_audit_logs(AdminAuditLogClearRequest(ids=["log-1"]), db, admin)
            self.assertEqual(result["deleted_count"], 1)
            self.assertIsNone(db.get(AdminAuditLog, "log-1"))
            self.assertIsNotNone(db.get(AdminAuditLog, "log-2"))
            result = clear_admin_audit_logs(AdminAuditLogClearRequest(clear_all=True), db, admin)
            self.assertEqual(result["deleted_count"], 1)
            self.assertIsNone(db.get(AdminAuditLog, "log-2"))


if __name__ == "__main__":
    unittest.main()
