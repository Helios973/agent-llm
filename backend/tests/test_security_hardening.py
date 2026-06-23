from __future__ import annotations

import hashlib
import hmac
import io
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import auth as auth_routes
from backend.app.core import database
from backend.app.core.config import settings
from backend.app.models import User
from backend.app.schemas.auth import RegisterRequest
from backend.app.services import auth_service, files, human_check


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        human_check.reset_human_check_state()

    def test_placeholder_auth_secret_is_not_accepted_for_token_signing(self) -> None:
        user = types.SimpleNamespace(id="user-123")
        with mock.patch.object(settings, "auth_secret_key", "change-me-local-auth-secret"):
            token = auth_service.create_access_token(user)
            self.assertEqual(auth_service.verify_access_token(token), "user-123")

            prefix, encoded_payload, _ = token.split(".", 2)
            forged_signature = hmac.new(
                b"change-me-local-auth-secret",
                encoded_payload.encode("ascii"),
                hashlib.sha256,
            ).digest()
            forged_token = f"{prefix}.{encoded_payload}.{auth_service._b64encode(forged_signature)}"
            self.assertIsNone(auth_service.verify_access_token(forged_token))

    def test_bootstrap_admin_requires_explicit_non_placeholder_password(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
        database.Base.metadata.create_all(bind=engine)

        with (
            mock.patch.object(database, "SessionLocal", session_factory),
            mock.patch.object(settings, "admin_bootstrap_username", "admin"),
            mock.patch.object(settings, "admin_bootstrap_email", "admin@example.com"),
            mock.patch.object(settings, "admin_bootstrap_password", "Admin123456!"),
        ):
            database._ensure_bootstrap_admin()

        with session_factory() as session:
            users = session.scalars(select(User)).all()
        self.assertEqual(users, [])

    def test_bootstrap_admin_creates_admin_when_explicitly_configured(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
        database.Base.metadata.create_all(bind=engine)

        with (
            mock.patch.object(database, "SessionLocal", session_factory),
            mock.patch.object(settings, "admin_bootstrap_username", "security-admin"),
            mock.patch.object(settings, "admin_bootstrap_email", "security-admin@example.com"),
            mock.patch.object(settings, "admin_bootstrap_password", "VeryStrongAdminPassword!42"),
            mock.patch.object(settings, "admin_bootstrap_reset_password", False),
        ):
            database._ensure_bootstrap_admin()

        with session_factory() as session:
            admin_user = session.scalar(select(User).where(User.username == "security-admin"))
        self.assertIsNotNone(admin_user)
        self.assertEqual(admin_user.role, "admin")
        self.assertTrue(admin_user.is_active)

    def test_extract_project_blocks_tar_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "evil.tar"
            outside_path = root / "outside.txt"
            payload = b"owned"

            with tarfile.open(archive_path, "w") as archive:
                info = tarfile.TarInfo("../outside.txt")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))

            with mock.patch.object(settings, "storage_root", root / "storage"):
                with self.assertRaises(ValueError):
                    files.extract_project("task-1", archive_path)

            self.assertFalse(outside_path.exists())

    def test_human_check_proof_is_single_use(self) -> None:
        with mock.patch.object(settings, "human_check_min_completion_ms", 0):
            challenge = human_check.issue_human_check_challenge()
            proof = human_check.verify_human_check_challenge(challenge.challenge_token)

        human_check.consume_human_check_proof(proof.proof_token)
        with self.assertRaises(HTTPException):
            human_check.consume_human_check_proof(proof.proof_token)

    def test_register_requires_server_side_human_check_proof(self) -> None:
        payload = RegisterRequest(
            username="newuser",
            email="newuser@example.com",
            password="StrongPass123!",
            human_check_proof="invalid-proof-token",
        )

        with self.assertRaises(HTTPException):
            auth_routes.register(payload, db=mock.MagicMock())


if __name__ == "__main__":
    unittest.main()
