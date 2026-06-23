from __future__ import annotations

import shutil
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, is_zipfile

from fastapi import UploadFile

from backend.app.core.config import settings


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2")
REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class SavedUploadBundle:
    path: Path
    names: list[str]


def _normalized_relative_path(filename: str | None) -> Path:
    raw_name = (filename or "upload.bin").replace("\\", "/")
    safe_parts = [part for part in PurePosixPath(raw_name).parts if part not in {"", ".", "..", "/"}]
    if not safe_parts:
        return Path("upload.bin")
    return Path(*safe_parts)


def _archive_member_destination(project_dir: Path, member_name: str) -> Path:
    normalized_name = (member_name or "").replace("\\", "/")
    normalized_path = PurePosixPath(normalized_name)
    if not normalized_path.parts:
        raise ValueError("Archive contains an empty path entry")
    if normalized_path.is_absolute() or normalized_name.startswith("/"):
        raise ValueError("Archive contains an absolute path entry")
    if normalized_path.parts[0].endswith(":"):
        raise ValueError("Archive contains a drive-qualified path entry")
    if any(part in {"", ".", ".."} for part in normalized_path.parts):
        raise ValueError("Archive contains a path traversal entry")

    project_root = project_dir.resolve()
    destination = (project_root / Path(*normalized_path.parts)).resolve()
    if destination != project_root and project_root not in destination.parents:
        raise ValueError("Archive extraction escaped the project directory")
    return destination


def _extract_zip_archive(upload_path: Path, project_dir: Path) -> None:
    with ZipFile(upload_path) as archive:
        for info in archive.infolist():
            destination = _archive_member_destination(project_dir, info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("Archive contains an unsupported symbolic link entry")
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)


def _extract_tar_archive(upload_path: Path, project_dir: Path) -> None:
    with tarfile.open(upload_path) as archive:
        for member in archive.getmembers():
            destination = _archive_member_destination(project_dir, member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("Archive contains an unsupported special entry")
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue

            source = archive.extractfile(member)
            if source is None:
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)


def _extract_archive(upload_path: Path, project_dir: Path) -> None:
    if tarfile.is_tarfile(upload_path):
        _extract_tar_archive(upload_path, project_dir)
        return
    if is_zipfile(upload_path):
        _extract_zip_archive(upload_path, project_dir)
        return
    raise ValueError("Unsupported archive format")


async def _write_upload(upload: UploadFile, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("wb") as buffer:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            buffer.write(chunk)
    await upload.close()


async def save_upload(task_id: str, upload: UploadFile) -> Path:
    bundle = await save_uploads(task_id, [upload])
    return bundle.path


async def save_uploads(task_id: str, uploads: list[UploadFile]) -> SavedUploadBundle:
    if not uploads:
        raise ValueError("No uploads provided")

    settings.ensure_directories()
    target_dir = settings.upload_root / task_id
    target_dir.mkdir(parents=True, exist_ok=True)

    normalized_names = [_normalized_relative_path(upload.filename) for upload in uploads]
    normalized_name_strings = [path.as_posix() for path in normalized_names]
    if len(set(normalized_name_strings)) != len(normalized_name_strings):
        raise ValueError("Duplicate upload paths detected in request")

    if len(uploads) == 1 and len(normalized_names[0].parts) == 1:
        target_path = target_dir / normalized_names[0]
        await _write_upload(uploads[0], target_path)
        return SavedUploadBundle(path=target_path, names=normalized_name_strings)

    bundle_dir = target_dir / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    for upload, relative_path in zip(uploads, normalized_names, strict=True):
        await _write_upload(upload, bundle_dir / relative_path)
    return SavedUploadBundle(path=bundle_dir, names=normalized_name_strings)


def build_demo_upload(task_id: str) -> Path:
    settings.ensure_directories()
    source_dir = REPO_ROOT / "examples" / "vulnerable_python_app"
    if not source_dir.exists():
        raise FileNotFoundError(source_dir)

    target_dir = settings.upload_root / task_id
    target_dir.mkdir(parents=True, exist_ok=True)
    archive_path = target_dir / "vulnerable_python_app.zip"

    with ZipFile(archive_path, mode="w", compression=ZIP_DEFLATED) as archive:
        for file_path in source_dir.rglob("*"):
            if file_path.is_file():
                archive.write(file_path, arcname=file_path.relative_to(source_dir.parent))

    return archive_path


def prepare_project_path(task_id: str) -> Path:
    project_dir = settings.project_root / task_id
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


def extract_project(task_id: str, upload_path: Path) -> Path:
    project_dir = prepare_project_path(task_id)
    if upload_path.is_dir():
        shutil.copytree(upload_path, project_dir, dirs_exist_ok=True)
        return project_dir

    lowered_name = upload_path.name.lower()
    if lowered_name.endswith(ARCHIVE_SUFFIXES):
        _extract_archive(upload_path, project_dir)
        return project_dir

    shutil.copy2(upload_path, project_dir / upload_path.name)
    return project_dir


def list_project_files(project_path: Path) -> list[Path]:
    return [path for path in project_path.rglob("*") if path.is_file()]
