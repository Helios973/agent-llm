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
        files = [info for info in archive.infolist() if not info.is_dir()]
        total_size = sum(info.file_size for info in files)
        if len(files) > settings.extraction_max_files:
            raise ValueError("Archive contains too many files")
        if total_size > settings.extraction_max_total_bytes:
            raise ValueError("Archive expands beyond the configured size limit")
        for info in files:
            compressed = max(info.compress_size, 1)
            if info.file_size / compressed > settings.extraction_max_ratio:
                raise ValueError("Archive contains an excessive compression ratio")
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
        members = archive.getmembers()
        files = [member for member in members if member.isfile()]
        if len(files) > settings.extraction_max_files:
            raise ValueError("Archive contains too many files")
        if sum(member.size for member in files) > settings.extraction_max_total_bytes:
            raise ValueError("Archive expands beyond the configured size limit")
        for member in members:
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


async def _write_upload(upload: UploadFile, target_path: Path, remaining_total: int) -> int:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target_path.open("wb") as buffer:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > settings.upload_max_file_bytes:
                raise ValueError(f"Upload exceeds per-file limit: {upload.filename}")
            if written > remaining_total:
                raise ValueError("Uploads exceed the configured total size limit")
            buffer.write(chunk)
    await upload.close()
    return written


async def save_upload(task_id: str, upload: UploadFile) -> Path:
    bundle = await save_uploads(task_id, [upload])
    return bundle.path


async def save_uploads(
    task_id: str,
    uploads: list[UploadFile],
    *,
    max_total_bytes: int | None = None,
) -> SavedUploadBundle:
    if not uploads:
        raise ValueError("No uploads provided")
    if len(uploads) > settings.upload_max_files:
        raise ValueError("Too many files in one upload request")

    settings.ensure_directories()
    target_dir = settings.upload_root / task_id
    target_dir.mkdir(parents=True, exist_ok=True)

    normalized_names = [_normalized_relative_path(upload.filename) for upload in uploads]
    normalized_name_strings = [path.as_posix() for path in normalized_names]
    if len(set(normalized_name_strings)) != len(normalized_name_strings):
        raise ValueError("Duplicate upload paths detected in request")

    total_limit = min(max_total_bytes or settings.upload_max_total_bytes, settings.upload_max_total_bytes)
    written_total = 0
    try:
        if len(uploads) == 1 and len(normalized_names[0].parts) == 1:
            target_path = target_dir / normalized_names[0]
            await _write_upload(uploads[0], target_path, total_limit)
            return SavedUploadBundle(path=target_path, names=normalized_name_strings)

        bundle_dir = target_dir / "bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        for upload, relative_path in zip(uploads, normalized_names, strict=True):
            written_total += await _write_upload(upload, bundle_dir / relative_path, total_limit - written_total)
        return SavedUploadBundle(path=bundle_dir, names=normalized_name_strings)
    except Exception:
        shutil.rmtree(target_dir, ignore_errors=True)
        for upload in uploads:
            await upload.close()
        raise


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
    try:
        if upload_path.is_dir():
            shutil.copytree(upload_path, project_dir, dirs_exist_ok=True)
            return project_dir

        lowered_name = upload_path.name.lower()
        if lowered_name.endswith(ARCHIVE_SUFFIXES):
            _extract_archive(upload_path, project_dir)
            return project_dir

        shutil.copy2(upload_path, project_dir / upload_path.name)
        return project_dir
    except Exception:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise


def list_project_files(project_path: Path) -> list[Path]:
    return [path for path in project_path.rglob("*") if path.is_file()]


def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError:
                continue
    return total


def user_storage_usage(tasks: list[object]) -> int:
    seen: set[Path] = set()
    total = 0
    for task in tasks:
        for value in (getattr(task, "upload_path", None), getattr(task, "project_path", None), getattr(task, "report_dir", None)):
            if not value:
                continue
            path = Path(value).resolve()
            if path in seen:
                continue
            seen.add(path)
            total += path_size(path)
    return total
