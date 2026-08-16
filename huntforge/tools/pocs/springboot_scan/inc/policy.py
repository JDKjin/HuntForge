from __future__ import annotations

import os
import stat
from pathlib import Path


TLS_VERIFY = True


def _is_reparse_point(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(metadata, "st_file_attributes", 0) & marker)


def _reject_link_or_special(path: Path, *, expect_directory: bool) -> None:
    metadata = path.lstat()
    if path.is_symlink() or _is_reparse_point(metadata):
        raise ValueError(f"路径不得包含符号链接或重解析点: {path}")
    expected = (
        stat.S_ISDIR(metadata.st_mode)
        if expect_directory
        else stat.S_ISREG(metadata.st_mode)
    )
    if not expected:
        kind = "目录" if expect_directory else "普通文件"
        raise ValueError(f"路径必须是{kind}: {path}")


def configure_tls(*, insecure: bool = False) -> None:
    """默认校验证书，仅在本次运行显式选择 insecure 时关闭。"""
    global TLS_VERIFY
    TLS_VERIFY = not insecure


def resolve_output_path(raw_output: str, *, cwd: Path | None = None) -> Path:
    """将输出解析为当前工作目录内的普通文件。"""
    root = (cwd or Path.cwd()).resolve(strict=True)
    raw_path = Path(raw_output)
    unresolved = raw_path if raw_path.is_absolute() else root / raw_path
    if unresolved.is_symlink():
        raise ValueError("--output 不得是符号链接")
    candidate = unresolved.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("--output 必须位于当前工作目录内") from exc
    if candidate.exists() and not candidate.is_file():
        raise ValueError("--output 必须是普通文件路径")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def resolve_artifact_dir(
    raw_directory: str | os.PathLike[str],
    *,
    cwd: Path | None = None,
) -> Path:
    """创建并验证当前工作目录内的单次运行产物目录。"""
    root = (cwd or Path.cwd()).resolve(strict=True)
    raw_path = Path(raw_directory)
    unresolved = raw_path if raw_path.is_absolute() else root / raw_path
    try:
        relative = unresolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("--artifact-dir 必须位于当前工作目录内") from exc
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("--artifact-dir 不得包含路径逃逸段")

    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _reject_link_or_special(current, expect_directory=True)
        else:
            current.mkdir()

    resolved = unresolved.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("--artifact-dir 解析后逃逸当前工作目录") from exc
    if resolved != unresolved.absolute():
        raise ValueError("--artifact-dir 不得通过链接或重解析点解析")
    return resolved


def artifact_path(
    artifact_dir: str | os.PathLike[str],
    filename: str,
) -> Path:
    """返回产物目录内的直接子文件，并拒绝链接、特殊文件和路径逃逸。"""
    if not filename or Path(filename).name != filename:
        raise ValueError("产物文件名必须是单一文件名")
    directory = resolve_artifact_dir(artifact_dir)
    path = directory / filename
    if path.exists() or path.is_symlink():
        _reject_link_or_special(path, expect_directory=False)
    return path


def append_artifact(
    artifact_dir: str | os.PathLike[str],
    filename: str,
    text: str,
) -> Path:
    path = artifact_path(artifact_dir, filename)
    with path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(text)
    return path


def reset_artifact(
    artifact_dir: str | os.PathLike[str],
    filename: str,
) -> Path:
    path = artifact_path(artifact_dir, filename)
    path.write_text("", encoding="utf-8")
    return path
