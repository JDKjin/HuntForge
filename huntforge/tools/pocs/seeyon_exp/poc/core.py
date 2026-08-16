from __future__ import annotations

import json
import builtins
import os
import re
import stat
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning


REQUEST_TIMEOUT = (3.05, 10.0)
TLS_VERIFY = True

_output_path: Path | None = None
_output_root: Path | None = None


def configure_tls(*, insecure: bool = False) -> None:
    """Require certificate validation unless the CLI explicitly opts out."""
    global TLS_VERIFY
    TLS_VERIFY = not insecure


def _is_reparse_point(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(metadata, "st_file_attributes", 0) & marker)


def _reject_link_or_special(path: Path, *, expect_directory: bool) -> None:
    metadata = path.lstat()
    if path.is_symlink() or _is_reparse_point(metadata):
        raise ValueError(f"path must not contain a symlink/reparse point: {path}")
    expected = stat.S_ISDIR(metadata.st_mode) if expect_directory else stat.S_ISREG(
        metadata.st_mode
    )
    if not expected:
        kind = "directory" if expect_directory else "regular file"
        raise ValueError(f"path must be a {kind}: {path}")


def _prepare_parent(root: Path, parent: Path) -> None:
    try:
        relative = parent.relative_to(root)
    except ValueError as exc:
        raise ValueError("--output must stay inside the current working directory") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists():
            _reject_link_or_special(current, expect_directory=True)
        else:
            current.mkdir()
    if parent.resolve(strict=True) != parent:
        raise ValueError("--output parent must not resolve through a link")


def _open_output_fd(path: Path) -> int:
    if _output_root is None:
        raise RuntimeError("output root is not configured")
    _prepare_parent(_output_root, path.parent)
    if path.exists() or path.is_symlink():
        _reject_link_or_special(path, expect_directory=False)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        try:
            path.parent.resolve(strict=True).relative_to(_output_root)
        except ValueError as exc:
            raise ValueError("--output parent escaped during secure open") from exc
        if path.parent.resolve(strict=True) != path.parent:
            raise ValueError("--output parent changed during secure open")
        if (
            path.is_symlink()
            or _is_reparse_point(current)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError("--output changed during secure open")
        return fd
    except Exception:
        os.close(fd)
        raise


def configure_output(raw_output: str | os.PathLike[str], *, cwd: Path | None = None) -> Path:
    """Configure the only evidence file used by result()."""
    global _output_path, _output_root

    if not str(raw_output or "").strip():
        raise ValueError("--output is required")
    root = (cwd or Path.cwd()).resolve(strict=True)
    candidate = Path(raw_output).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("--output must stay inside the current working directory") from exc
    if candidate == root:
        raise ValueError("--output must name an evidence file")
    _prepare_parent(root, candidate.parent)

    _output_root = root
    _output_path = candidate
    fd = _open_output_fd(candidate)
    os.close(fd)
    return candidate


def evidence_path() -> str:
    if _output_path is None:
        raise RuntimeError("output is not configured; pass --output")
    return str(_output_path)


def result(name: str, payload: str, info: str | None = None) -> None:
    if _output_path is None:
        raise RuntimeError("output is not configured; pass --output")
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "name": str(name),
        "payload": str(payload),
    }
    if info is not None:
        record["info"] = str(info)
    line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    fd = _open_output_fd(_output_path)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _redact(value: object) -> str:
    text = str(value or "")
    substitutions = (
        (r"(?i)(JSESSIONID\s*=\s*)[^\s;,&]+", r"\1[REDACTED]"),
        (
            r"(?i)(\b(?:password|passwd|pwd|token|secret|api[_-]?key)\b\s*[=:]\s*)"
            r"[^\s;,&]+",
            r"\1[REDACTED]",
        ),
        (r"(?i)(\b(?:authorization|cookie)\s*:\s*)[^\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@"),
        (r"(?i)\b(?:rebeyond|asasd3344|WLCCYBD@SEEYON)\b", "[REDACTED]"),
    )
    for pattern, replacement in substitutions:
        text = re.sub(pattern, replacement, text)
    if "webshell" in text.lower():
        text = re.sub(r"https?://\S+", "[REDACTED_WEBSHELL_URL]", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def start_echo(name: str) -> None:
    print(f"[#] check: {_redact(name)}")


def end_echo(name: str, payload: str | None = None) -> None:
    if payload is not None:
        print(f"[#] finding: {_redact(name)}")
        print(f"[#] sensitive details written to: {evidence_path()}")
    else:
        print(f"[#] not found: {_redact(name)}")
    print("----------------------------------------------------")


def sensitive_success(name: str) -> None:
    print(f"[#] sensitive exploit evidence captured: {_redact(name)}")
    print(f"[#] evidence: {evidence_path()}")


def safe_print(*values: object, sep: str = " ", end: str = "\n", file=None, flush: bool = False) -> None:
    """Drop-in print replacement for legacy PoC modules with secret literals."""
    rendered = sep.join(str(value) for value in values)
    builtins.print(_redact(rendered), end=end, file=file, flush=flush)


def _request_error(method: str, url: str, exc: requests.RequestException) -> None:
    status = getattr(getattr(exc, "response", None), "status_code", None)
    suffix = f" status={status}" if status is not None else ""
    # Exception messages may embed response bodies or request headers. Preserve
    # the actionable type/status without copying attacker-controlled content.
    detail = _redact(f"{method} {url}: {exc.__class__.__name__}{suffix}")
    print(f"[#] request failed: {detail}", file=sys.stderr)


def post(
    url: str,
    path: str,
    header: dict[str, str],
    data: object,
    files: object | None = None,
):
    target = url + path
    try:
        with warnings.catch_warnings():
            if not TLS_VERIFY:
                warnings.simplefilter("ignore", InsecureRequestWarning)
            if files is None:
                return requests.post(
                    url=target,
                    data=data,
                    headers=header,
                    timeout=REQUEST_TIMEOUT,
                    verify=TLS_VERIFY,
                )
            return requests.post(
                url=target,
                data=data,
                headers=header,
                files=files,
                timeout=REQUEST_TIMEOUT,
                verify=TLS_VERIFY,
            )
    except requests.RequestException as exc:
        _request_error("POST", target, exc)
        return None


def get(url: str, path: str):
    target = url + path
    try:
        with warnings.catch_warnings():
            if not TLS_VERIFY:
                warnings.simplefilter("ignore", InsecureRequestWarning)
            return requests.get(
                url=target,
                timeout=REQUEST_TIMEOUT,
                verify=TLS_VERIFY,
            )
    except requests.RequestException as exc:
        _request_error("GET", target, exc)
        return None


def _reset_output_for_tests() -> None:
    global _output_path, _output_root, TLS_VERIFY
    _output_path = None
    _output_root = None
    TLS_VERIFY = True
