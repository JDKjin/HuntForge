"""quick 生成器适配层：把 VulHunter tools/quick/ 脚本接进工具目录。

catalog 里 generator 类工具经本模块的 run_* 入口调用，统一返回 JSON 结果。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

_QUICK = Path(__file__).resolve().parent

SCRIPTS = {
    "jwt_forge": ("jwt_forge.py", 30),
    "deser_gen": ("deser_gen.py", 60),
    "pickle_gen": ("pickle_gen.py", 30),
    "raw_http": ("raw_http.py", 60),
}


def _run_script(name: str, args: list[str], timeout: Optional[float] = None) -> dict:
    script, default_tb = SCRIPTS[name]
    try:
        r = subprocess.run(
            [sys.executable, str(_QUICK / script), *args],
            capture_output=True, timeout=timeout or default_tb)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    out = (r.stdout or b"").decode("utf-8", "replace").strip()
    err = (r.stderr or b"").decode("utf-8", "replace").strip()
    result: dict = {"ok": r.returncode == 0}
    try:
        parsed = json.loads(out)
        result.update(parsed)
    except (json.JSONDecodeError, TypeError):
        result["raw"] = out[-4000:]
    if err:
        result["stderr"] = err[-800:]
    return result


def jwt_forge(**kw) -> dict:
    args = ["--token", str(kw.get("token", "")),
            "--attack", str(kw.get("attack", "none"))]
    for key in ("jwks_url", "kid_payload", "payload_override"):
        if kw.get(key) is not None:
            args += [f"--{key.replace('_', '-')}", str(kw[key])]
    return _run_script("jwt_forge", args, timeout=kw.get("timeout"))


def deser_gen(**kw) -> dict:
    args = ["--format", str(kw.get("format", "php"))]
    if kw.get("gadget"):
        args += ["--gadget", str(kw["gadget"])]
    args += ["--cmd", str(kw.get("cmd", "cat /flag.txt"))]
    if kw.get("class_name"):
        args += ["--class-name", str(kw["class_name"])]
    return _run_script("deser_gen", args, timeout=kw.get("timeout"))


def pickle_gen(**kw) -> dict:
    args = ["--target", str(kw.get("target", ""))]
    args += ["--cmd", str(kw.get("cmd", "cat /flag.txt"))]
    args += ["--format", str(kw.get("format", "base64"))]
    return _run_script("pickle_gen", args, timeout=kw.get("timeout"))


def raw_http(**kw) -> dict:
    args = ["--target", str(kw.get("target", "")),
            "--method", str(kw.get("method", "GET"))]
    if kw.get("payload") is not None:
        args += ["--payload", str(kw["payload"])]
    if kw.get("encoding"):
        args += ["--encoding", str(kw["encoding"])]
    for h in kw.get("header") or []:
        args += ["--header", str(h)]
    return _run_script("raw_http", args, timeout=kw.get("timeout"))
