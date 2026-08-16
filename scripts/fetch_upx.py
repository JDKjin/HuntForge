"""下载 upx 静态包到仓库根（.upx.tar.xz，Dockerfile ADD 解包用）。

构建机代理隧道对 github releases 偶发返回假 200，Dockerfile 内直连不可靠；
本脚本在宿主机（直连网络）下载后随构建上下文注入。可重复执行。

用法：python scripts/fetch_upx.py
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

URL = ("https://github.com/upx/upx/releases/download/v4.2.4/"
       "upx-4.2.4-amd64_linux.tar.xz")
OUT = Path(__file__).resolve().parents[1] / ".upx.tar.xz"
XZ_MAGIC = b"\xfd7zXZ\x00"

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
req = urllib.request.Request(URL, headers={"User-Agent": "huntforge-build"})
with urllib.request.urlopen(req, timeout=120) as resp:
    data = resp.read()
if not data.startswith(XZ_MAGIC) or len(data) < 100_000:
    print(f"[upx] 下载内容异常（{len(data)} 字节，非 xz）", flush=True)
    sys.exit(1)
OUT.write_bytes(data)
print(f"[upx] OK -> {OUT}（{len(data)} 字节）", flush=True)
