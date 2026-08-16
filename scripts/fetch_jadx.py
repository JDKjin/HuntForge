"""下载 jadx 到仓库根（.jadx.zip，Dockerfile ADD 解包用）。

构建机代理隧道对 github releases 偶发假 200，宿主机直连下载后随构建
上下文注入。可重复执行。

用法：python scripts/fetch_jadx.py
"""
from __future__ import annotations

import sys
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

URL = ("https://github.com/skylot/jadx/releases/download/v1.5.3/"
       "jadx-1.5.3.zip")
OUT = Path(__file__).resolve().parents[1] / ".jadx.zip"

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
req = urllib.request.Request(URL, headers={"User-Agent": "huntforge-build"})
with urllib.request.urlopen(req, timeout=300) as resp:
    data = resp.read()
if not data.startswith(b"PK") or len(data) < 1_000_000:
    print(f"[jadx] 下载内容异常（{len(data)} 字节，非 zip）", flush=True)
    sys.exit(1)
with zipfile.ZipFile(BytesIO(data)) as z:
    names = z.namelist()
    assert any("bin/jadx" in n for n in names), "zip 内无 bin/jadx"
OUT.write_bytes(data)
print(f"[jadx] OK -> {OUT}（{len(data)/1e6:.1f}MB）", flush=True)
