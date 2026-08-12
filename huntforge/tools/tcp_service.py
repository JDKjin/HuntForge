"""TCP 协议服务探测工具（f1-* 自定义协议 pwn 题的通用入口）。

能力：连接 → 读 banner → 依次发送探测载荷 → 扫描响应中的 flag{...}。
协议逆向不在能力内，但很多 f1 题对 HELP/LIST/GET 等明文指令有响应，
banner 或响应里可能直接泄露线索甚至 flag。
"""
from __future__ import annotations

import re
import socket
import time

FLAG_RE = re.compile(r"(?:flag|FLAG)\{[^}\s\n]{1,200}\}")

# 通用探测载荷（明文协议友好；二进制协议会静默失败，不产生副作用）
PROBE_PAYLOADS = [
    b"\r\n", b"HELP\r\n", b"help\r\n", b"PING\r\n", b"GET\r\n", b"LIST\r\n",
    b"LS\r\n", b"STATS\r\n", b"STATUS\r\n", b"INFO\r\n", b"VERSION\r\n",
    b"GET flag\r\n", b"GET flag.txt\r\n", b"GET *\r\n", b"read flag\r\n",
    b"cat flag\r\n", b"FLAG\r\n", b"flag\r\n", b"QUIT\r\n",
]


def extract_flags(text: str) -> list[str]:
    return list(dict.fromkeys(FLAG_RE.findall(text or "")))


def _read_once(sock: socket.socket, timeout: float, max_bytes: int = 8192) -> bytes:
    sock.settimeout(timeout)
    data = b""
    deadline = time.time() + timeout
    try:
        while time.time() < deadline and len(data) < max_bytes:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 2048:
                time.sleep(0.2)  # 给服务端一个写完的机会
                break
    except (socket.timeout, OSError):
        pass
    return data


def probe(host: str, port: int, payloads: list[bytes] | None = None,
          timeout: float = 8.0) -> list[dict]:
    """连接服务，读 banner，然后对每个载荷独立新连接发送并读响应。"""
    out: list[dict] = []
    payloads = payloads if payloads is not None else PROBE_PAYLOADS

    # 1) banner
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        banner = _read_once(s, timeout)
        s.close()
        out.append({"payload": "<banner>",
                    "response": banner.decode("utf-8", "replace")[:2000]})
    except OSError as exc:
        return [{"payload": "<banner>", "response": "", "error": str(exc)}]

    # 2) 载荷探测（每载荷新连接，避免把状态机打挂）
    for p in payloads:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.sendall(p)
            resp = _read_once(s, timeout)
            s.close()
        except OSError as exc:
            out.append({"payload": p.decode("utf-8", "replace"),
                        "response": "", "error": str(exc)})
            continue
        text = resp.decode("utf-8", "replace")
        out.append({"payload": p.decode("utf-8", "replace"),
                    "response": text[:2000]})
        if extract_flags(text):
            break
    return out


def run(host: str, port: int, timeout: float = 8.0) -> dict:
    """工具入口：返回 {ok, banner, responses, flags}。

    timeout 是总时限（含所有载荷），超时立即停止剩余探测。
    """
    deadline = time.time() + timeout
    results = []
    for p in [b"<banner>"] + list(PROBE_PAYLOADS):
        left = deadline - time.time()
        if left <= 0:
            break
        try:
            s = socket.create_connection((host, port), timeout=min(left, 5.0))
            if p == b"<banner>":
                # banner 只给 2s（有就有，没有立即进入载荷探测，别吃掉总预算）
                resp = _read_once(s, min(left, 2.0))
                results.append({"payload": "<banner>",
                                "response": resp.decode("utf-8", "replace")[:2000]})
            else:
                s.sendall(p)
                resp = _read_once(s, min(left, 5.0))
                text = resp.decode("utf-8", "replace")
                results.append({"payload": p.decode("utf-8", "replace"),
                                "response": text[:2000]})
                if extract_flags(text):
                    break
            s.close()
        except OSError as exc:
            results.append({"payload": (p.decode("utf-8", "replace")
                                        if p != b"<banner>" else "<banner>"),
                            "response": "", "error": str(exc)})
    flags: list[str] = []
    for r in results:
        flags.extend(extract_flags(r.get("response", "")))
    return {"ok": True, "banner": (results[0].get("response") if results else ""),
            "responses": results, "flags": list(dict.fromkeys(flags))}


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 3:
        print("usage: python -m huntforge.tools.tcp_service HOST PORT")
        sys.exit(1)
    print(json.dumps(run(sys.argv[1], int(sys.argv[2])), ensure_ascii=False, indent=2))
