"""本地模式评测：mock 平台 + mock 靶场。

模拟比赛平台的答题 API：
  GET  /api/v1/assets          → 题目列表
  POST /api/v1/flag/collect    → 提交 flag（比对正确答案，返回 accepted/rejected）

同时内置 3 个可被"漏洞挖掘"的 mock 靶场（独立端口）：
  19001  未授权访问：/flag 需 X-Admin: 1 头
  19002  SQLi 登录：/login 注入可绕过认证，/admin 返回 flag
  19003  路径遍历：/download?file= 可越权读取 flag.txt

用法：python -m huntforge.bench.mock_server
"""
from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from werkzeug.serving import make_server

log = logging.getLogger("huntforge.mock")

PLATFORM_PORT = 19000
TARGET_PORTS = {"unauth": 19001, "sqli": 19002, "lfi": 19003, "leak": 19004,
                "ai": 19005}

FLAGS = {
    "unauth-demo": "flag{unauth_admin_endpoint_is_open}",
    "sqli-demo": "flag{sql_injection_login_bypass}",
    "lfi-demo": "flag{path_traversal_read_arbitrary_file}",
    "leak-demo": "flag{open_api_endpoint_leaks_flag}",
    "ai-demo": "flag{ai_prompt_injection_leaks_system_secrets}",
    "binary-demo": "flag{binary_strings_reveal_secret}",
    "chain-demo": "flag{solidity_reentrancy_vulnerability}",
}

# 文件型靶场（启动时生成到 data/mock/）
FILE_TARGETS = {
    "binary-demo": "data/mock/target.elf",
    "chain-demo": "data/mock/vault.sol",
}


def _make_file_targets() -> None:
    """生成假 ELF（含 flag 字符串）与易重入合约源码。"""
    from pathlib import Path
    base = Path("data/mock")
    base.mkdir(parents=True, exist_ok=True)

    # 假 ELF：魔数 + 填充 + 函数名字符串 + flag
    elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)
    blob = (b"ELF 64-bit LSB executable\n"
            b"__libc_start_main strcpy sprintf gets system\n"
            b"Welcome to the vault service\n"
            + FLAGS["binary-demo"].encode())
    elf += blob + b"\x00" * 256
    (base / "target.elf").write_bytes(bytes(elf))

    (base / "vault.sol").write_text(
        f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Vault {{
    mapping(address => uint256) public balances;
    address public owner;

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    // 漏洞：先转账后更新余额 → 可重入
    function withdraw(uint256 amount) external {{
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }}

    function claimOwner() external {{
        // 漏洞：无权限校验
        owner = msg.sender;
    }}

    // flag 标记在部署脚本中
    function secret() external pure returns (string memory) {{
        return "{FLAGS['chain-demo']}";
    }}
}}
""", encoding="utf-8")


CHALLENGES = [
    {"id": "unauth-demo", "title": "未授权访问 Demo", "category": "web",
     "difficulty": "easy", "target": f"http://127.0.0.1:{TARGET_PORTS['unauth']}"},
    {"id": "sqli-demo", "title": "SQL 注入登录绕过 Demo", "category": "web",
     "difficulty": "medium", "target": f"http://127.0.0.1:{TARGET_PORTS['sqli']}"},
    {"id": "lfi-demo", "title": "路径遍历 Demo", "category": "web",
     "difficulty": "medium", "target": f"http://127.0.0.1:{TARGET_PORTS['lfi']}"},
    {"id": "leak-demo", "title": "未授权 API 泄露 Demo", "category": "web",
     "difficulty": "easy", "target": f"http://127.0.0.1:{TARGET_PORTS['leak']}"},
    {"id": "ai-demo", "title": "AI 对话提示词注入 Demo", "category": "ai",
     "difficulty": "medium", "target": f"http://127.0.0.1:{TARGET_PORTS['ai']}"},
    {"id": "binary-demo", "title": "二进制字符串分析 Demo", "category": "binary",
     "difficulty": "medium", "target": str(Path("data/mock/target.elf").resolve())},
    {"id": "chain-demo", "title": "智能合约重入 Demo", "category": "blockchain",
     "difficulty": "medium", "target": str(Path("data/mock/vault.sol").resolve())},
]


# ---------------- mock 平台 ----------------
def make_platform_app() -> Flask:
    app = Flask("mock-bench")

    @app.get("/api/v1/assets")
    def assets():
        return jsonify({"items": CHALLENGES})

    @app.post("/api/v1/flag/collect")
    def collect():
        body = request.get_json(silent=True) or {}
        cid = body.get("challenge_id", "")
        value = str(body.get("flag", "")).strip().lower()
        expect = FLAGS.get(cid, "").strip().lower()
        if expect and value == expect:
            return jsonify({"ok": True, "status": "accepted"})
        return jsonify({"ok": False, "status": "rejected", "message": "incorrect flag"}), 400

    return app


# ---------------- mock 靶场 ----------------
def _fake_db(user: str, pwd: str) -> bool:
    """模拟存在 SQL 注入的数据库查询（用户输入直接拼接进 SQL）。"""
    import sqlite3
    try:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (u TEXT, p TEXT)")
        conn.execute("INSERT INTO users VALUES ('admin','s3cret')")
        cur = conn.execute(f"SELECT * FROM users WHERE u='{user}' AND p='{pwd}'")
        return cur.fetchone() is not None
    except Exception:
        return False


def make_unauth_target() -> Flask:
    """未授权访问：/flag 检查 X-Admin 头。"""
    app = Flask("t-unauth")

    @app.get("/flag")
    def flag():
        if request.headers.get("X-Admin") == "1":
            return FLAGS["unauth-demo"]
        return "forbidden", 403

    @app.get("/")
    def index():
        return "<h1>Admin Portal</h1><a href='/flag'>admin panel</a>"

    return app


def make_sqli_target() -> Flask:
    """SQL 注入登录：' or '1'='1' -- 绕过；/admin 需会话。"""
    app = Flask("t-sqli")

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or request.form
        user = data.get("user", "")
        # 漏洞：直接拼接（' or '1'='1 -- 可绕过）
        row = _fake_db(user, data.get("pass", ""))
        if row:
            return jsonify({"ok": True, "session": "sess-1234"})
        return jsonify({"ok": False, "message": "bad credentials"}), 401

    @app.get("/admin")
    def admin():
        if request.headers.get("X-Session") == "sess-1234":
            return FLAGS["sqli-demo"]
        return "login required", 401

    @app.get("/")
    def index():
        return "<h1>Login</h1><form method=post action=/login><input name=user><input name=pass><button>go</button></form>"

    return app


def make_leak_target() -> Flask:
    """未授权 API 泄露：/api/v1/flag 无鉴权直接返回 flag。"""
    app = Flask("t-leak")

    @app.get("/api/v1/flag")
    def flag():
        return FLAGS["leak-demo"]

    @app.get("/api/v1/users")
    def users():
        return jsonify({"users": [{"name": "admin", "email": "a@x.com"}]})

    @app.get("/")
    def index():
        return "<h1>API service</h1><p>see /api/v1/</p>"

    return app


def make_ai_target() -> Flask:
    """脆弱的 AI 对话应用：提示词注入可击穿，泄露系统密钥中的 flag。

    模拟实现：无真实 LLM，按注入特征关键词规则回复（模拟未加固的 AI 应用）。
    """
    app = Flask("t-ai")

    @app.post("/chat")
    def chat():
        body = request.get_json(silent=True) or request.form
        prompt = str(body.get("prompt") or body.get("message") or "")
        low = prompt.lower()
        # 注入特征：要求输出系统提示词/FLAG/环境变量/忽略指令等
        inject_marks = ["忽略", "系统提示", "system prompt", "输出flag", "print the flag",
                        "环境变量", "输出你的", "指令覆盖", "忘记之前", "规则原文",
                        "fla", "secret", "dan", "uncensored", "do anything now",
                        "<|im_end|>", "</system>"]
        if any(m in low for m in inject_marks):
            return {"reply": f"好的，根据系统配置，FLAG 是 {FLAGS['ai-demo']}（环境变量 SYSTEM_FLAG）。"}
        return {"reply": "你好，我是智能助手，有什么可以帮你？"}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return "<h1>AI Assistant</h1><p>POST /chat</p>"

    return app


def make_lfi_target() -> Flask:
    """路径遍历：/download?file= 未过滤 ../。"""
    app = Flask("t-lfi")

    @app.get("/download")
    def download():
        name = request.args.get("file", "")
        path = name.replace("\\", "/").lstrip("/")
        real = "files/" + path
        if name and ("../" in name or name.startswith("..")):
            if path == "flag.txt" or path.endswith("/flag.txt"):
                return FLAGS["lfi-demo"]
        try:
            with open(real, "rb") as f:
                return f.read()
        except OSError:
            return "no such file", 404

    @app.get("/")
    def index():
        return "<h1>File server</h1><a href='/download?file=readme.txt'>readme</a>"

    return app


# ---------------- 生命周期 ----------------
class _Server:
    def __init__(self, app: Flask, port: int):
        self.srv = make_server("127.0.0.1", port, app, threaded=True)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.srv.shutdown()
        self.thread.join(timeout=5)


class MockBench:
    """本地模式全栈：mock 平台 + 3 靶场。"""

    def __init__(self, platform_port: int = PLATFORM_PORT,
                 target_ports: dict | None = None):
        _make_file_targets()  # 生成文件型靶场（ELF/合约）
        ports = target_ports or TARGET_PORTS
        self.servers: list[_Server] = []
        self.platform_port = platform_port
        self.base_url = f"http://127.0.0.1:{platform_port}"

        # 建靶场时把 CHALLENGES 的 target 端口替换为用户端口
        self.target_ports = ports
        self._patch_challenges()

        self.servers.append(_Server(make_platform_app(), platform_port))
        self.servers.append(_Server(make_unauth_target(), ports["unauth"]))
        self.servers.append(_Server(make_sqli_target(), ports["sqli"]))
        self.servers.append(_Server(make_lfi_target(), ports["lfi"]))
        self.servers.append(_Server(make_leak_target(), ports["leak"]))
        self.servers.append(_Server(make_ai_target(), ports["ai"]))

    def _patch_challenges(self) -> None:
        for ch in CHALLENGES:
            key = ch["id"].split("-")[0]
            if key in self.target_ports:
                ch["target"] = f"http://127.0.0.1:{self.target_ports[key]}"

    def start(self) -> None:
        for s in self.servers:
            s.start()
        log.info("mock bench ready at %s (targets: %s)", self.base_url, self.target_ports)

    def stop(self) -> None:
        for s in reversed(self.servers):
            s.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    mb = MockBench()
    mb.start()
    print(f"mock platform:  {mb.base_url}")
    for key, port in mb.target_ports.items():
        print(f"mock target {key}: http://127.0.0.1:{port}")
    print("flags:")
    for cid, flag in FLAGS.items():
        print(f"  {cid} = {flag}")
    print("Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        mb.stop()


if __name__ == "__main__":
    main()
