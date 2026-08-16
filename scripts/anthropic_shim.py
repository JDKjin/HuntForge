"""Anthropic Messages API → OpenAI Chat Completions 转换 shim。

用途：Claude Code 只讲 Anthropic 协议（/v1/messages + SSE 流式），而托管沙箱
的大模型网关只提供 OpenAI 兼容协议。本 shim 在本机回环起 HTTP 服务，把
Claude Code 的请求翻译成 OpenAI 请求并转发，再把 OpenAI 的 SSE 响应转回
Anthropic SSE 事件。

双模型路由（最后一场方案，用户指定）：主/快模型统一
deepseek-v4-flash + MAX 推理模式（reasoning_effort=max），上游均为
api.deepseek.com.tsecbench.gw；快模型可经 HF_FAST_* 环境变量独立配置，
失败自动降级 HF_FAST_FALLBACK（默认同为 flash）重试一次。

环境变量：
    HF_LLM_BASE_URL      大脑上游 OpenAI 地址（默认 http://api.deepseek.com.tsecbench.gw/v1）
    HF_LLM_API_KEY       大脑上游 key（必填；Claude Code 的 ANTHROPIC_AUTH_TOKEN 同名传入）
    HF_LLM_MODEL         大脑模型（默认 deepseek-v4-pro）
    HF_FAST_MODEL        干活模型（默认 glm-5.2-agent-chanllenge）
    HF_FAST_BASE_URL     干活上游地址（默认 http://agent-awd.baidu.com.tsecbench.gw/v1）
    HF_FAST_API_KEY      干活上游 key（默认取 BAIDU_AWD_API_KEY）
    HF_FAST_FALLBACK     干活兜底模型（默认 deepseek-v4-flash，走大脑上游）
    用法：容器内由 entrypoint 启动；本地测试可手动起：
        python scripts/anthropic_shim.py [port]
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

UPSTREAM = os.environ.get("HF_LLM_BASE_URL",
                           "http://api.deepseek.com.tsecbench.gw/v1").rstrip("/")
API_KEY = os.environ.get("HF_LLM_API_KEY", "")
# 最后一场模型方案（用户指定）：全部 deepseek-v4-flash + MAX 推理模式
MAIN_MODEL = os.environ.get("HF_LLM_MODEL", "deepseek-v4-flash")
FAST_MODEL = os.environ.get("HF_FAST_MODEL",
                            os.environ.get("HF_LLM_FAST_MODEL",
                                           "deepseek-v4-flash"))
FAST_UPSTREAM = os.environ.get(
    "HF_FAST_BASE_URL", UPSTREAM).rstrip("/")
FAST_API_KEY = os.environ.get(
    "HF_FAST_API_KEY", API_KEY)
FAST_FALLBACK = os.environ.get("HF_FAST_FALLBACK", "deepseek-v4-flash")

if not API_KEY:
    # 本地调试兜底：环境里没有 HF_LLM_API_KEY 时尝试 DEEPSEEK_API_KEY
    API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
if not FAST_API_KEY:
    FAST_API_KEY = API_KEY

_session = requests.Session()


def _route_model(requested) -> dict:
    """按请求模型名路由：命中快模型名 → 快上游；否则 → 主模型。
    两种模型统一 deepseek-v4-flash + max（最后一场方案）。
    返回 {base, key, model, effort, floor}；effort 为空字符串 = 不发送该字段。"""
    r = (requested or "").lower()
    if FAST_MODEL.lower() and FAST_MODEL.lower() in r:
        return {"base": FAST_UPSTREAM, "key": FAST_API_KEY,
                "model": FAST_MODEL, "effort": "max", "floor": 8192}
    return {"base": UPSTREAM, "key": API_KEY,
            "model": MAIN_MODEL, "effort": "max", "floor": 8192}


def _now_id() -> str:
    return "msg_" + uuid.uuid4().hex


def _sse(event: str, data: dict):
    return (f"event: {event}\ndata: "
            f"{json.dumps(data, ensure_ascii=False)}\n\n").encode("utf-8")


def _to_openai_messages(payload: dict) -> tuple[list, str]:
    """Anthropic messages → OpenAI messages；返回 (messages, system)。"""
    system = ""
    if isinstance(payload.get("system"), str):
        system = payload["system"]
    elif isinstance(payload.get("system"), list):
        for b in payload["system"]:
            if b.get("type") == "text":
                system += b.get("text", "")
    msgs = []
    for m in payload.get("messages") or []:
        role = m.get("role")
        content = m.get("content") or []
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        parts, tool_calls = [], []
        for b in content:
            if b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_calls.append({"id": b.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                                   "type": "function",
                                   "function": {"name": b.get("name", ""),
                                                "arguments": json.dumps(
                                                    b.get("input") or {},
                                                    ensure_ascii=False)}})
            elif b.get("type") == "tool_result":
                inner = b.get("content")
                if isinstance(inner, list):
                    inner = "\n".join(x.get("text", "") for x in inner
                                      if isinstance(x, dict))
                msgs.append({"role": "tool",
                             "tool_call_id": b.get("tool_use_id") or "call_x",
                             "content": str(inner)[:20000]})
        if role == "assistant":
            item = {"role": "assistant", "content": "\n".join(parts) or None}
            if tool_calls:
                item["tool_calls"] = tool_calls
            msgs.append(item)
        else:
            msgs.append({"role": "user", "content": "\n".join(parts)})
    return msgs, system


def _to_openai_tools(payload: dict) -> list | None:
    tools = payload.get("tools") or []
    out = []
    for t in tools:
        out.append({"type": "function",
                    "function": {"name": t.get("name", ""),
                                 "description": t.get("description", ""),
                                 "parameters": t.get("input_schema") or
                                               {"type": "object",
                                                "properties": {}}}})
    return out or None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _err(self, code: int, message: str):
        body = json.dumps({"type": "error",
                           "error": {"type": "api_error", "message": message}})
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return self._err(400, "bad json")
        if path.endswith("/messages"):
            return self._messages(payload)
        if path.endswith("/count_tokens"):
            return self._count_tokens(payload)
        self._err(404, f"no route: {path}")

    # ---------- count_tokens（Claude Code 压缩上下文时会调） ----------
    def _count_tokens(self, payload):
        total = 0
        for m in payload.get("messages") or []:
            for b in (m.get("content") or []):
                if isinstance(b, dict) and b.get("type") == "text":
                    total += max(1, len(b.get("text", "")) // 3)
        body = json.dumps({"input_tokens": total}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- messages ----------
    def _messages(self, payload):
        msgs, system = _to_openai_messages(payload)
        route = _route_model(payload.get("model"))
        req = {"model": route["model"],
               "messages": ([{"role": "system", "content": system}] + msgs
                            if system else msgs),
               # 输出预算给足 floor（Claude Code 传的 max_tokens 对未知模型
               # 偏小，推理会被截断）
               "max_tokens": max(int(payload.get("max_tokens") or 4096),
                                 route["floor"]),
               "stream": True,
               "temperature": float(payload.get("temperature") or 0.2)}
        # 大脑（pro）MAX 最大推理；干活（glm 非推理模型）不发送该字段
        if route["effort"]:
            req["reasoning_effort"] = route["effort"]
        tools = _to_openai_tools(payload)
        if tools:
            req["tools"] = tools
        if payload.get("tool_choice"):
            tc = payload["tool_choice"]
            if isinstance(tc, dict) and tc.get("type") == "tool":
                req["tool_choice"] = {"type": "function",
                                      "function": {"name": tc.get("name")}}
            elif tc == "any":
                req["tool_choice"] = "auto"
        headers = {"Authorization": f"Bearer {route['key']}",
                   "Content-Type": "application/json"}
        # 快上游失败（限流/故障）→ 自动降级主上游重试一次（兜底保险；
        # 主快上游相同时无需重试）
        attempts = [(route["base"], route["model"], route["key"])]
        if route["base"] != UPSTREAM and FAST_FALLBACK:
            attempts.append((UPSTREAM, FAST_FALLBACK, API_KEY))
        last_exc = ""
        for base, model, key in attempts:
            req["model"] = model
            headers["Authorization"] = f"Bearer {key}"
            # 全模型统一 flash + MAX 推理
            if route["effort"]:
                req["reasoning_effort"] = route["effort"]
            else:
                req.pop("reasoning_effort", None)
            try:
                resp = _session.post(base + "/chat/completions",
                                     json=req, headers=headers,
                                     stream=True, timeout=(15, 300),
                                     verify=False)
            except requests.RequestException as exc:
                last_exc = str(exc)
                continue
            if resp.status_code != 200:
                last_exc = f"upstream {resp.status_code}: {resp.text[:200]}"
                continue
            return self._stream(resp, model)
        return self._err(502, f"upstream error: {last_exc}")

    def _stream(self, resp, model):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        # SSE 无 Content-Length/chunked：以关连接标记流结束（Claude Code 兼容）
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        mid = _now_id()
        self.wfile.write(_sse("message_start", {"type": "message_start",
                                                "message": {"id": mid,
                                                            "type": "message",
                                                            "role": "assistant",
                                                            "content": [],
                                                            "model": model,
                                                            "usage": None}}))
        self.wfile.flush()

        text_block_open = False
        tool_blocks: dict[int, dict] = {}
        stop_reason = "end_turn"

        def close_text_block():
            nonlocal text_block_open
            if text_block_open:
                self.wfile.write(_sse("content_block_stop",
                                      {"type": "content_block_stop",
                                       "index": 0}))
                text_block_open = False

        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                finish = choice.get("finish_reason")
                # 文本增量
                text = delta.get("content") or ""
                if text:
                    if not text_block_open:
                        self.wfile.write(_sse(
                            "content_block_start",
                            {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "text", "text": ""}}))
                        text_block_open = True
                    self.wfile.write(_sse(
                        "content_block_delta",
                        {"type": "content_block_delta", "index": 0,
                         "delta": {"type": "text_delta", "text": text}}))
                # 工具调用增量（OpenAI 分片累积）
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index", 0)
                    blk = tool_blocks.setdefault(
                        idx, {"id": "", "name": "", "args": ""})
                    if tc.get("id"):
                        blk["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        blk["name"] = fn["name"]
                    if fn.get("arguments"):
                        blk["args"] += fn["arguments"]
                if finish:
                    stop_reason = {"stop": "end_turn",
                                   "length": "max_tokens",
                                   "tool_calls": "tool_use"}.get(finish,
                                                                 "end_turn")
            self.wfile.flush()

        # 工具调用块（在文本块之后输出）
        if tool_blocks:
            close_text_block()
            for idx, blk in sorted(tool_blocks.items()):
                cid = blk["id"] or f"call_{uuid.uuid4().hex[:8]}"
                try:
                    args = blk["args"] if blk["args"] else "{}"
                    json.loads(args)   # 校验 JSON 完整性
                except json.JSONDecodeError:
                    args = blk["args"] or "{}"
                self.wfile.write(_sse(
                    "content_block_start",
                    {"type": "content_block_start", "index": idx + 1,
                     "content_block": {"type": "tool_use",
                                       "id": cid,
                                       "name": blk["name"],
                                       "input": {}}}))
                self.wfile.write(_sse(
                    "content_block_delta",
                    {"type": "content_block_delta", "index": idx + 1,
                     "delta": {"type": "input_json_delta",
                               "partial_json": args}}))
                self.wfile.write(_sse(
                    "content_block_stop",
                    {"type": "content_block_stop", "index": idx + 1}))
        else:
            close_text_block()
        self.wfile.write(_sse(
            "message_delta",
            {"type": "message_delta",
             "delta": {"stop_reason": stop_reason, "stop_sequence": None},
             "usage": None}))
        self.wfile.write(_sse("message_stop", {"type": "message_stop"}))
        self.wfile.flush()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        os.environ.get("HF_SHIM_PORT", "8765"))
    if not API_KEY:
        print("[shim] 缺少 HF_LLM_API_KEY/DEEPSEEK_API_KEY，退出", flush=True)
        sys.exit(1)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    print(f"[shim] Anthropic->OpenAI shim on 127.0.0.1:{port} "
          f"main={MAIN_MODEL}(max)@{UPSTREAM} "
          f"fast={FAST_MODEL}(max)@{FAST_UPSTREAM} "
          f"fallback={FAST_FALLBACK}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
