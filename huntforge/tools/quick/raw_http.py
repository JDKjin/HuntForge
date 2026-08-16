#!/usr/bin/env python3
"""Raw HTTP Request Tool — 发送原始 HTTP 请求，支持 chunked/HTTP2/自定义 header

用法:
  python raw_http.py --target URL --method POST --payload 'data' --encoding chunked
  python raw_http.py --target URL --method GET --header 'X-Custom: val'

输出: JSON {status, headers, body, raw_response}
"""

import argparse, json, socket, ssl, sys, time, urllib.parse


def build_raw_request(method: str, path: str, host: str, port: int,
                      headers: dict[str, str], body: str | None,
                      encoding: str) -> bytes:
    """构建原始 HTTP 请求字节"""
    if encoding == "chunked":
        return _build_chunked(method, path, host, headers, body)
    else:
        return _build_standard(method, path, host, headers, body)


def _build_standard(method, path, host, headers, body):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    if body:
        req += f"Content-Length: {len(body.encode())}\r\n"
    req += "\r\n"
    if body:
        req += body
    return req.encode()


def _build_chunked(method, path, host, headers, body):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n"
    for k, v in headers.items():
        if k.lower() != "content-length":
            req += f"{k}: {v}\r\n"
    req += "\r\n"
    if body:
        body_bytes = body.encode()
        req += f"{len(body_bytes):x}\r\n"
        req += body.decode("latin-1")
        req += "\r\n"
    req += "0\r\n\r\n"
    return req.encode("latin-1")


def send_raw(target: str, method: str = "GET", headers: dict[str, str] | None = None,
             body: str | None = None, encoding: str = "standard",
             timeout: int = 15) -> dict:
    """发送原始 HTTP 请求并返回解析结果"""
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    hdrs = headers or {}
    if "User-Agent" not in hdrs:
        hdrs["User-Agent"] = "VulHunter-RawHTTP/1.0"

    raw = build_raw_request(method, path, host, port, hdrs, body, encoding)
    use_tls = parsed.scheme == "https"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.sendall(raw)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        return _parse_response(response)
    finally:
        sock.close()


def _parse_response(data: bytes) -> dict:
    """解析 HTTP 响应为结构化 JSON"""
    try:
        header_end = data.index(b"\r\n\r\n")
        header_part = data[:header_end].decode("latin-1", errors="replace")
        body = data[header_end + 4:]
    except ValueError:
        header_part = data.decode("latin-1", errors="replace")
        body = b""

    lines = header_part.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 else 0

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return {
        "status": status,
        "headers": headers,
        "body": body.decode("utf-8", errors="replace")[:8192],
        "body_bytes": len(body),
        "raw_status_line": status_line
    }


def main():
    parser = argparse.ArgumentParser(description="Raw HTTP Request Tool")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--payload", default=None, help="Request body")
    parser.add_argument("--encoding", default="standard",
                        choices=["standard", "chunked"], help="Transfer encoding")
    parser.add_argument("--header", action="append", default=[],
                        help="Custom header (repeatable)")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    result = send_raw(args.target, args.method, headers, args.payload,
                      args.encoding, args.timeout)
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
