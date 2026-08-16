#!/usr/bin/env python
# coding=utf-8
from __future__ import annotations

import argparse
from collections.abc import Sequence

from inc import output, policy, proxycheck


def _parse_checks(raw: str) -> tuple[int, ...]:
    try:
        checks = tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--checks 必须是逗号分隔的整数列表") from exc
    if not checks or any(item < 1 or item > 11 for item in checks):
        raise argparse.ArgumentTypeError("--checks 只能包含 1 到 11")
    if len(set(checks)) != len(checks):
        raise argparse.ArgumentTypeError("--checks 不得包含重复编号")
    return checks


def get_parser(argv: Sequence[str] | None = None):
    parser = argparse.ArgumentParser(
        usage="python SpringBoot-Scan.py ACTION [options]",
        description="SpringBoot 安全扫描与显式授权的漏洞验证工具",
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("-u", "--url", help="扫描单个 URL 的信息泄露端点")
    actions.add_argument("-uf", "--urlfile", help="从文本文件批量扫描信息泄露端点")
    actions.add_argument("-v", "--vul", help="对单个 URL 执行主动漏洞验证")
    actions.add_argument("-vf", "--vulfile", help="从文本文件批量执行主动漏洞验证")
    actions.add_argument("-d", "--dump", help="扫描并下载单个目标的敏感文件")
    actions.add_argument("-df", "--dumpfile", help="批量扫描敏感文件端点")
    actions.add_argument("-z", "--zoomeye", help="使用 ZoomEye 导出 Spring 资产")
    actions.add_argument("-f", "--fofa", help="使用 FOFA 导出 Spring 资产")
    actions.add_argument("-y", "--hunter", help="使用 Hunter 导出 Spring 资产")

    parser.add_argument("-p", "--proxy", default="", help="HTTP 代理 host:port")
    parser.add_argument("-t", "--newheader", help="JSON 格式的自定义 HTTP 头文件")
    parser.add_argument("-c", "--cookie", help="请求 Cookie")
    parser.add_argument("--delay", type=float, default=0.0, help="安全扫描每次请求后的延迟秒数")
    parser.add_argument("--max-concurrency", type=int, default=10, help="批量安全扫描最大并发数")
    parser.add_argument("--output", help="安全扫描结果文件，必须位于当前工作目录内")
    parser.add_argument(
        "--artifact-dir",
        help="主动验证、敏感文件下载或资产导出的单次运行产物目录",
    )
    parser.add_argument(
        "--active-exploit",
        action="store_true",
        help="显式允许 -v/-vf 的目标写入型漏洞验证",
    )
    parser.add_argument("--checks", type=_parse_checks, help="主动验证编号，例如 2,3")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="仅本次运行关闭 TLS 证书校验",
    )

    args = parser.parse_args(argv)
    active_mode = bool(args.vul or args.vulfile)
    safe_scan_mode = bool(args.url or args.urlfile)
    artifact_mode = not safe_scan_mode
    if active_mode and not args.active_exploit:
        parser.error("-v/-vf 必须显式提供 --active-exploit")
    if args.active_exploit and not active_mode:
        parser.error("--active-exploit 只能与 -v/-vf 一起使用")
    if active_mode and not args.checks:
        parser.error("-v/-vf 必须显式提供非空 --checks 列表")
    if args.checks and not active_mode:
        parser.error("--checks 只能与 -v/-vf 一起使用")
    if safe_scan_mode and not args.output:
        parser.error("-u/-uf 必须显式提供 --output")
    if args.output and not safe_scan_mode:
        parser.error("--output 只能与 -u/-uf 一起使用")
    if artifact_mode and not args.artifact_dir:
        parser.error("当前动作必须显式提供 --artifact-dir")
    if safe_scan_mode and args.artifact_dir:
        parser.error("-u/-uf 使用 --output，不接受 --artifact-dir")
    if args.delay < 0:
        parser.error("--delay 必须大于或等于 0")
    if not 1 <= args.max_concurrency <= 100:
        parser.error("--max-concurrency 必须在 1 到 100 之间")
    if args.output:
        try:
            args.output = str(policy.resolve_output_path(args.output))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.artifact_dir:
        try:
            args.artifact_dir = str(policy.resolve_artifact_dir(args.artifact_dir))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = get_parser(argv)
    policy.configure_tls(insecure=args.insecure)
    output.logo()
    proxycheck.SpringBoot_Scan_Proxy(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
