#!/usr/bin/env python
# coding=utf-8
from __future__ import annotations

import asyncio

from inc import fofa, hunter, poc, run, springcheck, vul, zoom


def SpringBoot_Scan_console(args, proxies, header_new):
    if args.url:
        urlnew = springcheck.check(args.url, proxies, header_new)
        return run.url(
            urlnew,
            proxies,
            header_new,
            delay=args.delay,
            output_file=args.output,
        )
    if args.urlfile:
        return asyncio.run(
            run.file_main(
                args.urlfile,
                proxies,
                header_new,
                delay=args.delay,
                max_concurrency=args.max_concurrency,
                output_file=args.output,
            )
        )
    if args.vul:
        if not args.active_exploit:
            raise PermissionError("主动利用模式未获得显式授权")
        urlnew = springcheck.check(args.vul, proxies, header_new)
        return vul.vul(
            urlnew,
            proxies,
            header_new,
            choices=args.checks,
            active_exploit=True,
            artifact_dir=args.artifact_dir,
        )
    if args.vulfile:
        if not args.active_exploit:
            raise PermissionError("主动利用模式未获得显式授权")
        return poc.poc(
            args.vulfile,
            proxies,
            choices=args.checks,
            active_exploit=True,
            artifact_dir=args.artifact_dir,
        )
    if args.dump:
        urlnew = springcheck.check(args.dump, proxies, header_new)
        return run.dump(
            urlnew,
            proxies,
            header_new,
            artifact_dir=args.artifact_dir,
        )
    if args.dumpfile:
        return run.dumpfile(
            args.dumpfile,
            proxies,
            header_new,
            artifact_dir=args.artifact_dir,
            delay=args.delay,
        )
    if args.zoomeye:
        return zoom.ZoomDowload(args.zoomeye, proxies, artifact_dir=args.artifact_dir)
    if args.fofa:
        return fofa.FofaDowload(args.fofa, proxies, artifact_dir=args.artifact_dir)
    if args.hunter:
        return hunter.HunterDowload(args.hunter, proxies, artifact_dir=args.artifact_dir)
    raise ValueError("未选择执行动作")
