#!/usr/bin/env python
# coding=utf-8
from __future__ import annotations

import json

import requests
from termcolor import cprint

from inc import policy


def JSON_load(text, *, artifact_dir):
    data = json.loads(text)
    matches = data.get("matches", [])
    count = 0
    for match in matches:
        portinfo = match.get("portinfo", {})
        service = "https://" if "https" in str(portinfo.get("service", "")) else "http://"
        host = portinfo.get("hostname") or match.get("ip")
        port = portinfo.get("port")
        if not host or port is None:
            continue
        policy.append_artifact(
            artifact_dir,
            "zoomout.txt",
            f"{service}{host}:{port}\n",
        )
        count += 1
    if count == 0:
        cprint("[-] 没有搜索到任何资产，请检查搜索语法", "yellow")
    return count


def Key_Dowload(key, proxies, choices, searchs, *, artifact_dir):
    headers = {"API-KEY": key, "Content-Type": "application/x-www-form-urlencoded"}
    pages = choices // 20 + (1 if choices % 20 else 0)
    for page in range(1, pages + 1):
        url = (
            "https://api.zoomeye.org/host/search?query="
            + searchs
            + "&t=web&page="
            + str(page)
        )
        cprint(f"[+] 正在下载第 {page} 页数据", "red")
        try:
            response = requests.get(
                url=url,
                headers=headers,
                timeout=6,
                verify=policy.TLS_VERIFY,
                proxies=proxies,
            )
            if response.status_code in {200, 201}:
                JSON_load(response.text, artifact_dir=artifact_dir)
            else:
                cprint(f"[-] ZoomEye API 返回状态码 {response.status_code}", "yellow")
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            cprint(f"[-] ZoomEye API 请求失败: {type(exc).__name__}", "yellow")
            policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")


def Key_Test(key, proxies, choices, searchs, *, artifact_dir):
    headers = {"API-KEY": key, "Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.get(
            url='https://api.zoomeye.org/host/search?query=app:"Spring Framework"&page=1',
            headers=headers,
            timeout=6,
            verify=policy.TLS_VERIFY,
            proxies=proxies,
        )
        if response.status_code in {200, 201}:
            cprint("[+] ZoomEye 凭据验证成功", "red")
            return Key_Dowload(
                key,
                proxies,
                choices,
                searchs,
                artifact_dir=artifact_dir,
            )
        cprint(f"[-] ZoomEye 凭据验证失败，状态码 {response.status_code}", "yellow")
        return None
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        cprint(f"[-] ZoomEye 凭据验证失败: {type(exc).__name__}", "yellow")
        policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")
        return None


def ZoomDowload(key, proxies, *, artifact_dir):
    artifact_dir = policy.resolve_artifact_dir(artifact_dir)
    cprint("======开始对接 ZoomEye 进行 Spring 资产测绘======", "green")
    cprint("[+] 已加载 ZoomEye 凭据", "green")
    try:
        raw_choices = input("\n[.] 请输入资产数量（默认100条）: ").strip()
        choices = int(raw_choices or "100")
        if choices <= 0:
            raise ValueError("资产数量必须大于 0")
    except ValueError as exc:
        cprint(f"[-] 参数错误: {exc}", "yellow")
        return None
    searchs = input('[.] 请输入测绘语句（默认 app:"Spring Framework"）: ').strip()
    if not searchs:
        searchs = 'app:"Spring Framework"'
    output = policy.reset_artifact(artifact_dir, "zoomout.txt")
    Key_Test(key, proxies, choices, searchs, artifact_dir=artifact_dir)
    count = len(output.read_text(encoding="utf-8").splitlines())
    cprint(f"[+] ZoomEye 资产结果已写入本次运行产物目录，共 {count} 条", "red")
    return output
