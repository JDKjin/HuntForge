#!/usr/bin/env python
# coding=utf-8
from __future__ import annotations

import base64
import json
import sys

import requests
from termcolor import cprint

from inc import policy


def JSON_load(text, *, artifact_dir):
    data = json.loads(text)
    services = [service[0] for service in data.get("results", [])]
    if not services:
        cprint("[-] 没有搜索到任何资产，请检查搜索语法", "yellow")
        return 0
    count = 0
    for service in services:
        outurl = str(service)
        if "https" not in outurl:
            outurl = "http://" + outurl
        policy.append_artifact(artifact_dir, "fofaout.txt", outurl + "\n")
        count += 1
    return count


def Key_Dowload(key, proxies, choices, searchs, *, artifact_dir):
    cprint("======通过 FOFA API 下载资产======", "green")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    pages = choices // 100 + (1 if choices % 100 else 0)
    for page in range(1, pages + 1):
        url = (
            "https://fofax.tech/api/v1/search/all?&key="
            + key
            + "&qbase64="
            + str(searchs)
            + "&page="
            + str(page)
        )
        cprint(f"[+] 正在下载第 {page} 页数据", "red")
        try:
            response = requests.get(
                url=url,
                headers=headers,
                timeout=10,
                verify=policy.TLS_VERIFY,
                proxies=proxies,
            )
            if response.status_code == 200 and '"error":false' in response.text:
                JSON_load(response.text, artifact_dir=artifact_dir)
            else:
                cprint(f"[-] FOFA API 返回状态码 {response.status_code}", "yellow")
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            cprint(f"[-] FOFA API 请求失败: {type(exc).__name__}", "yellow")
            policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")


def Key_Test(key, proxies, choices, searchs, *, artifact_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        response = requests.get(
            url="https://fofax.tech/api/v1/info/my?key=" + key,
            headers=headers,
            timeout=6,
            verify=policy.TLS_VERIFY,
            proxies=proxies,
        )
        data = response.json()
        if response.status_code == 200 and not data.get("error"):
            cprint("[+] FOFA 凭据验证成功", "red")
            return Key_Dowload(
                key,
                proxies,
                choices,
                searchs,
                artifact_dir=artifact_dir,
            )
        cprint(f"[-] FOFA 凭据验证失败，状态码 {response.status_code}", "yellow")
        return None
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        cprint(f"[-] FOFA 凭据验证失败: {type(exc).__name__}", "yellow")
        policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")
        return None


def FofaDowload(key, proxies, *, artifact_dir):
    artifact_dir = policy.resolve_artifact_dir(artifact_dir)
    cprint("======开始对接 FOFA 进行 Spring 资产测绘======", "green")
    cprint("[+] 已加载 FOFA 凭据", "green")
    try:
        raw_choices = input("\n[.] 请输入资产数量（默认100条）: ").strip()
        choices = int(raw_choices or "100")
        if choices <= 0:
            raise ValueError("资产数量必须大于 0")
    except ValueError as exc:
        cprint(f"[-] 参数错误: {exc}", "yellow")
        return None
    search = input('[.] 请输入测绘语句（默认 icon_hash="116323821"）: ').strip()
    if not search:
        searchs = "aWNvbl9oYXNoPSIxMTYzMjM4MjEi"
    else:
        searchs = base64.b64encode(search.encode("utf-8")).decode("ascii")
    output = policy.reset_artifact(artifact_dir, "fofaout.txt")
    Key_Test(key, proxies, choices, searchs, artifact_dir=artifact_dir)
    count = len(output.read_text(encoding="utf-8").splitlines())
    cprint(f"[+] FOFA 资产结果已写入本次运行产物目录，共 {count} 条", "red")
    return output
