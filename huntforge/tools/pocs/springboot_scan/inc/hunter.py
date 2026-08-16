#!/usr/bin/env python
# coding=utf-8
from __future__ import annotations

import base64
import json

import requests
from termcolor import cprint

from inc import policy


def JSON_load(text, *, artifact_dir):
    data = json.loads(text)
    services = [item.get("url") for item in data.get("data", {}).get("arr", [])]
    services = [str(item) for item in services if item]
    if not services:
        cprint("[-] 没有搜索到任何资产，请检查搜索语法", "yellow")
        return 0
    for service in services:
        policy.append_artifact(artifact_dir, "hunterout.txt", service + "\n")
    return len(services)


def Key_Dowload(key, proxies, choices, searchs, *, artifact_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    pages = choices // 20 + (1 if choices % 20 else 0)
    for page in range(1, pages + 1):
        url = (
            "https://hunter.qianxin.com/openApi/search?api-key="
            + str(key)
            + "&search="
            + str(searchs)
            + "&page_size=20&is_web=1&page="
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
            if response.status_code == 200 and '"code":200' in response.text:
                JSON_load(response.text, artifact_dir=artifact_dir)
            else:
                cprint(f"[-] Hunter API 返回状态码 {response.status_code}", "yellow")
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            cprint(f"[-] Hunter API 请求失败: {type(exc).__name__}", "yellow")
            policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")


def Key_Test(key, proxies, choices, searchs, *, artifact_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        response = requests.get(
            url=(
                "https://hunter.qianxin.com/openApi/search?api-key="
                + key
                + "&search=dGl0bGU9IuWMl-S6rCI=&page=1&page_size=10&is_web=1"
            ),
            headers=headers,
            timeout=10,
            verify=policy.TLS_VERIFY,
            proxies=proxies,
        )
        data = response.json()
        if response.status_code == 200 and str(data.get("code")) == "200":
            cprint("[+] Hunter 凭据验证成功", "red")
            return Key_Dowload(
                key,
                proxies,
                choices,
                searchs,
                artifact_dir=artifact_dir,
            )
        cprint(f"[-] Hunter 凭据验证失败，状态码 {response.status_code}", "yellow")
        return None
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        cprint(f"[-] Hunter 凭据验证失败: {type(exc).__name__}", "yellow")
        policy.append_artifact(artifact_dir, "error.log", str(exc) + "\n")
        return None


def HunterDowload(key, proxies, *, artifact_dir):
    artifact_dir = policy.resolve_artifact_dir(artifact_dir)
    cprint("======开始对接 Hunter 进行 Spring 资产测绘======", "green")
    cprint("[+] 已加载 Hunter 凭据", "green")
    try:
        raw_choices = input("\n[.] 请输入资产数量（默认100条）: ").strip()
        choices = int(raw_choices or "100")
        if choices <= 0:
            raise ValueError("资产数量必须大于 0")
    except ValueError as exc:
        cprint(f"[-] 参数错误: {exc}", "yellow")
        return None
    search = input('[.] 请输入测绘语句（默认 app.name="Spring Whitelabel Error"）: ').strip()
    if not search:
        searchs = "YXBwLm5hbWU9IlNwcmluZyBXaGl0ZWxhYmVsIEVycm9yIg=="
    else:
        searchs = base64.urlsafe_b64encode(search.encode("utf-8")).decode("ascii")
    output = policy.reset_artifact(artifact_dir, "hunterout.txt")
    Key_Test(key, proxies, choices, searchs, artifact_dir=artifact_dir)
    count = len(output.read_text(encoding="utf-8").splitlines())
    cprint(f"[+] Hunter 资产结果已写入本次运行产物目录，共 {count} 条", "red")
    return output
