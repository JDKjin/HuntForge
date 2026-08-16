#!/usr/bin/env python
# coding=utf-8
  ################
 #   AabyssZG   #
################

from inc import output,run,vul,console,policy
import requests, sys, hashlib, json
from termcolor import cprint
outtime = 10

def Spring_Check(url,proxies,header_new):
    cprint("[.] 正在进行Spring的指纹识别","cyan")
    Spring_hash = "0488faca4c19046b94d07c3ee83cf9d6"
    Paths = ["favicon.ico", "AabyssZG666"]
    check_status = 0
    for path in Paths:
        test_url = str(url) + path
        r = requests.get(
            test_url,
            timeout=outtime,
            verify=policy.TLS_VERIFY,
            headers=header_new,
            proxies=proxies,
        )
        try:
            content_type = r.headers.get("Content-Type", "")
            if r.text and ('timestamp' in r.text):
                cprint("[+] 站点报错内容符合Spring特征，识别成功","red")
                check_status = 1
            elif "image" in content_type or "octet-stream" in content_type:
                favicon_hash = hashlib.md5(r.content).hexdigest()
                if favicon_hash == Spring_hash:
                    cprint("[+] 站点Favicon是Spring图标，识别成功","red")
                    check_status = 1
            while check_status == 0:
                cprint("[-] 站点指纹不符合Spring特征，可能不是Spring框架","yellow")
                check_status = 2
        except KeyboardInterrupt:
            print("Ctrl + C 手动终止了进程")
            sys.exit()
        except Exception as e:
            cprint(f"[-] Spring 指纹识别错误: {type(e).__name__}", "yellow")

def check(url,proxies,header_new):
    if type(header_new) != dict:
        header_new = json.loads(header_new)
    if ('://' not in url):
        url = str("http://") + str(url)
    if str(url[-1]) != "/":
        url = url + "/"
    try:
        r = requests.get(
            url,
            timeout=outtime,
            verify=policy.TLS_VERIFY,
            headers=header_new,
            proxies=proxies,
        )
        if (r.status_code == 503) or (r.status_code == 502):
            cprint("[-] 网页状态码为503或502", "magenta")
            sys.exit()
        else:
            Spring_Check(url,proxies,header_new)
            return url
    except KeyboardInterrupt:
        print("Ctrl + C 手动终止了进程")
        sys.exit()
    except Exception as e:
        cprint(
            "[-] URL为 " + url + " 的目标拒绝请求: " + type(e).__name__,
            "magenta",
        )
        sys.exit()
