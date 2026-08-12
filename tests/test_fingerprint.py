"""指纹识别测试。"""
from huntforge.web.fingerprint import Fingerprinter


def test_identify_from_headers():
    fp = Fingerprinter()
    tags = fp.identify("http://x/", headers={"Server": "nginx/1.24",
                                             "X-Powered-By": "PHP/8.1"},
                       body="", status=200)
    assert "nginx" in tags and "php" in tags


def test_identify_from_body():
    fp = Fingerprinter()
    tags = fp.identify("http://x/", headers={}, body="Powered by ThinkPHP 6",
                       status=200)
    assert "thinkphp" in tags


def test_identify_from_path_status():
    fp = Fingerprinter()
    tags = fp.identify("http://x/", headers={}, body="", status=200,
                       path_status={"/actuator": 200})
    assert "spring-actuator" in tags


def test_check_order_fingerprint_priority():
    fp = Fingerprinter()
    order = fp.check_order(["spring-actuator"])
    assert order.index("unauth") < order.index("sqli")
    # 默认顺序兜底
    order2 = fp.check_order([])
    assert order2 == ["unauth", "sqli", "lfi", "ssrf", "rce"]
    # 指纹的专项排前面
    order3 = fp.check_order(["thinkphp"])
    assert order3.index("rce") < order3.index("sqli")
