"""ABANDON 三层停损测试：关键词层 / 调用签名层 / CVE 编号层。"""
from huntforge.core.abandon import AbandonGuard, call_signature


def test_call_signature_strips_host_and_query():
    """CHYing 教训：签名去掉 IP/域名与参数，同一操作跨主机才能正确归并。"""
    a = call_signature("GET", "/admin")
    b = call_signature("get", "http://10.0.1.5/admin?id=1")
    c = call_signature("GET", "https://evil.com/Admin/")
    assert a == b == c == "get /admin"


def test_keyword_layer_blocks():
    g = AbandonGuard()
    # 最近 3 轮必须全部为失败特征才拦（recon 阶段 404 是常态，2/3 不拦）
    g.observe("c1", "get /x", ok=False, snippet="Access Denied")
    g.observe("c1", "get /y", ok=False, snippet="403 Forbidden")
    assert g.check("c1", "GET", "/z") is None       # 2/3 失败 → 放行
    g.observe("c1", "get /w", ok=False, snippet="Timeout")
    assert g.check("c1", "GET", "/z") is not None   # 3/3 失败 → 拦截
    # 换一道题互不污染
    assert g.check("c2", "GET", "/z") is None


def test_script_exempt_from_keyword_layers():
    """实盘第 10 轮教训：get/post 探测失败恰是改用脚本深挖的原因——
    script 动作豁免关键词两层，只受签名层（脚本本身连续失败）约束。"""
    g = AbandonGuard()
    for i in range(3):
        g.observe("c1", f"get /p{i}", ok=False, snippet="404 not found")
    # get 被拦，但 script 放行（升级路径不被误禁）
    assert g.check("c1", "GET", "/p9") is not None
    assert g.check("c1", "script", "(script)", payload_text="import requests") is None


def test_signature_layer_blocks_after_dup_limit():
    g = AbandonGuard(dup_limit=3)
    for _ in range(3):
        # snippet 不含失败关键词 → 只测签名层（层间互不干扰）
        g.observe("c1", "get /admin", ok=False, snippet="normal page, no flag")
    # 同签名已连续失败 3 次 → 拦截；不同签名放行
    assert g.check("c1", "GET", "/admin") is not None
    assert g.check("c1", "GET", "/api/flag") is None
    # 中间出现过成功 → 不拦截
    g.observe("c1", "get /admin", ok=True, snippet="200 ok")
    assert g.check("c1", "GET", "/admin") is None


def test_cve_layer_blocks_repeated_cve():
    g = AbandonGuard(dup_limit=99)
    g.observe("c1", "get /vuln", ok=False, snippet="not vuln",
              payload_text="CVE-2024-1234 payload1")
    g.observe("c1", "get /vuln2", ok=False, snippet="not vuln",
              payload_text="CVE-2024-1234 payload2-variant")
    # 同一 CVE 已试 ≥2 个变体 → 拦截
    assert g.check("c1", "GET", "/vuln3", payload_text="CVE-2024-1234 v3") is not None
    # 新 CVE 放行
    assert g.check("c1", "GET", "/vuln4", payload_text="CVE-2024-9999") is None


def test_keyword_intersection_layer():
    """CHYing _matches_dead_end 语义：新调用与已确认失败方向关键词交集 ≥2 即拦。"""
    g = AbandonGuard(dup_limit=99)
    g.observe("c1", "get /api/login", ok=False,
              snippet="/api/login login failed: invalid credential")
    g.observe("c1", "post /api/login", ok=False,
              snippet="credential rejected")
    # 新调用含 /api/login + credential → 交集 ≥2 → 拦截
    assert g.check("c1", "POST", "/api/login",
                   data={"credential": "x"}) is not None
    # 完全不同的方向 → 放行
    assert g.check("c1", "GET", "/robots.txt") is None


def test_breakthrough_unlock_clears_failures():
    """CHYing breakthrough-unlock：成功方向清除该签名的失败记录。"""
    g = AbandonGuard(dup_limit=3)
    for _ in range(3):
        g.observe("c1", "get /admin", ok=False, snippet="normal page")
    assert g.check("c1", "GET", "/admin") is not None
    g.observe("c1", "get /admin", ok=True, snippet="200 flag hint")
    assert g.check("c1", "GET", "/admin") is None


def test_reset_clears_state():
    g = AbandonGuard()
    for snip in ("Access Denied", "Timeout", "403 Forbidden"):
        g.observe("c1", "get /x", ok=False, snippet=snip)
    assert g.check("c1", "GET", "/z") is not None
    g.reset("c1")
    assert g.check("c1", "GET", "/z") is None
