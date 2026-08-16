"""rev.py 逆向自动化工具测试（合成数据；外部工具缺失时验证优雅降级）。"""
from huntforge.tools import rev


def test_xor_single():
    flag = b"flag{t0p_s3cr3t}"
    data = bytes(b ^ 0x5A for b in flag) + b"\x00" * 16
    hits = rev.xor_single(data)
    assert hits and any(b"flag{t0p" in h["plain"] for h in hits)


def test_keystream_recover():
    key = b"\x11\x22\x33"
    plain = b"paddingFLAG{ks_recovered}tail"
    data = bytes(plain[i] ^ key[i % len(key)] for i in range(len(plain)))
    hits = rev.keystream_recover(data, known=b"FLAG{")
    assert hits and any(b"FLAG{ks_recovered}" in h["plain"] for h in hits)


def test_table_invert():
    import random
    rnd = random.Random(42)
    perm = list(range(256))
    rnd.shuffle(perm)
    plain = b"flag{tbl_map}"
    enc = bytes(perm[b] for b in plain)
    blob = bytes(perm) + b"\x00" * 8 + enc
    hits = rev.table_invert(blob)
    assert hits and any(b"flag{tbl_map}" in h["plain"] for h in hits)


def test_lcg_predict():
    a, c, x0 = 13, 77, 5
    stream, x = [], x0
    for _ in range(32):
        x = (a * x + c) & 0xFF
        stream.append(x)
    pred = rev.lcg_predict(bytes(stream))
    assert pred and pred == stream


def test_rc4_candidates():
    key = b"secret"
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    plain = b"xxFLAG{rc4_hit}yy"
    out = bytearray()
    for b in plain:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    hits = rev.rc4_candidates(bytes(out), [b"secret", b"wrong"])
    assert hits and hits[0]["key"] == b"secret"


def test_license_probe(tmp_path):
    script = tmp_path / "check.py"
    script.write_text(
        "import sys\n"
        "k = sys.argv[1] if len(sys.argv) > 1 else ''\n"
        "print('License accepted.' if k == 'GOODKEY' else 'invalid license')\n",
        encoding="utf-8")
    probes = rev.license_probe(str(script), ["BAD", "GOODKEY"])
    assert probes and probes[0]["key"] == "GOODKEY"


def test_bin_triage_degrade(tmp_path):
    # Windows 宿主机可能缺 file/r2：必须优雅降级不崩
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 64 + b"flag{dummy}")
    t = rev.bin_triage(str(p))
    assert t["format"] == "elf"
    assert any("flag" in s for s in t["flag_strings"])


def test_auto_pipeline_synthetic(tmp_path):
    flag = b"flag{auto_pipe}"
    data = bytes(b ^ 0x41 for b in flag) + b"\x00" * 8
    p = tmp_path / "t.bin"
    p.write_bytes(data)
    res = rev.auto_pipeline(str(p), {"path": str(p)}, budget=15)
    assert any(b"flag{auto_pipe}" in (r.get("plain") or b"") for r in res)
