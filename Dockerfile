# HuntForge 铸猎 · 托管运行镜像（Claude Code 驾驶舱）
# 构建：docker build -t huntforge:latest .
# 导出：docker save huntforge:latest | gzip > huntforge.tar.gz
#
# 设计要点：
# - 渗透工具全部内置（托管沙箱无公网）：nuclei/katana/httpx（Go 二进制）、
#   sqlmap/ffuf/gobuster/hydra/wfuzz/john/nmap/binwalk/steghide/radare2/
#   exiftool/tcpdump/socat/gdb/ltrace/strace/upx、pwntools(checksec)/angr/
#   z3/ROPgadget/dirsearch/arjun。
# - Claude Code CLI（锁定版本）为解题大脑：入口跑无人值守驾驶循环，
#   LLM 走平台大模型网关（agent-awd.baidu.com.tsecbench.gw，Anthropic 协议）。
# - 平台环境变量 BENCHMARK_BASE_URL/BENCHMARK_TOKEN 运行时注入；密钥全部
#   走环境变量（ANTHROPIC_AUTH_TOKEN/LLM_API_KEY），镜像内无任何硬编码密钥。
# 基础镜像走国内镜像（Docker Hub 被墙；1ms 镜像内容与官方一致，bookworm 稳定）
FROM docker.1ms.run/library/python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    NPM_CONFIG_CACHE=/tmp/npm-cache

# 1) 系统工具 + 渗透工具链（全部内置，沙箱内零外部依赖）
#    apt 源切阿里云 https（构建机 http:80 经代理不稳，https CONNECT 隧道可靠）
RUN sed -i 's|http://deb.debian.org|https://mirrors.aliyun.com|g' \
      /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
    apt-get update && apt-get install -y --no-install-recommends \
      bash curl ca-certificates dnsutils netcat-openbsd nmap \
      sqlmap ffuf gobuster hydra wfuzz john socat tcpdump \
      binutils file gdb git jq unzip zip iproute2 procps \
      binwalk steghide telnet \
      ltrace strace patchelf \
      openjdk-17-jre-headless \
      default-mysql-client redis-tools libimage-exiftool-perl \
      nodejs npm openssh-client \
    && rm -rf /var/lib/apt/lists/*

# jadx（APK 逆向：run-10043 五道 APK 题全靠手写 DEX 解析器，太慢——
# 宿主下载 .jadx.zip 随构建上下文注入；ADD 不自动解 zip，显式 unzip）
ADD .jadx.zip /tmp/jadx.zip
RUN set -eux; \
    unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && rm -f /tmp/jadx.zip

# upx（bookworm 无 upx-ucl 包；官方静态包经 .upx.tar.xz 注入——
# 构建机代理隧道对 github releases 偶发假 200，改为宿主机下载：
# python scripts/fetch_upx.py 生成仓库根 .upx.tar.xz，ADD 自动解包）
ADD .upx.tar.xz /tmp/upx/
RUN set -eux; \
    install -m755 /tmp/upx/upx-4.2.4-amd64_linux/upx /usr/local/bin/upx \
    && rm -rf /tmp/upx

# radare2（bookworm 无此包，官方 .deb）
RUN set -eux; \
    curl -fsSL -o /tmp/r2.deb \
      https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb \
    && dpkg -i /tmp/r2.deb || apt-get install -fy \
    && rm -f /tmp/r2.deb

# 2) Go 工具（build 期下载，锁定版本）：nuclei / katana / httpx
RUN set -eux; \
    curl -fsSL -o /tmp/nuclei.zip \
      https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_amd64.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip; \
    curl -fsSL -o /tmp/katana.zip \
      https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin katana \
    && chmod +x /usr/local/bin/katana && rm /tmp/katana.zip; \
    curl -fsSL -o /tmp/httpx.zip \
      https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin httpx \
    && chmod +x /usr/local/bin/httpx && rm /tmp/httpx.zip

# 3) Python 依赖（pwntools 自带 checksec；angr/z3 供 license 约束求解；
#    ROPgadget/pyelftools 供 pwn 链构造；dirsearch/arjun 载荷与枚举）
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt pwntools \
    angr z3-solver ROPgadget pyelftools dirsearch arjun

# 4) Claude Code CLI（驾驶舱大脑，锁定版本）
RUN npm install -g @anthropic-ai/claude-code@2.1.232 \
    && rm -rf /tmp/npm-cache

WORKDIR /app
COPY . .

# 非 root 运行（Claude Code 拒绝以 root 使用 --dangerously-skip-permissions）
RUN useradd -m -s /bin/bash ctf \
    && mkdir -p /app/artifacts /app/scratch /app/.claude \
    && chown -R ctf:ctf /app
USER ctf

# 5) 运行时约定：Claude Code 经内置 shim 接平台网关（沙箱域名
#    api.deepseek.com.tsecbench.gw；shim 在 127.0.0.1:8765 做
#    Anthropic→OpenAI 协议转换，由 entrypoint 启动）。
#    模型方案（最后一场，用户指定）：全部 deepseek-v4-flash + MAX 推理。
ENV PYTHONUNBUFFERED=1 \
    HUNTFORGE_GATEWAY=1 \
    HUNTFORGE_KALI=1 \
    ANTHROPIC_BASE_URL=http://127.0.0.1:8765 \
    ANTHROPIC_MODEL=deepseek-v4-flash \
    ANTHROPIC_SMALL_FAST_MODEL=deepseek-v4-flash \
    HF_LLM_BASE_URL=http://api.deepseek.com.tsecbench.gw/v1 \
    HF_LLM_MODEL=deepseek-v4-flash \
    HF_FAST_MODEL=deepseek-v4-flash \
    HF_FAST_BASE_URL=http://api.deepseek.com.tsecbench.gw/v1 \
    HF_FAST_FALLBACK=deepseek-v4-flash \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT=1

ENTRYPOINT ["bash", "/app/docker/entrypoint.sh"]
