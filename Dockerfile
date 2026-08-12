# HuntForge 铸猎 · 托管模式镜像
# 启动即自解：BenchClient 握手 → 拉题 → 流水线挖掘 → 幂等提交
# 构建：docker build -t huntforge:latest .
# 导出：docker save huntforge:latest | gzip > huntforge.tar.gz
FROM python:3.11-slim

# 离线安全工具链（8核16G 预算内常用子集）
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl dnsutils netcat-openbsd nmap sqlmap ffuf gobuster \
    binutils file gdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 敏感配置一律环境变量注入（平台要求），代码内无密钥
ENV HUNTFORGE_GATEWAY=1 \
    PYTHONUNBUFFERED=1

# 托管模式入口：启动即开始解题（无 --mock）
CMD ["python", "-m", "huntforge.main", "--max-time", "3540"]
