#!/usr/bin/env python3
"""部署注册机 Docker 到远程服务器"""
import paramiko
import os
import sys

HOST = "47.104.161.77"
USER = "root"
PASS = "Hy@8104905"
PORT = 22

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_TO_UPLOAD = [
    "keygen_web.py",
    "keygen_web.html",
    "Dockerfile.keygen",
    "docker-compose.keygen.yml",
]
CORE_FILES = [
    ("core/license_manager.py", "core/license_manager.py"),
]

REMOTE_DIR = "/root/keygen-web"


def run_cmd(ssh, cmd, desc=""):
    label = f" [{desc}]" if desc else ""
    print(f"--- {cmd}{label} ---")
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    exit_code = stdout.channel.recv_exit_status()
    if out:
        print(out)
    if err:
        print("STDERR:", err)
    print(f"exit={exit_code}")
    return exit_code, out, err


def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"🔗 连接 {USER}@{HOST}:{PORT}...")
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10)
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        sys.exit(1)

    print("✅ 已连接\n")

    # 1. 创建目录
    run_cmd(client, f"mkdir -p {REMOTE_DIR}/core", "创建目录")

    # 2. 上传文件
    sftp = client.open_sftp()
    for fname in FILES_TO_UPLOAD:
        local = os.path.join(BASE_DIR, fname)
        remote = f"{REMOTE_DIR}/{fname}"
        if os.path.exists(local):
            sftp.put(local, remote)
            print(f"  📤 {fname} -> {remote}")
        else:
            print(f"  ⚠ {fname} 不存在，跳过")

    for src, dst in CORE_FILES:
        local = os.path.join(BASE_DIR, src)
        remote = f"{REMOTE_DIR}/{dst}"
        if os.path.exists(local):
            sftp.put(local, remote)
            print(f"  📤 {src} -> {remote}")
        else:
            print(f"  ⚠ {src} 不存在，跳过")
    sftp.close()
    print()

    # 3. 停止旧容器
    run_cmd(client, f"cd {REMOTE_DIR} && docker compose -f docker-compose.keygen.yml down 2>/dev/null || true", "停止旧容器")
    run_cmd(client, "docker rm -f hikvision-keygen 2>/dev/null || true", "清理旧容器")

    # 4. 构建镜像
    code, out, err = run_cmd(
        client,
        f"cd {REMOTE_DIR} && docker compose -f docker-compose.keygen.yml build --no-cache 2>&1",
        "构建镜像"
    )
    if code != 0:
        print("❌ 构建失败，请检查日志")
        client.close()
        sys.exit(1)

    # 5. 启动
    code, out, err = run_cmd(
        client,
        f"cd {REMOTE_DIR} && docker compose -f docker-compose.keygen.yml up -d 2>&1",
        "启动容器"
    )

    # 6. 验证
    run_cmd(client, "docker ps --filter name=hikvision-keygen --format '{{.ID}} {{.Status}} {{.Ports}}'", "验证运行状态")
    run_cmd(client, "sleep 1 && curl -s http://localhost:5800/api/login -X POST -H 'Content-Type: application/json' -d '{\"password\":\"hy8104905\"}'", "测试 API")

    client.close()
    print("\n✅ 部署完成！访问 http://47.104.161.77:5800")


if __name__ == "__main__":
    main()
