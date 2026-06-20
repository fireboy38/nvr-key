#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
部署注册机 Docker 到远程服务器。

通过 SSH 上传项目文件，重建并启动 Docker 容器。
依赖: paramiko  (pip install paramiko)

可通过环境变量覆盖默认配置:
    DEPLOY_HOST     SSH 主机
    DEPLOY_USER     SSH 用户名
    DEPLOY_PASS     SSH 密码
    DEPLOY_PORT     SSH 端口
    REMOTE_DIR      远程部署目录
"""

import os
import sys

import paramiko

# ============================================================
# 远程服务器配置（可通过环境变量覆盖）
# ============================================================

HOST       = os.environ.get("DEPLOY_HOST", "47.104.161.77")
USER       = os.environ.get("DEPLOY_USER", "root")
PASS       = os.environ.get("DEPLOY_PASS", "Hy@8104905")
PORT       = int(os.environ.get("DEPLOY_PORT", "22"))
REMOTE_DIR = os.environ.get("REMOTE_DIR", "/root/keygen-web")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 顶层文件
FILES_TO_UPLOAD = [
    "keygen_web.py",
    "keygen_web.html",
    "Dockerfile.keygen",
    "docker-compose.keygen.yml",
]

# core/ 子目录下的文件: (本地相对路径, 远程相对路径)
CORE_FILES = [
    ("core/license_manager.py", "core/license_manager.py"),
]


# ============================================================
# 工具函数
# ============================================================

def run_cmd(ssh, cmd, desc=""):
    """在远程主机执行命令，并打印输出。返回 (exit_code, stdout, stderr)。"""
    label = f" [{desc}]" if desc else ""
    print(f"--- {cmd}{label} ---")

    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    exit_code = stdout.channel.recv_exit_status()

    if out:
        print(out)
    if err:
        print("STDERR:", err)
    print(f"exit={exit_code}")
    return exit_code, out, err


def upload_file(sftp, local, remote):
    """上传单个文件，打印日志。"""
    if os.path.exists(local):
        sftp.put(local, remote)
        print(f"  [UP] {local} -> {remote}")
    else:
        print(f"  [SKIP] {local} 不存在，跳过")


def connect_ssh():
    """建立 SSH 连接，失败时退出程序。"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"[*] 连接 {USER}@{HOST}:{PORT}...")
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=10)
    except Exception as e:
        print(f"[!] 连接失败: {e}")
        sys.exit(1)

    print("[*] 已连接\n")
    return client


# ============================================================
# 部署流程
# ============================================================

def deploy():
    client = connect_ssh()

    try:
        # 1. 创建目录
        run_cmd(client, f"mkdir -p {REMOTE_DIR}/core", "创建目录")

        # 2. 上传文件
        print("\n[1/5] 上传项目文件...")
        sftp = client.open_sftp()
        try:
            for fname in FILES_TO_UPLOAD:
                upload_file(sftp,
                            os.path.join(BASE_DIR, fname),
                            f"{REMOTE_DIR}/{fname}")

            for src, dst in CORE_FILES:
                upload_file(sftp,
                            os.path.join(BASE_DIR, src),
                            f"{REMOTE_DIR}/{dst}")
        finally:
            sftp.close()
        print()

        # 3. 停止旧容器
        print("[2/5] 停止旧容器...")
        run_cmd(client,
                f"cd {REMOTE_DIR} && "
                f"docker compose -f docker-compose.keygen.yml down 2>/dev/null || true",
                "docker compose down")
        run_cmd(client,
                "docker rm -f hikvision-keygen 2>/dev/null || true",
                "清理残留容器")

        # 4. 构建镜像
        print("[3/5] 构建镜像...")
        code, _, _ = run_cmd(
            client,
            f"cd {REMOTE_DIR} && "
            f"docker compose -f docker-compose.keygen.yml build --no-cache 2>&1",
            "构建镜像",
        )
        if code != 0:
            print("[!] 构建失败，请检查日志")
            sys.exit(1)

        # 5. 启动容器
        print("[4/5] 启动容器...")
        run_cmd(
            client,
            f"cd {REMOTE_DIR} && "
            f"docker compose -f docker-compose.keygen.yml up -d 2>&1",
            "启动容器",
        )

        # 6. 验证
        print("[5/5] 验证运行状态...")
        run_cmd(client,
                "docker ps --filter name=hikvision-keygen "
                "--format '{{.ID}} {{.Status}} {{.Ports}}'",
                "容器状态")
        run_cmd(client,
                "sleep 2 && curl -s -o /dev/null -w '%{http_code}' "
                "http://localhost:5800/",
                "HTTP 健康检查")

        print(f"\n[*] 部署完成！访问 http://{HOST}:5800")

    finally:
        client.close()


if __name__ == "__main__":
    deploy()
