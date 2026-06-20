# nvr-key · 注册机 Web 管理台

海康录像批量下载工具的密钥管理系统。基于 Python 标准库实现，零第三方依赖（部署脚本除外）。

## 功能特性

- 单/批量生成激活密钥（试用版 / 标准版 / 终身版）
- 在线验证密钥与机器码匹配关系
- 完整的历史记录管理（增删、导出 CSV、清空）
- 基于 HMAC-SHA256 的密钥签名，绑定机器码 + 过期日期
- 内存级会话管理，2 小时 TTL，登出即失效
- 自带 Dockerfile 和 docker-compose，开箱即用

## 目录结构

```
nvr-key/
├── core/
│   └── license_manager.py    # 许可证核心模块：机器码、密钥生成/验证、注册管理
├── keygen_web.py             # Web 后端：HTTP 路由 + SQLite 记录 + Session
├── keygen_web.html           # Web 前端：登录页 + 4 个功能面板
├── Dockerfile.keygen         # 容器镜像构建
├── docker-compose.keygen.yml # 容器编排（含 healthcheck）
├── deploy_keygen.py          # 远程 SSH 一键部署脚本（依赖 paramiko）
└── README.md
```

## 快速开始

### 本地运行

```bash
python keygen_web.py
# 访问 http://localhost:5800
# 默认管理密码: hy8104905 (建议通过环境变量修改)
```

可通过环境变量覆盖默认配置:

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `KEYGEN_HOST` | `0.0.0.0` | 监听地址 |
| `KEYGEN_PORT` | `5800` | 监听端口 |
| `KEYGEN_ADMIN_PASSWORD` | `hy8104905` | 管理密码 |

### Docker 部署

```bash
# 构建并启动
docker compose -f docker-compose.keygen.yml up -d --build

# 查看日志
docker logs -f hikvision-keygen

# 停止
docker compose -f docker-compose.keygen.yml down
```

### 远程一键部署

```bash
pip install paramiko
python deploy_keygen.py
```

部署脚本默认连接 `47.104.161.77`，可通过环境变量 `DEPLOY_HOST` / `DEPLOY_USER` / `DEPLOY_PASS` / `DEPLOY_PORT` 覆盖。

## 密钥算法

- **机器码**: `MD5("{mac}-{hostname}-{disk_serial}")[:16]` 大写十六进制
- **激活密钥**: `HMAC-SHA256(SECRET_KEY, "{machine_code}{expiry_date}")[:16]` 大写十六进制，格式化为 `XXXX-XXXX-XXXX-XXXX`
- **终身版**: HMAC 消息只含 machine_code（无 expiry_date）
- **试用版/标准版**: HMAC 消息为 `machine_code + expiry_date`，验证时遍历可能的日期范围匹配

## 许可证类型

| 类型 | 有效期 | 标签色 |
|------|--------|--------|
| `trial` | 7 天 | 琥珀 |
| `standard` | 365 天 | 青色 |
| `lifetime` | 永不过期 | 绿色 |

## 命令行工具

`core/license_manager.py` 可独立作为 CLI 使用:

```bash
# 显示当前设备机器码
python -m core.license_manager --show-machine-code

# 为指定机器码生成标准版密钥
python -m core.license_manager --generate -m A1B2C3D4E5F67890 -t standard

# 检查当前许可证状态
python -m core.license_manager --check
```

## 安全提示

- 默认管理密码仅用于本地测试，生产环境务必通过环境变量修改
- `SECRET_KEY` 硬编码在 `license_manager.py` 中，如需更高安全性请改为从环境变量读取
- 部署脚本 `deploy_keygen.py` 中的服务器凭据同样建议通过环境变量注入
