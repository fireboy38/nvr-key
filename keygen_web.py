#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册机 Web 版后端 — 单文件，零第三方依赖。

启动:
    python keygen_web.py

访问:
    http://localhost:5800

环境变量:
    KEYGEN_ADMIN_USERNAME  管理用户名（默认 admin）
    KEYGEN_ADMIN_PASSWORD  管理密码（默认 admin123）
    KEYGEN_PORT            监听端口（默认 5800）
    KEYGEN_HOST            监听地址（默认 0.0.0.0）
"""

import os
import json
import sqlite3
import secrets
import threading
import datetime
import csv
import io
import importlib.util
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ============================================================
# 配置
# ============================================================

HOST = os.environ.get("KEYGEN_HOST", "0.0.0.0")
PORT = int(os.environ.get("KEYGEN_PORT", "5800"))
ADMIN_USERNAME = os.environ.get("KEYGEN_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("KEYGEN_ADMIN_PASSWORD", "admin123")
SESSION_TTL = 7200  # 秒，2 小时

DATA_DIR = os.path.join(os.path.expanduser("~"), ".hikvision_downloader")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "keygen_web.db")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============================================================
# 加载 license_manager（绕过 core/__init__.py）
# ============================================================

_spec = importlib.util.spec_from_file_location(
    "_license_manager",
    os.path.join(_BASE_DIR, "core", "license_manager.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

generate_key = _mod.generate_key
validate_key = _mod.validate_key
LICENSE_TYPE_TRIAL = _mod.LICENSE_TYPE_TRIAL
LICENSE_TYPE_STANDARD = _mod.LICENSE_TYPE_STANDARD
LICENSE_TYPE_LIFETIME = _mod.LICENSE_TYPE_LIFETIME

LICENSE_NAMES = {
    LICENSE_TYPE_TRIAL: "试用版",
    LICENSE_TYPE_STANDARD: "标准版",
    LICENSE_TYPE_LIFETIME: "终身版",
}

# 16 位十六进制字符集合，用于校验机器码
_HEX_CHARS = set("0123456789ABCDEF")


# ============================================================
# 数据库
# ============================================================

def _get_db():
    """打开一个 SQLite 连接，调用方负责关闭。"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表结构。"""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_code  TEXT    NOT NULL,
                activation_key TEXT   NOT NULL,
                license_type  TEXT    NOT NULL,
                expiry_date   TEXT,
                operator      TEXT    DEFAULT '',
                created_at    TEXT    NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_created_at "
            "ON records(created_at DESC)"
        )


def _save_record(machine_code, activation_key, license_type, expiry_date, operator):
    """保存一条生成记录。"""
    with _get_db() as conn:
        conn.execute(
            "INSERT INTO records "
            "(machine_code, activation_key, license_type, expiry_date, operator, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                machine_code, activation_key, license_type,
                expiry_date or "", operator or "web",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )


# ============================================================
# Session
# ============================================================

_sessions = {}
_session_lock = threading.Lock()


def create_session():
    """创建一个新的会话 token。"""
    token = secrets.token_urlsafe(32)
    with _session_lock:
        _sessions[token] = datetime.datetime.now().timestamp() + SESSION_TTL
    return token


def check_session(token):
    """检查 token 是否有效；过期会自动清除。"""
    if not token:
        return False
    with _session_lock:
        expiry = _sessions.get(token)
        if expiry is None:
            return False
        if expiry < datetime.datetime.now().timestamp():
            _sessions.pop(token, None)
            return False
        return True


def destroy_session(token):
    """销毁指定会话。"""
    with _session_lock:
        _sessions.pop(token, None)


# ============================================================
# 工具函数
# ============================================================

def _normalize_machine_code(raw):
    """
    清理并校验机器码：去除分隔符，转大写。
    返回 (machine_code, error)。校验通过时 error 为 None。
    """
    if not raw:
        return "", "机器码不能为空"
    mc = raw.strip().replace("-", "").replace(" ", "").upper()
    if len(mc) != 16 or not all(c in _HEX_CHARS for c in mc):
        return mc, "机器码格式无效，需 16 位十六进制字符"
    return mc, None


def _sanitize_int(value, default, minimum=1, maximum=1000):
    """安全地把请求参数转成 int，越界或非法时回退到 default。"""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, v))


# ============================================================
# API 处理函数（均返回 dict）
# ============================================================

def api_login(body):
    input_user = body.get("username", "")
    input_pwd = body.get("password", "")
    if input_user == ADMIN_USERNAME and input_pwd == ADMIN_PASSWORD:
        token = create_session()
        print(f"[keygen_web] 登录成功 user={input_user} (token={token[:8]}...)")
        return {"ok": True, "token": token, "username": input_user}
    print(f"[keygen_web] 登录失败: user={input_user} password_len={len(input_pwd)}")
    return {"ok": False, "error": "用户名或密码错误"}


def api_generate(body):
    mc, err = _normalize_machine_code(body.get("machine_code", ""))
    if err:
        return {"ok": False, "error": err}

    license_type = body.get("license_type", LICENSE_TYPE_STANDARD)
    expiry_date = body.get("expiry_date") or None

    try:
        result = generate_key(mc, license_type, expiry_date)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    _save_record(
        mc, result["activation_key"], license_type,
        result.get("expiry_date") or "", body.get("operator", "web"),
    )
    return {
        "ok": True,
        "activation_key": result["activation_key"],
        "license_type": license_type,
        "license_name": LICENSE_NAMES.get(license_type, license_type),
        "expiry_date": result.get("expiry_date") or "永不过期",
        "machine_code": mc,
    }


def api_batch(body):
    raw_codes = body.get("machine_codes", "")
    license_type = body.get("license_type", LICENSE_TYPE_STANDARD)
    operator = body.get("operator", "web")
    results = []

    for line in raw_codes.split("\n"):
        line = line.strip()
        if not line:
            continue

        mc, err = _normalize_machine_code(line)
        if err:
            results.append({
                "machine_code": line,
                "activation_key": "",
                "error": "格式无效",
            })
            continue

        try:
            result = generate_key(mc, license_type)
            _save_record(
                mc, result["activation_key"], license_type,
                result.get("expiry_date") or "", operator,
            )
            results.append({
                "machine_code": mc,
                "activation_key": result["activation_key"],
                "license_type": license_type,
                "expiry_date": result.get("expiry_date") or "永不过期",
                "ok": True,
            })
        except ValueError as e:
            results.append({
                "machine_code": mc,
                "activation_key": "",
                "error": str(e),
            })

    return {"ok": True, "results": results}


def api_verify(body):
    mc, err = _normalize_machine_code(body.get("machine_code", ""))
    if err:
        return {"ok": False, "error": err}

    key = (body.get("activation_key") or "").strip()
    if not key:
        return {"ok": False, "error": "请输入激活密钥"}

    try:
        result = validate_key(mc, key)
        return {
            "ok": True,
            "valid": result["valid"],
            "license_type": result.get("license_type"),
            "license_name": LICENSE_NAMES.get(result.get("license_type", ""), ""),
            "expiry_date": result.get("expiry_date") or "永不过期",
            "error": result.get("error"),
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}


def api_history(body):
    page = _sanitize_int(body.get("page"), 1, 1, 100000)
    size = _sanitize_int(body.get("size"), 20, 1, 200)
    offset = (page - 1) * size

    with _get_db() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM records").fetchone()["c"]
        rows = conn.execute(
            "SELECT id, machine_code, activation_key, license_type, "
            "       expiry_date, operator, created_at "
            "FROM records ORDER BY id DESC LIMIT ? OFFSET ?",
            (size, offset),
        ).fetchall()

    records = [{
        "id": r["id"],
        "machine_code": r["machine_code"],
        "activation_key": r["activation_key"],
        "license_type": r["license_type"],
        "license_name": LICENSE_NAMES.get(r["license_type"], r["license_type"]),
        "expiry_date": r["expiry_date"] or "永不过期",
        "operator": r["operator"],
        "created_at": r["created_at"],
    } for r in rows]

    return {"ok": True, "records": records, "total": total, "page": page, "size": size}


def api_delete(body):
    rid = body.get("id")
    if rid is None:
        return {"ok": False, "error": "缺少 id"}
    try:
        rid = int(rid)
    except (TypeError, ValueError):
        return {"ok": False, "error": "id 必须为整数"}

    with _get_db() as conn:
        conn.execute("DELETE FROM records WHERE id = ?", (rid,))
    return {"ok": True}


def api_clear(body):
    with _get_db() as conn:
        conn.execute("DELETE FROM records")
    return {"ok": True}


def api_export(body):
    """导出全部记录为 CSV 字符串。"""
    with _get_db() as conn:
        rows = conn.execute(
            "SELECT machine_code, activation_key, license_type, "
            "       expiry_date, operator, created_at "
            "FROM records ORDER BY id DESC"
        ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["机器码", "注册码", "授权类型", "过期日期", "备注", "生成时间"])
    for r in rows:
        writer.writerow([
            r["machine_code"],
            r["activation_key"],
            LICENSE_NAMES.get(r["license_type"], r["license_type"]),
            r["expiry_date"] or "永不过期",
            r["operator"],
            r["created_at"],
        ])
    return {"ok": True, "csv": buf.getvalue()}


# ============================================================
# 路由表
# ============================================================

# 无需登录的可访问路由
PUBLIC_ROUTES = {"/api/login"}

# 需要登录才能访问的路由 -> 处理函数
PROTECTED_ROUTES = {
    "/api/logout":   lambda body, handler: _handle_logout(body, handler),
    "/api/generate": lambda body, handler: api_generate(body),
    "/api/batch":    lambda body, handler: api_batch(body),
    "/api/verify":   lambda body, handler: api_verify(body),
    "/api/history":  lambda body, handler: api_history(body),
    "/api/delete":   lambda body, handler: api_delete(body),
    "/api/clear":    lambda body, handler: api_clear(body),
    "/api/export":   lambda body, handler: api_export(body),
}


def _handle_logout(body, handler):
    """登出处理：从 Authorization 头中提取 token 并销毁。"""
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        destroy_session(auth[7:])
    return {"ok": True}


# ============================================================
# HTTP Handler
# ============================================================

class Handler(BaseHTTPRequestHandler):
    server_version = "KeygenWeb/1.1"

    # ---------- 响应辅助 ----------

    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html, code=200):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        """读取并解析 JSON body，失败返回空 dict。"""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"[keygen_web] JSON 解析失败: {e}")
            return {}

    def _auth_token(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return auth[7:]

    # ---------- GET ----------

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html_path = os.path.join(_BASE_DIR, "keygen_web.html")
            try:
                with open(html_path, "r", encoding="utf-8") as f:
                    self._html(f.read())
            except FileNotFoundError:
                self._html("<h1>keygen_web.html not found</h1>", 404)
        else:
            self.send_error(404)

    # ---------- POST ----------

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        # 公开路由
        if path in PUBLIC_ROUTES:
            self._json(api_login(body))
            return

        # 鉴权
        if not check_session(self._auth_token()):
            self._json({"ok": False, "error": "未登录或会话已过期"}, 401)
            return

        # 受保护路由
        handler = PROTECTED_ROUTES.get(path)
        if handler is None:
            self._json({"ok": False, "error": "未知接口"}, 404)
            return

        try:
            self._json(handler(body, self))
        except Exception as e:
            print(f"[keygen_web] 处理 {path} 异常: {e}")
            self._json({"ok": False, "error": f"服务器内部错误: {e}"}, 500)

    # ---------- 静默日志 ----------

    def log_message(self, *args):
        pass


# ============================================================
# Main
# ============================================================

def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("\n  注册机 Web 管理台")
    print("  =============================")
    print(f"  访问地址: http://localhost:{PORT}")
    print(f"  登录凭据: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print(f"  数据文件: {DB_PATH}")
    print("  按 Ctrl+C 停止\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        server.shutdown()


if __name__ == "__main__":
    main()
