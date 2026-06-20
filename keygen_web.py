#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册机 Web 版后端 — 单文件，零第三方依赖
启动: python keygen_web.py
访问: http://localhost:5800
"""

import os
import sys
import json
import hmac
import hashlib
import datetime
import sqlite3
import secrets
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import importlib.util

# ============================================================
# 配置
# ============================================================

HOST = "0.0.0.0"
PORT = 5800
ADMIN_PASSWORD = os.environ.get("KEYGEN_ADMIN_PASSWORD", "hy8104905")
SESSION_TTL = 7200  # 2小时

DATA_DIR = os.path.join(os.path.expanduser("~"), ".hikvision_downloader")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "keygen_web.db")

# ============================================================
# 加载 license_manager（绕过 core/__init__.py）
# ============================================================

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "_license_manager", os.path.join(_BASE_DIR, "core", "license_manager.py"))
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

# ============================================================
# 数据库初始化
# ============================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_code TEXT NOT NULL,
        activation_key TEXT NOT NULL,
        license_type TEXT NOT NULL,
        expiry_date TEXT,
        operator TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

# ============================================================
# Session
# ============================================================

_sessions = {}
_session_lock = threading.Lock()

def create_session():
    token = secrets.token_urlsafe(32)
    with _session_lock:
        _sessions[token] = datetime.datetime.now().timestamp() + SESSION_TTL
    return token

def check_session(token):
    with _session_lock:
        if token not in _sessions:
            return False
        if _sessions[token] < datetime.datetime.now().timestamp():
            del _sessions[token]
            return False
        return True

def destroy_session(token):
    with _session_lock:
        _sessions.pop(token, None)

# ============================================================
# API
# ============================================================

def api_login(body):
    input_pwd = body.get("password", "")
    if input_pwd == ADMIN_PASSWORD:
        token = create_session()
        print(f"[keygen_web] 登录成功 (token={token[:8]}...)")
        return {"ok": True, "token": token}
    print(f"[keygen_web] 登录失败: 输入密码长度={len(input_pwd)}")
    return {"ok": False, "error": "密码错误"}

def api_generate(body):
    mc = body.get("machine_code", "").strip().replace("-", "").replace(" ", "").upper()
    if not mc or len(mc) != 16 or not all(c in "0123456789ABCDEF" for c in mc):
        return {"ok": False, "error": "机器码格式无效，需 16 位十六进制字符"}
    lt = body.get("license_type", LICENSE_TYPE_STANDARD)
    exp = body.get("expiry_date") or None
    try:
        r = generate_key(mc, lt, exp)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    _save_record(mc, r["activation_key"], lt, r.get("expiry_date") or "", body.get("operator", "web"))
    return {"ok": True, "activation_key": r["activation_key"], "license_type": lt,
            "license_name": LICENSE_NAMES.get(lt, lt),
            "expiry_date": r.get("expiry_date") or "永不过期", "machine_code": mc}

def api_batch(body):
    codes = body.get("machine_codes", "")
    lt = body.get("license_type", LICENSE_TYPE_STANDARD)
    results = []
    for i, line in enumerate([l.strip() for l in codes.split("\n") if l.strip()], 1):
        mc = line.replace("-", "").replace(" ", "").upper()
        if len(mc) != 16 or not all(c in "0123456789ABCDEF" for c in mc):
            results.append({"machine_code": line, "activation_key": "", "error": "格式无效"})
            continue
        try:
            r = generate_key(mc, lt)
            _save_record(mc, r["activation_key"], lt, r.get("expiry_date") or "", body.get("operator", "web"))
            results.append({"machine_code": mc, "activation_key": r["activation_key"],
                           "license_type": lt, "expiry_date": r.get("expiry_date") or "永不过期", "ok": True})
        except Exception as e:
            results.append({"machine_code": mc, "activation_key": "", "error": str(e)})
    return {"ok": True, "results": results}

def api_verify(body):
    mc = body.get("machine_code", "").strip().replace("-", "").replace(" ", "").upper()
    key = body.get("activation_key", "").strip()
    if not mc or not key:
        return {"ok": False, "error": "请输入机器码和注册码"}
    try:
        r = validate_key(mc, key)
        return {"ok": True, "valid": r["valid"], "license_type": r.get("license_type"),
                "license_name": LICENSE_NAMES.get(r.get("license_type", ""), ""),
                "expiry_date": r.get("expiry_date") or "永不过期", "error": r.get("error")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def api_history(body):
    page = int(body.get("page", 1))
    size = int(body.get("size", 20))
    off = (page - 1) * size
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM records")
    total = c.fetchone()[0]
    c.execute("SELECT id,machine_code,activation_key,license_type,expiry_date,operator,created_at FROM records ORDER BY id DESC LIMIT ? OFFSET ?", (size, off))
    rows = [{"id": r[0], "machine_code": r[1], "activation_key": r[2], "license_type": r[3],
             "license_name": LICENSE_NAMES.get(r[3], r[3]), "expiry_date": r[4] or "永不过期",
             "operator": r[5], "created_at": r[6]} for r in c.fetchall()]
    conn.close()
    return {"ok": True, "records": rows, "total": total, "page": page, "size": size}

def api_delete(body):
    rid = body.get("id")
    if not rid:
        return {"ok": False, "error": "缺少 id"}
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM records WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return {"ok": True}

def api_clear(body):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM records")
    conn.commit()
    conn.close()
    return {"ok": True}

def api_export(body):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT machine_code,activation_key,license_type,expiry_date,operator,created_at FROM records ORDER BY id DESC")
    lines = ["机器码,注册码,授权类型,过期日期,操作人,生成时间"]
    for r in c.fetchall():
        lines.append(f"{r[0]},{r[1]},{LICENSE_NAMES.get(r[2], r[2])},{r[3] or '永不过期'},{r[4]},{r[5]}")
    conn.close()
    return {"ok": True, "csv": "\n".join(lines)}

def _save_record(mc, key, lt, exp, operator):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO records (machine_code,activation_key,license_type,expiry_date,operator,created_at) VALUES (?,?,?,?,?,?)",
                 (mc, key, lt, exp, operator, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

# ============================================================
# HTTP Handler
# ============================================================

class Handler(BaseHTTPRequestHandler):
    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html, code=200):
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode('utf-8'))
            return data
        except Exception as e:
            print(f"[keygen_web] JSON解析失败: {e}")
            return {}

    def _auth(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False
        return check_session(auth[7:])

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/index.html'):
            html_path = os.path.join(_BASE_DIR, "keygen_web.html")
            if os.path.exists(html_path):
                with open(html_path, 'r', encoding='utf-8') as f:
                    self._html(f.read())
            else:
                self._html("<h1>keygen_web.html not found</h1>", 404)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()
        if path == '/api/login':
            self._json(api_login(body))
            return
        if not self._auth():
            self._json({"ok": False, "error": "未登录或会话已过期"}, 401)
            return
        routes = {
            '/api/logout': lambda: (destroy_session(self.headers.get('Authorization', '')[7:]), {"ok": True})[1],
            '/api/generate': lambda: api_generate(body),
            '/api/batch': lambda: api_batch(body),
            '/api/verify': lambda: api_verify(body),
            '/api/history': lambda: api_history(body),
            '/api/delete': lambda: api_delete(body),
            '/api/clear': lambda: api_clear(body),
            '/api/export': lambda: api_export(body),
        }
        handler = routes.get(path)
        if handler:
            self._json(handler())
        else:
            self._json({"ok": False, "error": "未知接口"}, 404)

    def log_message(self, *a):
        pass

# ============================================================
# Main
# ============================================================

def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"\n  注册机 Web 管理台")
    print(f"  =============================")
    print(f"  访问地址: http://localhost:{PORT}")
    print(f"  管理密码: {ADMIN_PASSWORD}")
    print(f"  数据文件: {DB_PATH}")
    print(f"  按 Ctrl+C 停止\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        server.shutdown()

if __name__ == "__main__":
    main()
