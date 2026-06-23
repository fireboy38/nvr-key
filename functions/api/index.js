/**
 * nvr-key EdgeOne Functions — API Backend
 *
 * Port of keygen_web.py to Node.js for EdgeOne Pages Functions.
 * All API routes: login, generate, batch, verify, history, delete, clear, export, logout.
 * HMAC-SHA256 key algorithm ported from Python license_manager.py.
 */

import { createHmac } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// ============================================================
// Configuration
// ============================================================
const ADMIN_USERNAME = process.env.KEYGEN_ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.KEYGEN_ADMIN_PASSWORD || 'admin123';
const SESSION_TTL = 7200; // 2 hours in seconds

const SECRET_KEY = Buffer.from('HikVision_Downloader_2024_SecretKey_XsInfo');

const LICENSE_TYPE_TRIAL = 'trial';
const LICENSE_TYPE_STANDARD = 'standard';
const LICENSE_TYPE_LIFETIME = 'lifetime';

const LICENSE_NAMES = {
  trial: '试用版',
  standard: '标准版',
  lifetime: '终身版',
};

const LICENSE_DURATION = { trial: 7, standard: 365, lifetime: null };
const HEX_CHARS = new Set('0123456789ABCDEF');

// ============================================================
// Session manager (in-memory)
// ============================================================
const sessions = new Map();

function createSession() {
  const token = Array.from({ length: 32 }, () =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[
      Math.floor(Math.random() * 64)
    ]
  ).join('');
  sessions.set(token, Date.now() / 1000 + SESSION_TTL);
  return token;
}

function checkSession(token) {
  if (!token) return false;
  const expiry = sessions.get(token);
  if (!expiry) return false;
  if (expiry < Date.now() / 1000) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function destroySession(token) { sessions.delete(token); }

// ============================================================
// Record storage (JSON file)
// ============================================================
function getRecordsPath() {
  try {
    // EdgeOne Functions have /tmp for writable storage
    const tmp = process.env.TMPDIR || '/tmp';
    return join(tmp, 'nvr-key-records.json');
  } catch {
    return '/tmp/nvr-key-records.json';
  }
}

function loadRecords() {
  try {
    const p = getRecordsPath();
    if (existsSync(p)) {
      return JSON.parse(readFileSync(p, 'utf-8'));
    }
  } catch {}
  return [];
}

function saveRecords(records) {
  try {
    writeFileSync(getRecordsPath(), JSON.stringify(records));
  } catch {}
}

function nextId(records) {
  return records.length > 0 ? Math.max(...records.map((r) => r.id)) + 1 : 1;
}

function nowStr() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

// ============================================================
// Key generation (HMAC-SHA256) — ported from Python
// ============================================================
function formatKey(hex) {
  return hex.match(/.{1,4}/g).join('-');
}

function generateKey(machineCode, licenseType, expiryDate) {
  const clean = machineCode.replace(/-/g, '').toUpperCase();
  if (clean.length !== 16 || ![...clean].every((c) => HEX_CHARS.has(c))) {
    throw new Error(`机器码格式无效，需 16 位十六进制字符`);
  }
  if (!LICENSE_DURATION[licenseType]) {
    throw new Error(`不支持的许可证类型: ${licenseType}`);
  }

  let expiry = expiryDate || null;
  if (expiry === null) {
    const dur = LICENSE_DURATION[licenseType];
    if (dur !== null) {
      const d = new Date();
      d.setDate(d.getDate() + dur);
      expiry = d.toISOString().slice(0, 10);
    }
  }

  let message = clean;
  if (expiry) message = clean + expiry;

  const hmac = createHmac('sha256', SECRET_KEY).update(message, 'utf-8').digest('hex').slice(0, 16).toUpperCase();
  return {
    activation_key: formatKey(hmac),
    license_type: licenseType,
    expiry_date: expiry || '永不过期',
    machine_code: clean,
  };
}

function validateKey(machineCode, key) {
  const cleanCode = machineCode.replace(/-/g, '').toUpperCase();
  if (cleanCode.length !== 16 || ![...cleanCode].every((c) => HEX_CHARS.has(c))) {
    return { valid: false, license_type: null, expiry_date: null, error: '机器码格式无效' };
  }
  const cleanKey = key.replace(/-/g, '').toUpperCase();
  if (cleanKey.length !== 16 || ![...cleanKey].every((c) => HEX_CHARS.has(c))) {
    return { valid: false, license_type: null, expiry_date: null, error: '激活密钥格式无效' };
  }

  // Try lifetime
  const lifetimeHmac = createHmac('sha256', SECRET_KEY).update(cleanCode, 'utf-8').digest('hex').slice(0, 16).toUpperCase();
  if (lifetimeHmac === cleanKey) {
    return { valid: true, license_type: LICENSE_TYPE_LIFETIME, expiry_date: null, error: null };
  }

  // Try date-based keys
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const ranges = [30, 400];
  for (const rangeDays of ranges) {
    for (const [lt, dur] of Object.entries(LICENSE_DURATION)) {
      if (dur === null) continue;
      const start = new Date(today); start.setDate(start.getDate() - rangeDays);
      const end = new Date(today); end.setDate(end.getDate() + dur + 30);

      for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
        const expiryStr = d.toISOString().slice(0, 10);
        const msg = cleanCode + expiryStr;
        const hmac = createHmac('sha256', SECRET_KEY).update(msg, 'utf-8').digest('hex').slice(0, 16).toUpperCase();
        if (hmac === cleanKey) {
          if (d < today) {
            return { valid: false, license_type: lt, expiry_date: expiryStr, error: '许可证已过期' };
          }
          return { valid: true, license_type: lt, expiry_date: expiryStr, error: null };
        }
      }
    }
  }
  return { valid: false, license_type: null, expiry_date: null, error: '激活密钥与机器码不匹配' };
}

function normalizeMachineCode(raw) {
  if (!raw) return { mc: '', error: '机器码不能为空' };
  const mc = raw.trim().replace(/-/g, '').replace(/ /g, '').toUpperCase();
  if (mc.length !== 16 || ![...mc].every((c) => HEX_CHARS.has(c))) {
    return { mc, error: '机器码格式无效，需 16 位十六进制字符' };
  }
  return { mc, error: null };
}

// ============================================================
// API handlers
// ============================================================
function apiLogin(body) {
  const u = body.username || '';
  const p = body.password || '';
  if (u === ADMIN_USERNAME && p === ADMIN_PASSWORD) {
    const token = createSession();
    return Response.json({ ok: true, token, username: u });
  }
  return Response.json({ ok: false, error: '用户名或密码错误' });
}

function apiGenerate(body) {
  const { mc, error } = normalizeMachineCode(body.machine_code || '');
  if (error) return Response.json({ ok: false, error });

  const licenseType = body.license_type || LICENSE_TYPE_STANDARD;
  try {
    const result = generateKey(mc, licenseType, body.expiry_date || null);
    const records = loadRecords();
    records.push({
      id: nextId(records),
      machine_code: mc,
      activation_key: result.activation_key,
      license_type: licenseType,
      expiry_date: result.expiry_date === '永不过期' ? '' : result.expiry_date,
      operator: body.operator || 'web',
      created_at: nowStr(),
    });
    saveRecords(records);
    return Response.json({
      ok: true,
      activation_key: result.activation_key,
      license_type: licenseType,
      license_name: LICENSE_NAMES[licenseType] || licenseType,
      expiry_date: result.expiry_date,
      machine_code: mc,
    });
  } catch (e) {
    return Response.json({ ok: false, error: e.message });
  }
}

function apiBatch(body) {
  const rawCodes = body.machine_codes || '';
  const licenseType = body.license_type || LICENSE_TYPE_STANDARD;
  const operator = body.operator || 'web';
  const results = [];
  const records = loadRecords();
  let maxId = records.length > 0 ? Math.max(...records.map((r) => r.id)) : 0;

  for (let line of rawCodes.split('\n')) {
    line = line.trim();
    if (!line) continue;
    const { mc, error } = normalizeMachineCode(line);
    if (error) {
      results.push({ machine_code: line, activation_key: '', error: '格式无效' });
      continue;
    }
    try {
      const result = generateKey(mc, licenseType, null);
      maxId++;
      records.push({
        id: maxId,
        machine_code: mc,
        activation_key: result.activation_key,
        license_type: licenseType,
        expiry_date: result.expiry_date === '永不过期' ? '' : result.expiry_date,
        operator,
        created_at: nowStr(),
      });
      results.push({
        machine_code: mc,
        activation_key: result.activation_key,
        license_type: licenseType,
        expiry_date: result.expiry_date,
        ok: true,
      });
    } catch (e) {
      results.push({ machine_code: mc, activation_key: '', error: e.message });
    }
  }
  saveRecords(records);
  return Response.json({ ok: true, results });
}

function apiVerify(body) {
  const { mc, error } = normalizeMachineCode(body.machine_code || '');
  if (error) return Response.json({ ok: false, error });
  const key = (body.activation_key || '').trim();
  if (!key) return Response.json({ ok: false, error: '请输入激活密钥' });

  const result = validateKey(mc, key);
  return Response.json({
    ok: true,
    valid: result.valid,
    license_type: result.license_type,
    license_name: LICENSE_NAMES[result.license_type] || '',
    expiry_date: result.expiry_date || '永不过期',
    error: result.error,
  });
}

function apiHistory(body) {
  const page = Math.max(1, Math.min(100000, parseInt(body.page) || 1));
  const size = Math.max(1, Math.min(200, parseInt(body.size) || 20));
  const offset = (page - 1) * size;

  const records = loadRecords();
  // Latest first
  records.sort((a, b) => b.id - a.id);
  const total = records.length;
  const pageRecords = records.slice(offset, offset + size).map((r) => ({
    id: r.id,
    machine_code: r.machine_code,
    activation_key: r.activation_key,
    license_type: r.license_type,
    license_name: LICENSE_NAMES[r.license_type] || r.license_type,
    expiry_date: r.expiry_date || '永不过期',
    operator: r.operator,
    created_at: r.created_at,
  }));

  return Response.json({ ok: true, records: pageRecords, total, page, size });
}

function apiDelete(body) {
  if (body.id == null) return Response.json({ ok: false, error: '缺少 id' });
  const id = parseInt(body.id);
  if (isNaN(id)) return Response.json({ ok: false, error: 'id 必须为整数' });

  let records = loadRecords();
  records = records.filter((r) => r.id !== id);
  saveRecords(records);
  return Response.json({ ok: true });
}

function apiClear() {
  saveRecords([]);
  return Response.json({ ok: true });
}

function apiExport() {
  const records = loadRecords();
  records.sort((a, b) => b.id - a.id);

  let csv = '\uFEFF机器码,注册码,授权类型,过期日期,备注,生成时间\n';
  for (const r of records) {
    const typeName = LICENSE_NAMES[r.license_type] || r.license_type;
    csv += `${r.machine_code},${r.activation_key},${typeName},${r.expiry_date || '永不过期'},${r.operator},${r.created_at}\n`;
  }
  return Response.json({ ok: true, csv });
}

function apiLogout(_, request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    destroySession(auth.slice(7));
  }
  return Response.json({ ok: true });
}

function getToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

// ============================================================
// CORS headers
// ============================================================
const PUBLIC_ROUTES = ['/api/login'];
const PROTECTED_ROUTES = {
  '/api/logout': apiLogout,
  '/api/generate': apiGenerate,
  '/api/batch': apiBatch,
  '/api/verify': apiVerify,
  '/api/history': apiHistory,
  '/api/delete': apiDelete,
  '/api/clear': apiClear,
  '/api/export': apiExport,
};

// ============================================================
// Export handler for EdgeOne Pages Functions
// ============================================================
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization, Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Only handle API routes matching /api/*
    if (!path.startsWith('/api/')) {
      return new Response('Not Found', { status: 404 });
    }

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json; charset=utf-8',
    };

    try {
      // Public routes
      if (PUBLIC_ROUTES.includes(path) && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        return apiLogin(body);
      }

      // Protected routes
      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ ok: false, error: 'Method Not Allowed' }), {
          status: 405, headers: corsHeaders,
        });
      }

      if (!checkSession(getToken(request))) {
        return new Response(JSON.stringify({ ok: false, error: '未登录或会话已过期' }), {
          status: 401, headers: corsHeaders,
        });
      }

      const handler = PROTECTED_ROUTES[path];
      if (!handler) {
        return new Response(JSON.stringify({ ok: false, error: '未知接口' }), {
          status: 404, headers: corsHeaders,
        });
      }

      const body = await request.json().catch(() => ({}));
      const result = await handler(body, request);
      // If handler already returns a Response, use it; otherwise wrap
      const response = result instanceof Response ? result : Response.json(result);
      // Merge CORS headers
      const finalHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders)) {
        if (!finalHeaders.has(k)) finalHeaders.set(k, v);
      }
      return new Response(response.body, { status: response.status, headers: finalHeaders });
    } catch (e) {
      console.error(`API Error [${path}]:`, e);
      return new Response(JSON.stringify({ ok: false, error: `服务器内部错误: ${e.message}` }), {
        status: 500, headers: corsHeaders,
      });
    }
  },
};
