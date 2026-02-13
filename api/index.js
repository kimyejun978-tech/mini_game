const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const GAME_USER_NAME = '__game__';
const GAME_USER_ID = '__rank__';
const BUG_ADMIN_KEY = process.env.BUG_ADMIN_KEY || 'ddsd';
const MAINTENANCE_MODE = false;

const json = (res, status, data) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(data));
};

async function sb(path, { method = 'GET', body } = {}) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'content-type': 'application/json',
      prefer: 'return=representation'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { ok: r.ok, status: r.status, data, text };
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return req.body;
}

function rankTokenFor(score, name) {
  const s = String(Math.max(0, Math.min(999999, score))).padStart(6, '0');
  const t = Date.now().toString().padStart(13, '0');
  const n = encodeURIComponent(name);
  return `rank:${s}:${t}:${n}`;
}

function parseRankToken(token) {
  if (!token || !token.startsWith('rank:')) return null;
  const parts = token.split(':');
  if (parts.length < 4) return null;
  const score = Number(parts[1]);
  const ts = Number(parts[2]);
  const name = decodeURIComponent(parts.slice(3).join(':'));
  if (!Number.isFinite(score) || !Number.isFinite(ts) || !name) return null;
  return { score, ts, name };
}

function bugTokenFor(name, text, ua = '') {
  const t = Date.now().toString().padStart(13, '0');
  const n = encodeURIComponent(name || '익명');
  const m = encodeURIComponent(text.slice(0, 300));
  const u = encodeURIComponent((ua || '').slice(0, 120));
  return `bug:${t}:${n}:${m}:${u}`;
}

function runTokenFor() {
  const t = Date.now().toString().padStart(13, '0');
  const rnd = Math.random().toString(36).slice(2, 10);
  return `run:${t}:${rnd}`;
}

function parseRunToken(token) {
  if (!token || !token.startsWith('run:')) return null;
  const parts = token.split(':');
  if (parts.length < 3) return null;
  const ts = Number(parts[1]);
  if (!Number.isFinite(ts)) return null;
  return { ts };
}

function nowSec() { return Math.floor(Date.now() / 1000); }

function safeIp(req) {
  const xff = req.headers['x-forwarded-for'] || '';
  const ip = String(xff).split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown';
  return String(ip).slice(0, 80);
}

function secLogToken(kind, payload) {
  return `sec:${kind}:${Date.now()}:${encodeURIComponent(payload.slice(0, 260))}`;
}

function rateToken(scope, key, ts) {
  return `rl:${scope}:${encodeURIComponent(key)}:${ts}`;
}

function hostOf(req) {
  return String(req.headers['x-forwarded-host'] || req.headers.host || '').toLowerCase();
}

function normalizeHost(h) {
  return String(h || '').toLowerCase().replace(/^https?:\/\//, '').replace(/:\d+$/, '').replace(/^www\./, '');
}

function hostnameFromUrlLike(v) {
  try {
    const u = new URL(String(v));
    return normalizeHost(u.hostname);
  } catch {
    return normalizeHost(String(v || '').split('/')[0]);
  }
}

function sameOriginGuard(req) {
  const rawHost = hostOf(req);
  const host = normalizeHost(rawHost);
  const origin = String(req.headers.origin || '');
  const referer = String(req.headers.referer || '');

  // 둘 다 없으면 (직접 스크립트 호출 등) 거부
  if (!origin && !referer) return false;

  const candidates = new Set([host, normalizeHost(rawHost), normalizeHost(req.headers.host || '')]);
  candidates.delete('');

  const originHost = origin ? hostnameFromUrlLike(origin) : '';
  const refererHost = referer ? hostnameFromUrlLike(referer) : '';

  return (originHost && candidates.has(originHost)) || (refererHost && candidates.has(refererHost));
}

function suspiciousUa(ua = '') {
  const s = String(ua).toLowerCase();
  const bad = ['burp', 'sqlmap', 'curl', 'python-requests', 'postman', 'insomnia'];
  return bad.some((k) => s.includes(k));
}

function isAdminReq(req) {
  return (req.headers['x-bug-admin-key'] || '') === BUG_ADMIN_KEY;
}

function parseBugToken(token) {
  if (!token || !token.startsWith('bug:')) return null;
  const parts = token.split(':');
  if (parts.length < 5) return null;
  const ts = Number(parts[1]);
  const name = decodeURIComponent(parts[2] || '익명');
  const text = decodeURIComponent(parts[3] || '');
  const ua = decodeURIComponent(parts.slice(4).join(':') || '');
  if (!Number.isFinite(ts) || !text) return null;
  return { ts, name, text, ua };
}

async function ensureGameUserId() {
  const q = await sb(`users?select=id,name,student_id&name=eq.${encodeURIComponent(GAME_USER_NAME)}&student_id=eq.${encodeURIComponent(GAME_USER_ID)}&limit=1`);
  if (q.ok && Array.isArray(q.data) && q.data[0]?.id) return q.data[0].id;

  const ins = await sb('users', {
    method: 'POST',
    body: {
      name: GAME_USER_NAME,
      student_id: GAME_USER_ID,
      password_hash: 'game_rank_no_login',
      approved: true,
      suspended: true
    }
  });

  if (ins.ok && Array.isArray(ins.data) && ins.data[0]?.id) return ins.data[0].id;

  const q2 = await sb(`users?select=id,name,student_id&name=eq.${encodeURIComponent(GAME_USER_NAME)}&student_id=eq.${encodeURIComponent(GAME_USER_ID)}&limit=1`);
  return q2.data?.[0]?.id || null;
}

async function getTopRanks(limit = 10) {
  const r = await sb('sessions?select=token&token=like.rank:*&order=token.desc&limit=3000');
  if (!r.ok || !Array.isArray(r.data)) return [];

  const byName = new Map();
  for (const row of r.data) {
    const parsed = parseRankToken(row.token);
    if (!parsed) continue;
    if (parsed.score > 5000) continue;
    const prev = byName.get(parsed.name);
    if (!prev || parsed.score > prev.score || (parsed.score === prev.score && parsed.ts < prev.ts)) {
      byName.set(parsed.name, parsed);
    }
  }

  const sorted = [...byName.values()].sort((a, b) => b.score - a.score || a.ts - b.ts);
  if (sorted.length <= limit) {
    return sorted.map((x, i) => ({ rank: i + 1, name: x.name, score: x.score }));
  }

  const cutoffScore = sorted[limit - 1].score;
  const withTies = sorted.filter((x, idx) => idx < limit || x.score === cutoffScore);

  let prevScore = null;
  let currentRank = 0;
  return withTies.map((x, idx) => {
    if (x.score !== prevScore) {
      currentRank = idx + 1;
      prevScore = x.score;
    }
    return { rank: currentRank, name: x.name, score: x.score };
  });
}

async function putSecurityLog(kind, payload) {
  const userId = await ensureGameUserId();
  if (!userId) return;
  await sb('sessions', { method: 'POST', body: { token: secLogToken(kind, payload), user_id: userId } });
}

async function checkRateLimit(scope, key, limitCount, windowSec) {
  const userId = await ensureGameUserId();
  if (!userId) return { ok: true, count: 0 };
  const now = nowSec();
  const from = now - windowSec;
  const prefix = `rl:${scope}:${encodeURIComponent(key)}:`;

  const r = await sb(`sessions?select=token&token=like.${encodeURIComponent(prefix)}*&limit=400`);
  const rows = (r.ok && Array.isArray(r.data)) ? r.data : [];
  let cnt = 0;
  for (const row of rows) {
    const parts = String(row.token || '').split(':');
    const ts = Number(parts[parts.length - 1]);
    if (Number.isFinite(ts) && ts >= from) cnt++;
  }

  if (cnt >= limitCount) return { ok: false, count: cnt };

  await sb('sessions', { method: 'POST', body: { token: rateToken(scope, key, now), user_id: userId } });
  return { ok: true, count: cnt + 1 };
}

module.exports = async function handler(req, res) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return json(res, 500, { error: 'server env missing' });
  }

  const pathname = (req.url || '').split('?')[0];

  try {
    if (pathname === '/api/rank/top' && req.method === 'GET') {
      const top = await getTopRanks(20);
      return json(res, 200, { top });
    }

    if (pathname === '/api/run/start' && req.method === 'POST') {
      const ip = safeIp(req);
      const ua = String(req.headers['user-agent'] || '').slice(0, 140);
      if (MAINTENANCE_MODE && !isAdminReq(req)) {
        return json(res, 503, { error: 'server maintenance' });
      }
      if (!sameOriginGuard(req)) {
        await putSecurityLog('blocked-origin-run-start', `${ip}|${ua}`);
        return json(res, 403, { error: 'forbidden origin' });
      }
      if (suspiciousUa(ua)) {
        await putSecurityLog('blocked-ua-run-start', `${ip}|${ua}`);
        return json(res, 403, { error: 'forbidden client' });
      }

      const rl = await checkRateLimit('run-ip', ip, 20, 60);
      if (!rl.ok) {
        await putSecurityLog('run-start-rate-limit', `${ip}|${ua}`);
        return json(res, 429, { error: 'too many run starts' });
      }

      const userId = await ensureGameUserId();
      if (!userId) return json(res, 500, { error: 'game user init failed' });

      const runToken = runTokenFor();
      const ins = await sb('sessions', { method: 'POST', body: { token: runToken, user_id: userId } });
      if (!ins.ok) return json(res, 500, { error: 'run start failed' });
      return json(res, 200, { ok: true, runToken });
    }

    if (pathname === '/api/rank/submit' && req.method === 'POST') {
      const { name, score, runToken } = parseBody(req);
      const cleanName = String(name || '').trim().slice(0, 20);
      const cleanScore = Number(score);
      const ip = safeIp(req);
      const ua = String(req.headers['user-agent'] || '').slice(0, 140);
      if (MAINTENANCE_MODE && !isAdminReq(req)) {
        return json(res, 503, { error: 'server maintenance' });
      }

      if (!sameOriginGuard(req)) {
        await putSecurityLog('blocked-origin-rank-submit', `${ip}|${ua}`);
        return json(res, 403, { error: 'forbidden origin' });
      }
      if (suspiciousUa(ua)) {
        await putSecurityLog('blocked-ua-rank-submit', `${ip}|${ua}`);
        return json(res, 403, { error: 'forbidden client' });
      }

      if (!cleanName) return json(res, 400, { error: 'name required' });
      if (!Number.isFinite(cleanScore) || cleanScore < 0) return json(res, 400, { error: 'score invalid' });
      if (!runToken) {
        await putSecurityLog('missing-run-token', `${ip}|${ua}|${cleanName}|${cleanScore}`);
        return json(res, 400, { error: 'run token required' });
      }

      // 1) IP 단위 제출 제한: 30초 5회
      const ipLimit = await checkRateLimit('rank-ip', ip, 5, 30);
      if (!ipLimit.ok) {
        await putSecurityLog('ip-rate-limit', `${ip}|${ua}`);
        return json(res, 429, { error: 'too many submits (ip)' });
      }

      // 2) 같은 이름 과다 제출 제한: 60초 3회
      const nameLimit = await checkRateLimit('rank-name', cleanName.toLowerCase(), 3, 60);
      if (!nameLimit.ok) {
        await putSecurityLog('name-rate-limit', `${cleanName}|${ip}`);
        return json(res, 429, { error: 'too many submits (name)' });
      }

      const run = parseRunToken(String(runToken));
      if (!run) {
        await putSecurityLog('bad-run-token', `${ip}|${ua}|${runToken}`);
        return json(res, 400, { error: 'run token invalid' });
      }

      const now = Date.now();
      if (now - run.ts > 10 * 60 * 1000) {
        await putSecurityLog('expired-run-window', `${ip}|${ua}|${runToken}`);
        return json(res, 400, { error: 'run token timeout' });
      }

      const elapsedSec = Math.max(0, (now - run.ts) / 1000);
      const maxPlausible = Math.floor(elapsedSec * 8 + 30); // generous upper bound
      if (cleanScore > maxPlausible || cleanScore > 5000) {
        await putSecurityLog('abnormal-score', `${ip}|${ua}|${cleanName}|${cleanScore}|max:${maxPlausible}`);
        return json(res, 400, { error: 'score rejected (abnormal)' });
      }

      const tokenCheck = await sb(`sessions?select=token&token=eq.${encodeURIComponent(String(runToken))}&limit=1`);
      if (!tokenCheck.ok || !Array.isArray(tokenCheck.data) || !tokenCheck.data[0]) {
        await putSecurityLog('expired-run-token', `${ip}|${ua}|${runToken}`);
        return json(res, 400, { error: 'run token expired' });
      }

      await sb(`sessions?token=eq.${encodeURIComponent(String(runToken))}`, { method: 'DELETE' });

      const userId = await ensureGameUserId();
      if (!userId) return json(res, 500, { error: 'game user init failed' });

      const token = rankTokenFor(Math.floor(cleanScore), cleanName);
      const ins = await sb('sessions', { method: 'POST', body: { token, user_id: userId } });
      if (!ins.ok) return json(res, 500, { error: 'submit failed' });

      const top = await getTopRanks(20);
      return json(res, 200, { ok: true, top });
    }

    if (pathname === '/api/bug/list' && req.method === 'GET') {
      if ((req.headers['x-bug-admin-key'] || '') !== BUG_ADMIN_KEY) {
        return json(res, 401, { error: 'admin only' });
      }

      const r = await sb('sessions?select=token&token=like.bug:*&order=token.desc&limit=500');
      if (!r.ok || !Array.isArray(r.data)) return json(res, 200, { bugs: [] });
      const bugs = r.data
        .map((x) => {
          const p = parseBugToken(x.token);
          if (!p) return null;
          return { token: x.token, ...p };
        })
        .filter(Boolean)
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 200)
        .map((b) => ({
          token: b.token,
          name: b.name,
          text: b.text,
          at: b.ts
        }));
      return json(res, 200, { bugs });
    }

    if (pathname === '/api/bug/submit' && req.method === 'POST') {
      const ip = safeIp(req);
      const ua = String(req.headers['user-agent'] || '').slice(0, 140);
      if (!sameOriginGuard(req)) {
        await putSecurityLog('blocked-origin-bug-submit', `${ip}|${ua}`);
        return json(res, 403, { error: 'forbidden origin' });
      }

      const bugLimit = await checkRateLimit('bug-ip', ip, 10, 60);
      if (!bugLimit.ok) {
        await putSecurityLog('bug-rate-limit', `${ip}|${ua}`);
        return json(res, 429, { error: 'too many reports' });
      }

      const { name, text } = parseBody(req);
      const cleanName = String(name || '').trim().slice(0, 20) || '익명';
      const cleanText = String(text || '').trim().slice(0, 300);
      if (!cleanText) return json(res, 400, { error: 'text required' });

      const userId = await ensureGameUserId();
      if (!userId) return json(res, 500, { error: 'game user init failed' });

      const uaRaw = req.headers['user-agent'] || '';
      const token = bugTokenFor(cleanName, cleanText, uaRaw);
      const ins = await sb('sessions', { method: 'POST', body: { token, user_id: userId } });
      if (!ins.ok) return json(res, 500, { error: 'submit failed' });

      return json(res, 200, { ok: true });
    }

    if (pathname === '/api/bug/delete' && req.method === 'POST') {
      if ((req.headers['x-bug-admin-key'] || '') !== BUG_ADMIN_KEY) {
        return json(res, 401, { error: 'admin only' });
      }
      const { token } = parseBody(req);
      if (!token) return json(res, 400, { error: 'token required' });

      const del = await sb(`sessions?token=eq.${encodeURIComponent(String(token))}`, { method: 'DELETE' });
      if (!del.ok) return json(res, 500, { error: 'delete failed' });
      return json(res, 200, { ok: true });
    }

    if (pathname === '/api/rank/clear-keep' && req.method === 'POST') {
      if ((req.headers['x-bug-admin-key'] || '') !== BUG_ADMIN_KEY) {
        return json(res, 401, { error: 'admin only' });
      }
      const { name } = parseBody(req);
      const keepName = String(name || '').trim();
      if (!keepName) return json(res, 400, { error: 'name required' });

      const r = await sb('sessions?select=token&token=like.rank:*&limit=5000');
      if (!r.ok || !Array.isArray(r.data)) return json(res, 500, { error: 'load failed' });

      const toDelete = r.data.filter((row) => {
        const p = parseRankToken(row.token);
        if (!p) return false;
        return p.name !== keepName;
      });

      for (const row of toDelete) {
        await sb(`sessions?token=eq.${encodeURIComponent(String(row.token))}`, { method: 'DELETE' });
      }

      const top = await getTopRanks(20);
      return json(res, 200, { ok: true, deleted: toDelete.length, top });
    }

    if (pathname === '/api/rank/clean-abnormal' && req.method === 'POST') {
      if ((req.headers['x-bug-admin-key'] || '') !== BUG_ADMIN_KEY) {
        return json(res, 401, { error: 'admin only' });
      }

      const r = await sb('sessions?select=token&token=like.rank:*&limit=5000');
      if (!r.ok || !Array.isArray(r.data)) return json(res, 500, { error: 'load failed' });

      const toDelete = r.data.filter((row) => {
        const p = parseRankToken(row.token);
        return p && p.score > 5000;
      });

      for (const row of toDelete) {
        await sb(`sessions?token=eq.${encodeURIComponent(String(row.token))}`, { method: 'DELETE' });
      }

      const top = await getTopRanks(20);
      return json(res, 200, { ok: true, deleted: toDelete.length, top });
    }

    if (pathname === '/api/security/logs' && req.method === 'GET') {
      if ((req.headers['x-bug-admin-key'] || '') !== BUG_ADMIN_KEY) {
        return json(res, 401, { error: 'admin only' });
      }
      const r = await sb('sessions?select=token&token=like.sec:*&order=token.desc&limit=100');
      const rows = (r.ok && Array.isArray(r.data)) ? r.data : [];
      const logs = rows.map((x) => String(x.token || '')).map((t) => {
        const p = t.split(':');
        return {
          raw: t,
          kind: p[1] || 'unknown',
          at: Number(p[2] || 0),
          payload: decodeURIComponent(p.slice(3).join(':') || '')
        };
      });
      return json(res, 200, { logs });
    }

    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: 'server error' });
  }
};
