export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  const SUPABASE_URL = env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
  const BUG_ADMIN_KEY = env.BUG_ADMIN_KEY || 'ddsd';
  const MAINTENANCE_MODE = false;

  const json = (status, data) => new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...corsHeaders(request)
    }
  });

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return json(500, { error: 'server env missing' });
  }

  async function sb(apiPath, { method = 'GET', body } = {}) {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${apiPath}`, {
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

  const parseBody = async () => {
    try { return await request.json(); } catch { return {}; }
  };

  const GAME_USER_NAME = '__game__';
  const GAME_USER_ID = '__rank__';

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

  function isSuspiciousAutoName(name = '') {
    const n = String(name || '').trim();
    return /^플레이어\d{3}$/i.test(n) || /^player\d{3}$/i.test(n);
  }

  function bugTokenFor(name, text, ua = '') {
    const t = Date.now().toString().padStart(13, '0');
    const n = encodeURIComponent(name || '익명');
    const m = encodeURIComponent(String(text || '').slice(0, 300));
    const u = encodeURIComponent(String(ua || '').slice(0, 120));
    return `bug:${t}:${n}:${m}:${u}`;
  }

  function parseBugToken(token) {
    if (!token || !token.startsWith('bug:')) return null;
    const parts = token.split(':');
    if (parts.length < 5) return null;
    const ts = Number(parts[1]);
    const name = decodeURIComponent(parts[2] || '익명');
    const text = decodeURIComponent(parts[3] || '');
    if (!Number.isFinite(ts) || !text) return null;
    return { ts, name, text };
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
      if (isSuspiciousAutoName(parsed.name)) continue;
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

  const isAdminReq = () => (request.headers.get('x-bug-admin-key') || '') === BUG_ADMIN_KEY;

  try {
    if (path === '/api/rank/top' && method === 'GET') {
      const top = await getTopRanks(20);
      return json(200, { top });
    }

    if (path === '/api/run/start' && method === 'POST') {
      if (MAINTENANCE_MODE && !isAdminReq()) return json(503, { error: 'server maintenance' });
      const userId = await ensureGameUserId();
      if (!userId) return json(500, { error: 'game user init failed' });
      const runToken = runTokenFor();
      const ins = await sb('sessions', { method: 'POST', body: { token: runToken, user_id: userId } });
      if (!ins.ok) return json(500, { error: 'run start failed' });
      return json(200, { ok: true, runToken });
    }

    if (path === '/api/rank/submit' && method === 'POST') {
      if (MAINTENANCE_MODE && !isAdminReq()) return json(503, { error: 'server maintenance' });

      const { name, score, runToken } = await parseBody();
      const cleanName = String(name || '').trim().slice(0, 20);
      const cleanScore = Number(score);

      if (!cleanName) return json(400, { error: 'name required' });
      if (!Number.isFinite(cleanScore) || cleanScore < 0) return json(400, { error: 'score invalid' });
      if (!runToken) return json(400, { error: 'run token required' });

      const run = parseRunToken(String(runToken));
      if (!run) return json(400, { error: 'run token invalid' });

      const now = Date.now();
      if (now - run.ts > 10 * 60 * 1000) return json(400, { error: 'run token timeout' });

      const elapsedSec = Math.max(0, (now - run.ts) / 1000);
      const maxPlausible = Math.floor(elapsedSec * 8 + 30);
      if (cleanScore > maxPlausible || cleanScore > 5000) return json(400, { error: 'score rejected (abnormal)' });

      const tokenCheck = await sb(`sessions?select=token&token=eq.${encodeURIComponent(String(runToken))}&limit=1`);
      if (!tokenCheck.ok || !Array.isArray(tokenCheck.data) || !tokenCheck.data[0]) {
        return json(400, { error: 'run token expired' });
      }

      await sb(`sessions?token=eq.${encodeURIComponent(String(runToken))}`, { method: 'DELETE' });

      const userId = await ensureGameUserId();
      if (!userId) return json(500, { error: 'game user init failed' });

      const token = rankTokenFor(Math.floor(cleanScore), cleanName);
      const ins = await sb('sessions', { method: 'POST', body: { token, user_id: userId } });
      if (!ins.ok) return json(500, { error: 'submit failed' });

      const top = await getTopRanks(20);
      return json(200, { ok: true, top });
    }

    if (path === '/api/bug/submit' && method === 'POST') {
      const { name, text } = await parseBody();
      const cleanName = String(name || '').trim().slice(0, 20) || '익명';
      const cleanText = String(text || '').trim().slice(0, 300);
      if (!cleanText) return json(400, { error: 'text required' });

      const userId = await ensureGameUserId();
      if (!userId) return json(500, { error: 'game user init failed' });

      const ua = request.headers.get('user-agent') || '';
      const token = bugTokenFor(cleanName, cleanText, ua);
      const ins = await sb('sessions', { method: 'POST', body: { token, user_id: userId } });
      if (!ins.ok) return json(500, { error: 'submit failed' });

      return json(200, { ok: true });
    }

    if (path === '/api/bug/list' && method === 'GET') {
      if (!isAdminReq()) return json(401, { error: 'admin only' });
      const r = await sb('sessions?select=token&token=like.bug:*&order=token.desc&limit=500');
      if (!r.ok || !Array.isArray(r.data)) return json(200, { bugs: [] });
      const bugs = r.data
        .map((x) => ({ token: x.token, ...(parseBugToken(x.token) || {}) }))
        .filter((x) => x.ts)
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 200)
        .map((b) => ({ token: b.token, name: b.name, text: b.text, at: b.ts }));
      return json(200, { bugs });
    }

    if (path === '/api/bug/delete' && method === 'POST') {
      if (!isAdminReq()) return json(401, { error: 'admin only' });
      const { token } = await parseBody();
      if (!token) return json(400, { error: 'token required' });
      const del = await sb(`sessions?token=eq.${encodeURIComponent(String(token))}`, { method: 'DELETE' });
      if (!del.ok) return json(500, { error: 'delete failed' });
      return json(200, { ok: true });
    }

    if (path === '/api/rank/cleanup-suspicious' && method === 'POST') {
      if (!isAdminReq()) return json(401, { error: 'admin only' });

      const r = await sb('sessions?select=token&token=like.rank:*&limit=5000');
      if (!r.ok || !Array.isArray(r.data)) return json(500, { error: 'load failed' });

      const targets = r.data.filter((row) => {
        const p = parseRankToken(row.token);
        return p && isSuspiciousAutoName(p.name);
      });

      for (const row of targets) {
        await sb(`sessions?token=eq.${encodeURIComponent(String(row.token))}`, { method: 'DELETE' });
      }

      const top = await getTopRanks(20);
      return json(200, { ok: true, deleted: targets.length, top });
    }

    return json(404, { error: 'not found' });
  } catch (e) {
    return json(500, { error: 'server error' });
  }
}

function corsHeaders(request) {
  const origin = request.headers.get('origin') || '*';
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type,x-bug-admin-key'
  };
}
