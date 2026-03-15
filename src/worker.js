// ── BlackRoad Auth — Sovereign Authentication ──
// D1-backed, JWT sessions, password hashing via Web Crypto
// Zero third-party auth dependencies

const CORS_HEADERS = (origin, env) => {
  const allowed = (env.ALLOWED_ORIGINS || '').split(',');
  const o = allowed.includes(origin) ? origin : allowed[0];
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
};

// ── Crypto helpers (Web Crypto API, no external deps) ──
async function hashPassword(password, salt) {
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  const saltB64 = btoa(String.fromCharCode(...salt));
  return `${saltB64}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [saltB64] = stored.split(':');
  const salt = new Uint8Array(atob(saltB64).split('').map(c => c.charCodeAt(0)));
  const result = await hashPassword(password, salt);
  return result === stored;
}

async function createJWT(payload, secret, expiresIn = 86400) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expiresIn, iss: 'blackroad.io' };

  const enc = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
  const bodyB64 = btoa(JSON.stringify(body)).replace(/=/g, '');
  const data = `${headerB64}.${bodyB64}`;

  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const [headerB64, bodyB64, sigB64] = token.split('.');
    const data = `${headerB64}.${bodyB64}`;
    const enc = new TextEncoder();

    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, enc.encode(data));

    if (!valid) return null;

    const body = JSON.parse(atob(bodyB64));
    if (body.exp < Math.floor(Date.now() / 1000)) return null;

    return body;
  } catch {
    return null;
  }
}

function generateId() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, b => b.toString(36).padStart(2, '0')).join('').slice(0, 20);
}

// ── DB Schema ──
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'operator',
  stripe_customer_id TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch()),
  last_login INTEGER,
  metadata TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`;

// ── Route handlers ──
async function handleSignup(request, env) {
  const { email, password, name } = await request.json();

  if (!email || !password) {
    return Response.json({ error: 'Email and password required' }, { status: 400 });
  }
  if (password.length < 8) {
    return Response.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
  }
  if (!email.includes('@')) {
    return Response.json({ error: 'Invalid email' }, { status: 400 });
  }

  // Check if user exists
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) {
    return Response.json({ error: 'Email already registered' }, { status: 409 });
  }

  const id = generateId();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(
    'INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), name || '', passwordHash).run();

  // Create session
  const token = await createJWT({ sub: id, email: email.toLowerCase(), name: name || '', plan: 'operator' }, env.JWT_SECRET || 'blackroad-secret-change-me');

  // Store session
  const sessionId = generateId();
  const tokenHash = await hashPassword(token.slice(-16));
  const expiresAt = Math.floor(Date.now() / 1000) + 86400 * 30; // 30 days
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(sessionId, id, tokenHash, expiresAt, request.headers.get('cf-connecting-ip') || '', request.headers.get('user-agent') || '').run();

  return Response.json({
    user: { id, email: email.toLowerCase(), name: name || '', plan: 'operator' },
    token,
    expiresAt,
  });
}

async function handleSignin(request, env) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return Response.json({ error: 'Email and password required' }, { status: 400 });
  }

  const user = await env.DB.prepare(
    'SELECT id, email, name, password_hash, plan, metadata FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (!user) {
    return Response.json({ error: 'Invalid email or password' }, { status: 401 });
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return Response.json({ error: 'Invalid email or password' }, { status: 401 });
  }

  // Update last login
  await env.DB.prepare('UPDATE users SET last_login = unixepoch(), updated_at = unixepoch() WHERE id = ?').bind(user.id).run();

  // Create session
  const token = await createJWT({
    sub: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan,
  }, env.JWT_SECRET || 'blackroad-secret-change-me', 86400 * 30);

  const sessionId = generateId();
  const tokenHash = await hashPassword(token.slice(-16));
  const expiresAt = Math.floor(Date.now() / 1000) + 86400 * 30;
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(sessionId, user.id, tokenHash, expiresAt, request.headers.get('cf-connecting-ip') || '', request.headers.get('user-agent') || '').run();

  return Response.json({
    user: { id: user.id, email: user.email, name: user.name, plan: user.plan },
    token,
    expiresAt,
  });
}

async function handleMe(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const token = auth.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET || 'blackroad-secret-change-me');
  if (!payload) {
    return Response.json({ error: 'Invalid or expired token' }, { status: 401 });
  }

  const user = await env.DB.prepare(
    'SELECT id, email, name, plan, stripe_customer_id, created_at, last_login, metadata FROM users WHERE id = ?'
  ).bind(payload.sub).first();

  if (!user) {
    return Response.json({ error: 'User not found' }, { status: 404 });
  }

  return Response.json({ user });
}

async function handleSignout(request, env) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const payload = await verifyJWT(token, env.JWT_SECRET || 'blackroad-secret-change-me');
    if (payload) {
      // Delete all sessions for this user
      await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(payload.sub).run();
    }
  }
  return Response.json({ ok: true });
}

async function handleUpdateUser(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET || 'blackroad-secret-change-me');
  if (!payload) {
    return Response.json({ error: 'Invalid token' }, { status: 401 });
  }

  const body = await request.json();
  const updates = [];
  const values = [];

  if (body.name !== undefined) { updates.push('name = ?'); values.push(body.name); }
  if (body.metadata !== undefined) { updates.push('metadata = ?'); values.push(JSON.stringify(body.metadata)); }

  if (body.password) {
    if (body.password.length < 8) {
      return Response.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
    }
    const hash = await hashPassword(body.password);
    updates.push('password_hash = ?');
    values.push(hash);
  }

  if (updates.length === 0) {
    return Response.json({ error: 'Nothing to update' }, { status: 400 });
  }

  updates.push('updated_at = unixepoch()');
  values.push(payload.sub);

  await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();

  return Response.json({ ok: true });
}

async function handleStats(env) {
  const users = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
  const sessions = await env.DB.prepare('SELECT COUNT(*) as count FROM sessions WHERE expires_at > unixepoch()').first();
  return Response.json({
    users: users?.count || 0,
    active_sessions: sessions?.count || 0,
    status: 'up',
  });
}

// ── Main ──
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = request.headers.get('Origin') || '';
    const cors = CORS_HEADERS(origin, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    // Init DB on first request
    if (path === '/api/init' || path === '/init') {
      const statements = SCHEMA.split(';').filter(s => s.trim());
      for (const sql of statements) {
        await env.DB.prepare(sql).run();
      }
      return Response.json({ ok: true, message: 'Schema initialized' }, { headers: cors });
    }

    try {
      let response;

      switch (path) {
        case '/api/signup':
          if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
          response = await handleSignup(request, env);
          break;

        case '/api/signin':
          if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
          response = await handleSignin(request, env);
          break;

        case '/api/me':
          response = await handleMe(request, env);
          break;

        case '/api/signout':
          response = await handleSignout(request, env);
          break;

        case '/api/user':
          if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
          response = await handleUpdateUser(request, env);
          break;

        case '/api/stats':
          response = await handleStats(env);
          break;

        case '/api/health':
          response = Response.json({ status: 'up', service: 'auth-blackroad' });
          break;

        default:
          response = Response.json({
            service: 'BlackRoad Auth',
            version: '1.0.0',
            endpoints: ['/api/signup', '/api/signin', '/api/me', '/api/signout', '/api/user', '/api/stats', '/api/health'],
            docs: 'POST /api/signup {email, password, name} → {user, token}',
          });
      }

      // Add CORS headers to response
      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(cors)) headers.set(k, v);
      return new Response(response.body, { status: response.status, headers });

    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: cors });
    }
  },
};
