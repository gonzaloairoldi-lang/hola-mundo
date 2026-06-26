const http = require('http');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
});

// In-memory session store
const sessions = {};

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function getSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies['sid'];
  if (sid && sessions[sid]) return sessions[sid];
  return null;
}

function parseCookies(req) {
  const list = {};
  const header = req.headers.cookie;
  if (!header) return list;
  header.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    list[name.trim()] = rest.join('=').trim();
  });
  return list;
}

async function setupDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        iduser SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        first_name VARCHAR(100) NOT NULL DEFAULT '',
        last_name VARCHAR(100) NOT NULL DEFAULT '',
        email VARCHAR(200) UNIQUE NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Add missing columns if upgrading from old schema
    const cols = ['first_name', 'last_name', 'email', 'role'];
    for (const col of cols) {
      await pool.query(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS ${col} 
        ${col === 'role' ? "VARCHAR(20) NOT NULL DEFAULT 'user'" : 
          col === 'email' ? "VARCHAR(200) NOT NULL DEFAULT ''" :
          "VARCHAR(100) NOT NULL DEFAULT ''"
        }
      `).catch(() => {});
    }

    // Seed admin user
    const hash = await bcrypt.hash('1234', 12);
    await pool.query(`
      INSERT INTO users (username, first_name, last_name, email, password_hash, role)
      VALUES ('Gonza', 'Gonzalo', 'Airoldi', 'gonza@aditi.com', $1, 'admin')
      ON CONFLICT (username) DO UPDATE 
      SET role = 'admin', first_name = 'Gonzalo', last_name = 'Airoldi', email = 'gonza@aditi.com'
    `, [hash]);

    console.log('DB lista.');
  } catch (err) {
    console.error('DB setup error:', err.message);
  }
}

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session) { json(res, 401, { message: 'No autorizado.' }); return null; }
  if (session.role !== 'admin') { json(res, 403, { message: 'Acceso denegado.' }); return null; }
  return session;
}

async function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

// --- Handlers ---

async function handleLogin(req, res) {
  const { username, password } = await readBody(req);
  if (!username || !password) return json(res, 400, { message: 'Faltan datos.' });
  try {
    const result = await pool.query(
      'SELECT iduser, username, first_name, last_name, role, password_hash FROM users WHERE username = $1 LIMIT 1',
      [username]
    );
    if (!result.rows.length) return json(res, 401, { message: 'Credenciales inválidas.' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return json(res, 401, { message: 'Credenciales inválidas.' });

    const sid = generateSessionId();
    sessions[sid] = { iduser: user.iduser, username: user.username, role: user.role };

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
    });
    res.end(JSON.stringify({ username: user.username, role: user.role }));
  } catch (err) {
    console.error('Login error:', err.message);
    json(res, 500, { message: 'Error interno.' });
  }
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  const sid = cookies['sid'];
  if (sid) delete sessions[sid];
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0'
  });
  res.end(JSON.stringify({ message: 'OK' }));
}

function handleMe(req, res) {
  const session = getSession(req);
  if (!session) return json(res, 401, { message: 'No autorizado.' });
  json(res, 200, session);
}

async function handleGetUsers(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    const result = await pool.query(
      'SELECT iduser, username, first_name, last_name, email, role, created_at FROM users ORDER BY iduser'
    );
    json(res, 200, result.rows);
  } catch (err) {
    json(res, 500, { message: 'Error interno.' });
  }
}

async function handleCreateUser(req, res) {
  if (!requireAdmin(req, res)) return;
  const { username, first_name, last_name, email, password, role } = await readBody(req);
  if (!username || !first_name || !last_name || !email || !password || !role)
    return json(res, 400, { message: 'Todos los campos son obligatorios.' });
  if (!['admin', 'user'].includes(role))
    return json(res, 400, { message: 'Rol inválido.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, first_name, last_name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING iduser, username, first_name, last_name, email, role`,
      [username, first_name, last_name, email, hash, role]
    );
    json(res, 201, result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return json(res, 409, { message: 'Usuario o email ya existe.' });
    json(res, 500, { message: 'Error interno.' });
  }
}

async function handleUpdateUser(req, res, iduser) {
  if (!requireAdmin(req, res)) return;
  const { username, first_name, last_name, email, password, role } = await readBody(req);
  if (!username || !first_name || !last_name || !email || !role)
    return json(res, 400, { message: 'Todos los campos son obligatorios.' });
  if (!['admin', 'user'].includes(role))
    return json(res, 400, { message: 'Rol inválido.' });
  try {
    let query, params;
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      query = `UPDATE users SET username=$1, first_name=$2, last_name=$3, email=$4, role=$5, password_hash=$6
               WHERE iduser=$7 RETURNING iduser, username, first_name, last_name, email, role`;
      params = [username, first_name, last_name, email, role, hash, iduser];
    } else {
      query = `UPDATE users SET username=$1, first_name=$2, last_name=$3, email=$4, role=$5
               WHERE iduser=$6 RETURNING iduser, username, first_name, last_name, email, role`;
      params = [username, first_name, last_name, email, role, iduser];
    }
    const result = await pool.query(query, params);
    if (!result.rows.length) return json(res, 404, { message: 'Usuario no encontrado.' });
    json(res, 200, result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return json(res, 409, { message: 'Usuario o email ya existe.' });
    json(res, 500, { message: 'Error interno.' });
  }
}

async function handleDeleteUser(req, res, iduser) {
  const session = requireAdmin(req, res);
  if (!session) return;
  if (session.iduser === parseInt(iduser))
    return json(res, 400, { message: 'No podés eliminarte a vos mismo.' });
  try {
    await pool.query('DELETE FROM users WHERE iduser = $1', [iduser]);
    json(res, 200, { message: 'Usuario eliminado.' });
  } catch (err) {
    json(res, 500, { message: 'Error interno.' });
  }
}

// --- Router ---
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method;

  // API routes
  if (url === '/api/login' && method === 'POST') return handleLogin(req, res);
  if (url === '/api/logout' && method === 'POST') return handleLogout(req, res);
  if (url === '/api/me' && method === 'GET') return handleMe(req, res);
  if (url === '/api/users' && method === 'GET') return handleGetUsers(req, res);
  if (url === '/api/users' && method === 'POST') return handleCreateUser(req, res);

  const userMatch = url.match(/^\/api\/users\/(\d+)$/);
  if (userMatch && method === 'PUT') return handleUpdateUser(req, res, userMatch[1]);
  if (userMatch && method === 'DELETE') return handleDeleteUser(req, res, userMatch[1]);

  // Static files
  const routes = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/login.html': 'login.html',
    '/admin.html': 'admin.html',
    '/welcome.html': 'welcome.html',
  };

  const file = routes[url];
  if (file) {
    serveFile(res, path.join(__dirname, file), 'text/html; charset=utf-8');
  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(PORT, async () => {
  console.log(`Corriendo en puerto ${PORT}`);
  await setupDB();
});
