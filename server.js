const http = require('http');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 3000;

// PostgreSQL connection - v2 ssl:false fix
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
});

async function setupDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    const hash = await bcrypt.hash('1234', 12);
    await pool.query(`
      INSERT INTO users (username, password_hash)
      VALUES ('Gonza', $1)
      ON CONFLICT (username) DO NOTHING
    `, [hash]);
    console.log('DB lista. Usuario Gonza creado.');
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

async function handleLogin(req, res) {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const { username, password } = JSON.parse(body);
      if (!username || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Faltan datos.' }));
        return;
      }
      const result = await pool.query(
        'SELECT username, password_hash FROM users WHERE username = $1 LIMIT 1',
        [username]
      );
      if (result.rows.length === 0) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Credenciales inválidas.' }));
        return;
      }
      const user = result.rows[0];
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Credenciales inválidas.' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'OK', username: user.username }));
    } catch (err) {
      console.error('Login error:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Error interno.' }));
    }
  });
}

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];

  if (req.method === 'POST' && url === '/api/login') {
    handleLogin(req, res);
    return;
  }

  const routes = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/login.html': 'login.html',
  };

  const file = routes[url];
  if (file) {
    const ext = path.extname(file);
    const types = { '.html': 'text/html; charset=utf-8' };
    serveFile(res, path.join(__dirname, file), types[ext] || 'text/plain');
  } else {
    res.writeHead(404); res.end('Not found');
  }
});

server.listen(PORT, async () => {
  console.log(`Corriendo en puerto ${PORT}`);
  await setupDB();
});
