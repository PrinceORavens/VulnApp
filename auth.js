'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-dev-key';

const USERS = [
  { id: 1, email: 'admin@acme.com', passwordHash: '$2b$10$examplehashhere', role: 'admin' },
  { id: 2, email: 'user@acme.com',  passwordHash: '$2b$10$examplehashhere', role: 'customer' },
];

// POST /api/auth/login
// VULNERABLE: jwt.sign without algorithms option — CVE-2022-23529
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = USERS.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash).catch(() => false);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  // VULNERABLE: no algorithms option
  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

// POST /api/auth/verify
// VULNERABLE: jwt.verify without algorithms restriction
router.post('/verify', (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, JWT_SECRET); // missing { algorithms: ['HS256'] }
    res.json({ valid: true, payload: decoded });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET); // VULNERABLE: no algorithms option
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

router.get('/me', authenticate, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
module.exports.authenticate = authenticate;
