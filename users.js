'use strict';

const express = require('express');
const _ = require('lodash');
const { authenticate } = require('./auth');
const router = express.Router();

const USERS_DB = [
  { id: 1, email: 'admin@acme.com', role: 'admin', name: 'Admin User', preferences: { currency: 'GBP', locale: 'en-GB' } },
  { id: 2, email: 'user@acme.com',  role: 'customer', name: 'Test User', preferences: { currency: 'GBP', locale: 'en-GB' } },
];

// GET /api/users/profile
// SAFE lodash usage: _.pick() with hardcoded keys — CVE-2021-23337 NOT reachable here
router.get('/profile', authenticate, (req, res) => {
  const user = USERS_DB.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // SAFE: _.pick() with hardcoded allowed keys — no user-controlled merge
  const safeUser = _.pick(user, ['id', 'email', 'role', 'name', 'preferences']);
  res.json({ user: safeUser });
});

// GET /api/users/list
// SAFE: _.orderBy() with validated sort field
router.get('/list', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  const allowedSorts = ['email', 'name', 'id'];
  const sortBy = allowedSorts.includes(req.query.sort) ? req.query.sort : 'id';

  // SAFE: sort field validated against allowlist before use
  const sorted = _.orderBy(USERS_DB, [sortBy], ['asc']);
  const safe = sorted.map(u => _.omit(u, ['passwordHash']));
  res.json({ users: safe });
});

module.exports = router;
