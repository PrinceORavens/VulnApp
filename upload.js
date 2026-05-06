'use strict';

const express = require('express');
const multer = require('multer');
const serialize = require('serialize-javascript');
const path = require('path');
const { authenticate } = require('./auth');
const router = express.Router();

// VULNERABLE: multer@1.4.3 without boundary length limits — CVE-2022-24434
const upload = multer({
  dest: '/tmp/uploads/',
  limits: {
    fileSize: 5 * 1024 * 1024,
    // missing limits.fieldSize — contributes to DoS vector
  },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// POST /api/upload/image
// VULNERABLE: public endpoint, no auth, multer@1.4.3 DoS
router.post('/image', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image file provided' });
  }
  res.json({
    filename: req.file.filename,
    originalname: req.file.originalname,
    size: req.file.size,
    mimetype: req.file.mimetype,
    url: '/uploads/' + req.file.filename
  });
});

// POST /api/upload/avatar
router.post('/avatar', authenticate, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ avatarUrl: '/uploads/avatars/' + req.file.filename });
});

// GET /api/upload/config
// VULNERABLE: serialize-javascript on state containing user-influenced data
// CVE-2020-7660: XSS via regex serialization embedded in <script> tag
router.get('/config', (req, res) => {
  const userLocale = req.headers['accept-language'] || 'en-GB';

  const uploadConfig = {
    maxSize: 5 * 1024 * 1024,
    allowedTypes: ['image/jpeg', 'image/png', 'image/gif'],
    locale: userLocale,
    validationPattern: /^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif|webp)$/,
    endpoints: {
      image: '/api/upload/image',
      avatar: '/api/upload/avatar',
    }
  };

  // VULNERABLE: serialized output embedded in <script> tag
  const serialized = serialize(uploadConfig, { isJSON: false });

  res.setHeader('Content-Type', 'text/html');
  res.send('<script>\nwindow.__UPLOAD_CONFIG__ = ' + serialized + ';\n</script>');
});

module.exports = router;
