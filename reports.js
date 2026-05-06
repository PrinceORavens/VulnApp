'use strict';

/**
 * Reports Routes
 * Uses: handlebars@4.5.3 (CVE-2021-23369 - RCE via prototype pollution)
 *       minimist@1.2.5 (CVE-2021-44906 - prototype pollution)
 */

const express = require('express');
const Handlebars = require('handlebars');
const minimist = require('minimist');
const { authenticate } = require('./auth');
const router = express.Router();

// Hardcoded report templates (NOT user-supplied)
const REPORT_TEMPLATES = {
  summary: `
    <h1>Order Summary for {{customerName}}</h1>
    <p>Total orders: {{totalOrders}}</p>
    <p>Total spent: £{{totalSpent}}</p>
    <ul>
      {{#each orders}}
        <li>{{this.id}} - £{{this.total}} - {{this.status}}</li>
      {{/each}}
    </ul>
  `,
  invoice: `
    <h1>Invoice #{{invoiceNumber}}</h1>
    <p>Date: {{date}}</p>
    <p>To: {{customerName}}</p>
    <p>Amount: £{{amount}}</p>
  `
};

/**
 * GET /api/reports/order-summary
 * ⚠ VULNERABLE: handlebars@4.5.3 (CVE-2021-23369)
 * BUT: template is hardcoded — data is user-supplied but template is SAFE
 * AI should assess: template not user-controlled → lower risk
 * Data values are still reflected, but not template structure
 */
router.get('/order-summary', authenticate, (req, res) => {
  const data = {
    customerName: req.user.email,
    totalOrders: 5,
    totalSpent: '247.50',
    orders: [
      { id: 'ORD-001', total: '49.99', status: 'delivered' },
      { id: 'ORD-002', total: '197.51', status: 'processing' }
    ]
  };

  // Template is from REPORT_TEMPLATES (hardcoded) — CVE-2021-23369 lower risk
  const template = Handlebars.compile(REPORT_TEMPLATES.summary);
  const html = template(data);

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

/**
 * POST /api/reports/custom
 * ⚠ HIGHLY VULNERABLE: user supplies BOTH template AND data
 * CVE-2021-23369: prototype pollution → RCE possible when user controls template
 * AI should flag as CONFIRMED REACHABLE
 */
router.post('/custom', authenticate, (req, res) => {
  const { template: userTemplate, data: userData } = req.body;

  if (!userTemplate) {
    return res.status(400).json({ error: 'Template required' });
  }

  try {
    // ⚠ HIGHLY VULNERABLE: user-supplied template compiled and executed
    // CVE-2021-23369: crafted template can achieve RCE via prototype pollution
    const template = Handlebars.compile(userTemplate);
    const html = template(userData || {});

    res.json({ html, generated: true });
  } catch (err) {
    res.status(400).json({ error: 'Template error', detail: err.message });
  }
});

/**
 * GET /api/reports/parse-options
 * ⚠ VULNERABLE: minimist@1.2.5 (CVE-2021-44906 - prototype pollution)
 * User controls the args string being parsed
 */
router.get('/parse-options', (req, res) => {
  const { args } = req.query;

  if (!args) return res.json({ options: {} });

  // ⚠ VULNERABLE: minimist on user-supplied input without prototype protection
  // Attacker can send: ?args=--__proto__.polluted=yes
  const options = minimist(args.split(' '));

  res.json({ options });
});

module.exports = router;
