'use strict';

const express = require('express');
const axios = require('axios');
const moment = require('moment');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const { authenticate } = require('./auth');
const router = express.Router();

const PAYMENT_SERVICE_URL = process.env.PAYMENT_SERVICE_URL || 'http://payment-svc:4000';
const SHIPPING_SERVICE_URL = process.env.SHIPPING_SERVICE_URL || 'http://shipping-svc:4002';

// SAFE: hardcoded locale — CVE-2022-24785 NOT reachable
moment.locale('en-GB');

let ORDERS = [];

// GET /api/orders
// moment used with hardcoded values only — SAFE for CVE-2022-24785
router.get('/', authenticate, (req, res) => {
  const userOrders = ORDERS.filter(o => o.userId === req.user.userId);

  const enriched = userOrders.map(order => ({
    ...order,
    createdAtFormatted: moment(order.createdAt).format('DD MMM YYYY, HH:mm'),
    relativeTime: moment(order.createdAt).fromNow(),
  }));

  res.json({ orders: enriched, total: enriched.length });
});

// POST /api/orders
// axios calls internal services only — CVE-2021-3749 low risk
router.post('/', authenticate, async (req, res) => {
  const { items, shippingAddress, paymentMethodId } = req.body;

  const orderId = uuidv4();
  const order = {
    id: orderId,
    userId: req.user.userId,
    items,
    shippingAddress,
    status: 'pending',
    createdAt: new Date().toISOString(),
    total: items?.reduce((sum, item) => sum + (item.price * item.qty), 0) || 0
  };

  try {
    // axios to INTERNAL service only — attacker would need to control TLS cert
    const paymentRes = await axios.post(PAYMENT_SERVICE_URL + '/charge', {
      orderId,
      amount: order.total,
      paymentMethodId
    }, { timeout: 5000 });

    order.paymentId = paymentRes.data.paymentId;
    order.status = 'paid';
    ORDERS.push(order);
    res.status(201).json({ order });
  } catch (err) {
    res.status(502).json({ error: 'Upstream service error', detail: err.message });
  }
});

// GET /api/orders/:id/tracking
// UNCERTAIN: node-fetch follows redirects with auth header — CVE-2022-0235
router.get('/:id/tracking', authenticate, async (req, res) => {
  const order = ORDERS.find(o => o.id === req.params.id && o.userId === req.user.userId);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  try {
    // UNCERTAIN: if shipping service redirects externally, auth header could leak
    const response = await fetch(SHIPPING_SERVICE_URL + '/track/' + order.id, {
      headers: {
        'Authorization': 'Bearer ' + process.env.INTERNAL_SERVICE_TOKEN,
        'X-Order-Id': order.id
      }
    });

    const tracking = await response.json();
    res.json({ tracking });
  } catch (err) {
    res.status(502).json({ error: 'Tracking unavailable' });
  }
});

// GET /api/orders/health
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

module.exports = router;
