'use strict';

/**
 * Product Routes
 * Uses: lodash@4.17.20 (CVE-2021-23337 - prototype pollution via _.merge)
 *       marked@2.0.0 (CVE-2022-21681 - ReDoS)
 */

const express = require('express');
const _ = require('lodash');
const { marked } = require('marked');
const { authenticate } = require('./auth');
const router = express.Router();

// Mock product store
let PRODUCTS = [
  { id: 1, name: 'Widget Pro',   price: 29.99, category: 'electronics', description: '**Bold** description', stock: 100, meta: {} },
  { id: 2, name: 'Gadget Plus',  price: 49.99, category: 'electronics', description: 'A great _gadget_',      stock: 50,  meta: {} },
  { id: 3, name: 'Doohickey',    price: 9.99,  category: 'accessories', description: 'Simple product',        stock: 200, meta: {} },
];

/**
 * GET /api/products
 * Safe - no vulnerability here
 */
router.get('/', (req, res) => {
  const { category, sort } = req.query;

  let products = [...PRODUCTS];
  if (category) products = products.filter(p => p.category === category);
  if (sort === 'price') products.sort((a, b) => a.price - b.price);

  res.json({ products, total: products.length });
});

/**
 * GET /api/products/:id
 * Renders description as Markdown
 * ⚠ VULNERABLE: marked@2.0.0 (CVE-2022-21681 ReDoS)
 *   However: description is from DB (trusted), not user input
 *   → AI should determine this is NOT directly exploitable via user input
 */
router.get('/:id', (req, res) => {
  const product = PRODUCTS.find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // marked() called on DB content (not raw user input)
  const renderedDescription = marked(product.description);
  res.json({ ...product, descriptionHtml: renderedDescription });
});

/**
 * PUT /api/products/:id
 * ⚠ VULNERABLE: _.merge() called with user-controlled req.body
 * CVE-2021-23337: Prototype Pollution
 * AI should flag this as REACHABLE — direct user input to _.merge()
 */
router.put('/:id', authenticate, (req, res) => {
  const product = PRODUCTS.find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // ⚠ VULNERABLE: merging user input directly into product object
  // Attacker can send: {"__proto__": {"isAdmin": true}}
  _.merge(product, req.body);

  res.json({ product, updated: true });
});

/**
 * POST /api/products
 * ⚠ VULNERABLE: _.merge() with user input again
 */
router.post('/', authenticate, (req, res) => {
  const newProduct = { id: PRODUCTS.length + 1, meta: {}, stock: 0 };

  // ⚠ VULNERABLE: user controls the merge source
  _.merge(newProduct, req.body);

  PRODUCTS.push(newProduct);
  res.status(201).json({ product: newProduct });
});

/**
 * POST /api/products/:id/review
 * ⚠ POTENTIALLY VULNERABLE: marked() on user-supplied review text
 *   AI needs to determine: is this user input? Yes.
 *   Is it rendered server-side or client-side? Check template rendering.
 */
router.post('/:id/review', authenticate, (req, res) => {
  const { reviewText, rating } = req.body;

  // marked() on user input — context-dependent XSS risk
  const renderedReview = marked(reviewText || '');

  res.json({
    productId: req.params.id,
    review: { text: reviewText, html: renderedReview, rating },
    message: 'Review submitted'
  });
});

module.exports = router;
