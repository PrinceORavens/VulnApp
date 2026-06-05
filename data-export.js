'use strict';

/**
 * Data Export Service
 * Uses: serialize-javascript@2.1.1 (CVE-2020-7660 - XSS via regex/function serialisation)
 *
 * This module deliberately creates a multi-hop call chain for Sentinel SCA call graph testing:
 *   POST /api/orders/export
 *     → handleExport (orders.js)
 *     → buildExportPayload (this file)
 *     → serialize (serialize-javascript)
 *
 * With the AST-backed call graph (III-K), Sentinel should trace this cross-file
 * chain and correctly mark serialize() as HTTP-reachable from the POST route.
 */

const serialize = require('serialize-javascript');

/**
 * Builds a serialised payload from order data for client-side hydration.
 *
 * ⚠ VULNERABLE: serialize-javascript@2.1.1 (CVE-2020-7660)
 * If orderData contains a RegExp or Function, the serialised output may be
 * unsafely rendered into a <script> tag, enabling XSS.
 *
 * The caller (orders.js handleExport) passes req.body directly here,
 * which means user-controlled content flows to serialize().
 */
function buildExportPayload(orderData) {
  // serialize() with user-supplied data — exploitable if output is injected into HTML
  return serialize(orderData, { isJSON: false });
}

/**
 * Generates a downloadable export bundle for an order.
 * Wraps the serialised payload in a JS module format for client-side consumption.
 */
function generateOrderExport(orderData, format = 'js') {
  const payload = buildExportPayload(orderData);

  if (format === 'js') {
    return `window.__ORDER_DATA__ = ${payload};`;
  }

  return payload;
}

module.exports = { buildExportPayload, generateOrderExport };
