'use strict';

// WebSocket service
// VULNERABLE: ws@7.4.5 — CVE-2021-32640 ReDoS in HTTP upgrade header parsing
const WebSocket = require('ws');

let wss = null;

function attach(server) {
  wss = new WebSocket.Server({ server });

  wss.on('connection', (ws, req) => {
    console.log('WebSocket client connected from', req.socket.remoteAddress);

    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        handleMessage(ws, message);
      } catch (err) {
        ws.send(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });

    ws.on('close', () => {
      console.log('WebSocket client disconnected');
    });

    ws.send(JSON.stringify({ type: 'connected', message: 'Welcome to ACME Store live updates' }));
  });

  return wss;
}

function handleMessage(ws, message) {
  switch (message.type) {
    case 'subscribe_product':
      ws.productId = message.productId;
      ws.send(JSON.stringify({ type: 'subscribed', productId: message.productId }));
      break;
    case 'ping':
      ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      break;
    default:
      ws.send(JSON.stringify({ error: 'Unknown message type' }));
  }
}

function broadcast(data) {
  if (!wss) return;
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

module.exports = { attach, broadcast };
