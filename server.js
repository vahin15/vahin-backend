// ═══════════════════════════════════════════════════════════════
//  VAHIN CONNECT — Notification & Presence Backend
//  Express + ws (WebSocket) + web-push
//  Storage: flat JSON file (swap for a real DB later if you scale)
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8787;
const DB_PATH = path.join(__dirname, 'data', 'subscriptions.json');

// ── VAPID keys ──
// Generated once with webpush.generateVAPIDKeys(). In production, set these
// via environment variables instead of hardcoding.
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || 'BK0ff9D-ym_kVEhPLM8I0d9gJkrcarp1-I-j1JsYFh_WcTxjRls7f2kOM8TFbK9XjfzXqZ-aeQVnyK1aRLmb_lc';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || 'cuOUHy0XgC6Mulf4ml4u0FseVY8MakVPY03K58JH8pA';
const VAPID_SUBJECT     = process.env.VAPID_SUBJECT || 'mailto:admin@vahinconnect.example';

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// ── Tiny flat-file "database" ──
// Shape: { "vahin007": [ {endpoint, keys:{p256dh,auth}}, ... ], ... }
function loadDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return {};
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8') || '{}');
  } catch (e) { return {}; }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
let db = loadDB();

// ── App ──
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

app.get('/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

// Register / update a push subscription for a given Vahin ID.
// A user can have multiple subscriptions (multiple devices/browsers).
app.post('/subscribe', (req, res) => {
  const { id, subscription } = req.body || {};
  if (!id || !subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'id and subscription required' });
  }
  const cleanId = String(id).toLowerCase().trim();
  db[cleanId] = (db[cleanId] || []).filter(s => s.endpoint !== subscription.endpoint);
  db[cleanId].push(subscription);
  saveDB(db);
  res.json({ ok: true, devices: db[cleanId].length });
});

// Remove a subscription (e.g. user signed out / disabled notifications on this device).
app.post('/unsubscribe', (req, res) => {
  const { id, endpoint } = req.body || {};
  if (!id || !endpoint) return res.status(400).json({ error: 'id and endpoint required' });
  const cleanId = String(id).toLowerCase().trim();
  if (db[cleanId]) {
    db[cleanId] = db[cleanId].filter(s => s.endpoint !== endpoint);
    if (!db[cleanId].length) delete db[cleanId];
    saveDB(db);
  }
  res.json({ ok: true });
});

// Trigger a push notification to a target Vahin ID.
// Used for: incoming call, new DM, new group message, conference invite.
// Body: { to, type: 'call'|'message'|'group'|'conf', from, text? }
app.post('/notify', async (req, res) => {
  const { to, type, from, text } = req.body || {};
  if (!to || !type || !from) return res.status(400).json({ error: 'to, type, from required' });
  const cleanTo = String(to).toLowerCase().trim();
  const subs = db[cleanTo];

  // If the recipient is connected live via WebSocket right now, the frontend
  // will already be ringing them through PeerJS — we still push as a backup
  // (covers backgrounded tabs / closed-but-installed PWA), but we skip if
  // they have zero registered subscriptions.
  if (!subs || !subs.length) {
    return res.json({ ok: true, delivered: 0, reason: 'no subscriptions for this id' });
  }

  const payload = JSON.stringify({
    type,                 // 'call' | 'message' | 'group' | 'conf'
    from,                 // sender's Vahin ID
    text: text || '',     // message preview, if any
    ts: Date.now(),
  });

  let delivered = 0;
  const stillValid = [];
  for (const sub of subs) {
    try {
      await webpush.sendNotification(sub, payload);
      delivered++;
      stillValid.push(sub);
    } catch (err) {
      // 404/410 = subscription expired or unsubscribed on the client; drop it.
      if (err.statusCode !== 404 && err.statusCode !== 410) {
        stillValid.push(sub); // keep on transient errors (network hiccup etc.)
      }
    }
  }
  db[cleanTo] = stillValid;
  if (!stillValid.length) delete db[cleanTo];
  saveDB(db);

  res.json({ ok: true, delivered, total: subs.length });
});

// ── Presence (lightweight WebSocket hub) ──
// This is NOT required for calls to work (PeerJS's own cloud server handles
// call signaling already), but it gives instant "online/offline" status
// without the polling-based presence probe the frontend used before.
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/presence' });

// id -> Set of live sockets (multi-tab/device support)
const liveSockets = new Map();

function broadcastPresence(id, online) {
  const msg = JSON.stringify({ type: 'presence', id, online });
  for (const sockets of liveSockets.values()) {
    for (const ws of sockets) {
      if (ws.readyState === ws.OPEN) {
        try { ws.send(msg); } catch (e) {}
      }
    }
  }
}

wss.on('connection', (ws) => {
  let myId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === 'hello' && msg.id) {
      myId = String(msg.id).toLowerCase().trim();
      if (!liveSockets.has(myId)) liveSockets.set(myId, new Set());
      liveSockets.get(myId).add(ws);
      broadcastPresence(myId, true);

      // tell the newly-connected client who else is currently online
      const onlineIds = Array.from(liveSockets.keys());
      ws.send(JSON.stringify({ type: 'roster', ids: onlineIds }));
    }

    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
  });

  ws.on('close', () => {
    if (myId && liveSockets.has(myId)) {
      liveSockets.get(myId).delete(ws);
      if (liveSockets.get(myId).size === 0) {
        liveSockets.delete(myId);
        broadcastPresence(myId, false);
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`Vahin Connect backend listening on :${PORT}`);
  console.log(`VAPID public key: ${VAPID_PUBLIC_KEY}`);
});
