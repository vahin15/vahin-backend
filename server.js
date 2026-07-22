// ═══════════════════════════════════════════════════════════════
//  VAHIN CONNECT — Notification & Presence Backend
//  Express + ws (WebSocket) + web-push + Firebase Admin (FCM)
//  Storage: flat JSON file (swap for a real DB later if you scale)
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const webpush = require('web-push');
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8787;
const DB_PATH = path.join(__dirname, 'data', 'subscriptions.json');

// ── VAPID keys (for browser Web Push — used as a fallback while the WebView
//    process is alive; NOT what wakes up a fully-killed Android app) ──
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || 'BK0ff9D-ym_kVEhPLM8I0d9gJkrcarp1-I-j1JsYFh_WcTxjRls7f2kOM8TFbK9XjfzXqZ-aeQVnyK1aRLmb_lc';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || 'cuOUHy0XgC6Mulf4ml4u0FseVY8MakVPY03K58JH8pA';
const VAPID_SUBJECT     = process.env.VAPID_SUBJECT || 'mailto:admin@vahinconnect.example';

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// ── Firebase Admin (FCM) — THIS is what actually wakes the Android app when
//    it's fully killed. The Android side (VahinMessagingService.java) sends a
//    token to POST /register-fcm, and this backend uses that token to push a
//    data-only message via admin.messaging(). Without this, /register-fcm
//    didn't even exist, so tokens were sent into the void and no FCM message
//    was ever dispatched — which is why ringing never worked.
//
//    Set FIREBASE_SERVICE_ACCOUNT_JSON to the full contents of a Firebase
//    service-account key JSON (Project settings → Service accounts → Generate
//    new private key, for project "unifest-99468"). You can paste the raw
//    JSON or a base64-encoded version of it into the env var.
let firebaseReady = false;
try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      parsed = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    }
    admin.initializeApp({ credential: admin.credential.cert(parsed) });
    firebaseReady = true;
    console.log('Firebase Admin initialized — FCM push (native ringing) is ENABLED.');
  } else {
    console.warn(
      'FIREBASE_SERVICE_ACCOUNT_JSON is not set. FCM push is DISABLED, so calls will ' +
      'NOT ring when the app is closed/killed — only the web-push fallback will fire, ' +
      'and only while the WebView process is still alive. See .env.example.'
    );
  }
} catch (e) {
  console.error('Failed to initialize Firebase Admin (check FIREBASE_SERVICE_ACCOUNT_JSON):', e.message);
}

// ── Tiny flat-file "database" ──
// Shape: { "vahin007": { push: [{endpoint, keys:{...}}, ...], fcm: ["token1", ...] } }
function loadDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return {};
    const raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8') || '{}');
    // Migrate old shape (id -> array of push subs) to the new shape.
    const migrated = {};
    for (const [id, val] of Object.entries(raw)) {
      if (Array.isArray(val)) migrated[id] = { push: val, fcm: [] };
      else migrated[id] = { push: val.push || [], fcm: val.fcm || [] };
    }
    return migrated;
  } catch (e) { return {}; }
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
function record(db, id) {
  const cleanId = String(id).toLowerCase().trim();
  if (!db[cleanId]) db[cleanId] = { push: [], fcm: [] };
  return { cleanId, entry: db[cleanId] };
}
let db = loadDB();

// ── App ──
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/health', (req, res) => res.json({ ok: true, time: Date.now(), fcmEnabled: firebaseReady }));

app.get('/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

// Register / update a browser Web Push subscription for a given Vahin ID.
app.post('/subscribe', (req, res) => {
  const { id, subscription } = req.body || {};
  if (!id || !subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'id and subscription required' });
  }
  const { cleanId, entry } = record(db, id);
  entry.push = entry.push.filter(s => s.endpoint !== subscription.endpoint);
  entry.push.push(subscription);
  saveDB(db);
  res.json({ ok: true, devices: entry.push.length });
});

app.post('/unsubscribe', (req, res) => {
  const { id, endpoint } = req.body || {};
  if (!id || !endpoint) return res.status(400).json({ error: 'id and endpoint required' });
  const cleanId = String(id).toLowerCase().trim();
  if (db[cleanId]) {
    db[cleanId].push = db[cleanId].push.filter(s => s.endpoint !== endpoint);
    if (!db[cleanId].push.length && !db[cleanId].fcm.length) delete db[cleanId];
    saveDB(db);
  }
  res.json({ ok: true });
});

// Register / update a native FCM registration token for a given Vahin ID.
// Called from the Android app (window.onFcmToken -> fetch('/register-fcm')).
// This was MISSING entirely before — the app was posting tokens to a route
// that didn't exist, so the backend never learned any device's FCM token.
app.post('/register-fcm', (req, res) => {
  const { id, token } = req.body || {};
  if (!id || !token) return res.status(400).json({ error: 'id and token required' });
  const { cleanId, entry } = record(db, id);
  if (!entry.fcm.includes(token)) entry.fcm.push(token);
  saveDB(db);
  res.json({ ok: true, devices: entry.fcm.length, fcmEnabled: firebaseReady });
});

// Optional: explicit token removal (e.g. on logout).
app.post('/unregister-fcm', (req, res) => {
  const { id, token } = req.body || {};
  if (!id || !token) return res.status(400).json({ error: 'id and token required' });
  const cleanId = String(id).toLowerCase().trim();
  if (db[cleanId]) {
    db[cleanId].fcm = db[cleanId].fcm.filter(t => t !== token);
    if (!db[cleanId].push.length && !db[cleanId].fcm.length) delete db[cleanId];
    saveDB(db);
  }
  res.json({ ok: true });
});

// Trigger a push notification to a target Vahin ID.
// Used for: incoming call, voice call, new DM, new group message, conference invite.
// Body: { to, type: 'call'|'voice-call'|'message'|'group'|'conf', from, text? }
app.post('/notify', async (req, res) => {
  const { to, type, from, text } = req.body || {};
  if (!to || !type || !from) return res.status(400).json({ error: 'to, type, from required' });
  const cleanTo = String(to).toLowerCase().trim();
  const entry = db[cleanTo];

  if (!entry || (!entry.push.length && !entry.fcm.length)) {
    return res.json({ ok: true, delivered: 0, reason: 'no subscriptions for this id' });
  }

  let fcmDelivered = 0;
  const stillValidFcm = [];
  if (firebaseReady && entry.fcm.length) {
    for (const token of entry.fcm) {
      try {
        // Data-only message: no "notification" field. This is required so
        // VahinMessagingService.onMessageReceived() runs even when the app
        // process is fully killed (Android delivers data-only FCM messages
        // to a background service; "notification" messages are only shown
        // automatically by the OS and do NOT wake app code when killed).
        await admin.messaging().send({
          token,
          data: { type: String(type), from: String(from), text: String(text || '') },
          android: { priority: 'high' },
        });
        fcmDelivered++;
        stillValidFcm.push(token);
      } catch (err) {
        const code = err && err.errorInfo && err.errorInfo.code;
        // Drop tokens that are no longer valid; keep on transient errors.
        if (code !== 'messaging/registration-token-not-registered' &&
            code !== 'messaging/invalid-registration-token') {
          stillValidFcm.push(token);
        }
      }
    }
  } else {
    stillValidFcm.push(...entry.fcm);
  }

  let pushDelivered = 0;
  const stillValidPush = [];
  const payload = JSON.stringify({ type, from, text: text || '', ts: Date.now() });
  for (const sub of entry.push) {
    try {
      await webpush.sendNotification(sub, payload);
      pushDelivered++;
      stillValidPush.push(sub);
    } catch (err) {
      if (err.statusCode !== 404 && err.statusCode !== 410) {
        stillValidPush.push(sub);
      }
    }
  }

  entry.fcm = stillValidFcm;
  entry.push = stillValidPush;
  if (!entry.fcm.length && !entry.push.length) delete db[cleanTo];
  saveDB(db);

  res.json({
    ok: true,
    delivered: fcmDelivered + pushDelivered,
    fcmDelivered,
    pushDelivered,
    total: entry.fcm.length + entry.push.length,
    fcmEnabled: firebaseReady,
  });
});

// ── Presence (lightweight WebSocket hub) ──
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/presence' });

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
  console.log(`FCM (native ringing): ${firebaseReady ? 'ENABLED' : 'DISABLED — set FIREBASE_SERVICE_ACCOUNT_JSON'}`);
});
