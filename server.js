// ═══════════════════════════════════════════════════════════════
//  VAHIN CONNECT — Notification & Presence Backend
//  Express + ws (WebSocket) + web-push + Firebase Admin (FCM + Firestore)
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const webpush = require('web-push');
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8787;
const DB_PATH = path.join(__dirname, 'data', 'subscriptions.json');
const USERS_PATH = path.join(__dirname, 'data', 'users.json');

// ── VAPID keys (browser Web Push fallback — only useful while the WebView
//    process is alive; does NOT wake a fully-killed Android app) ──
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || 'BK0ff9D-ym_kVEhPLM8I0d9gJkrcarp1-I-j1JsYFh_WcTxjRls7f2kOM8TFbK9XjfzXqZ-aeQVnyK1aRLmb_lc';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || 'cuOUHy0XgC6Mulf4ml4u0FseVY8MakVPY03K58JH8pA';
const VAPID_SUBJECT     = process.env.VAPID_SUBJECT || 'mailto:admin@vahinconnect.example';
webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// ── Shared-secret auth ──────────────────────────────────────────────────
// Without this, anyone who knows (or guesses/enumerates) a Vahin ID can hit
// /notify and make that person's phone ring, or hit /register-fcm and plant
// a token, with zero proof they're the real app. Every "write" route below
// now requires a header:  x-vahin-key: <API_SHARED_SECRET>
//
// Set API_SHARED_SECRET here (Render → Environment) to any long random
// string, and set the SAME value in www/index.html's API_SHARED_SECRET
// constant near the top of the <script>. If this env var is left unset,
// the check is skipped (so the app doesn't break before you've set both
// sides) — but you should set it.
const API_SHARED_SECRET = process.env.API_SHARED_SECRET || '';
function requireApiKey(req, res, next) {
  if (!API_SHARED_SECRET) return next(); // not configured yet — don't lock yourself out
  if (req.get('x-vahin-key') !== API_SHARED_SECRET) {
    return res.status(401).json({ error: 'missing or invalid x-vahin-key header' });
  }
  next();
}

// ── Minimal in-memory rate limiter (no extra dependency) ────────────────
// Caps how many times a single IP can hit a route per window. Cheap
// protection against someone spamming /notify to repeatedly ring a phone,
// or hammering /register-fcm. Not distributed (per-instance only) — fine
// for a single free-tier Render dyno.
function rateLimit({ windowMs, max }) {
  const hits = new Map(); // ip -> [timestamps]
  return function (req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) {
      return res.status(429).json({ error: 'too many requests, slow down' });
    }
    arr.push(now);
    hits.set(ip, arr);
    if (hits.size > 5000) hits.clear(); // crude memory cap for a long-running free dyno
    next();
  };
}
const notifyLimiter = rateLimit({ windowMs: 60_000, max: 20 });   // 20 calls/min/IP
const registerLimiter = rateLimit({ windowMs: 60_000, max: 30 }); // 30 registers/min/IP

// ── Firebase Admin (FCM + Firestore) — THIS is what actually wakes the
//    Android app when it's fully killed, and (new) also gives us a real
//    database instead of a JSON file that Render's free tier wipes on
//    every redeploy.
//
//    Set FIREBASE_SERVICE_ACCOUNT_JSON to the full contents of a Firebase
//    service-account key JSON (Project settings → Service accounts → Generate
//    new private key, project "unifest-99468"). Raw JSON or base64 both work.
let firebaseReady = false;
try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (raw) {
    let parsed;
    try { 
      parsed = JSON.parse(raw); 
    } catch (e) { 
      // Decodes Base64 string from PowerShell automatically if raw JSON parsing fails
      parsed = JSON.parse(Buffer.from(raw, 'base64').toString('utf8')); 
    }
    admin.initializeApp({ credential: admin.credential.cert(parsed) });
    firebaseReady = true;
    console.log('Firebase Admin initialized — FCM push (native ringing) is ENABLED.');
  } else {
    console.warn(
      'FIREBASE_SERVICE_ACCOUNT_JSON is not set. FCM push is DISABLED, so calls will ' +
      'NOT ring when the app is closed/killed. See .env.example.'
    );
  }
} catch (e) {
  console.error('Failed to initialize Firebase Admin (check FIREBASE_SERVICE_ACCOUNT_JSON):', e.message);
}

// ── Storage layer ────────────────────────────────────────────────────────
// Prefers Firestore (persists across Render redeploys/restarts) if Firebase
// is configured. Falls back to the old flat JSON file otherwise — which
// still works, but is wiped every time Render redeploys the free-tier
// instance, so people intermittently have to reopen the app to re-register.
// Shape per id: { push: [{endpoint, keys:{...}}, ...], fcm: ["token1", ...] }
let useFirestore = false;
let fsDb = null;
if (firebaseReady) {
  try {
    fsDb = admin.firestore();
    useFirestore = true;
    console.log('Using Firestore for persistent storage (survives redeploys).');
  } catch (e) {
    console.warn('Firestore unavailable, falling back to local JSON file (NOT persistent across redeploys):', e.message);
  }
} else {
  console.warn('Firebase not configured — using local JSON file (NOT persistent across redeploys). See .env.example.');
}

// Local flat-file fallback (unchanged behavior from before).
let fileDb = loadFileDB();
function loadFileDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return {};
    const raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8') || '{}');
    const migrated = {};
    for (const [id, val] of Object.entries(raw)) {
      if (Array.isArray(val)) migrated[id] = { push: val, fcm: [] };
      else migrated[id] = { push: val.push || [], fcm: val.fcm || [] };
    }
    return migrated;
  } catch (e) { return {}; }
}
function saveFileDB() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(fileDb, null, 2));
}

async function getEntry(id) {
  const cleanId = String(id).toLowerCase().trim();
  if (useFirestore) {
    const doc = await fsDb.collection('subscriptions').doc(cleanId).get();
    return { cleanId, entry: doc.exists ? doc.data() : { push: [], fcm: [] } };
  }
  if (!fileDb[cleanId]) fileDb[cleanId] = { push: [], fcm: [] };
  return { cleanId, entry: fileDb[cleanId] };
}
async function saveEntry(cleanId, entry) {
  const empty = !entry.push.length && !entry.fcm.length;
  if (useFirestore) {
    const ref = fsDb.collection('subscriptions').doc(cleanId);
    if (empty) await ref.delete().catch(() => {});
    else await ref.set(entry);
    return;
  }
  if (empty) delete fileDb[cleanId];
  else fileDb[cleanId] = entry;
  saveFileDB();
}

// ── User accounts (ID + password) ───────────────────────────────────────
// Same storage strategy as subscriptions above: Firestore if Firebase is
// configured (survives redeploys), otherwise a local JSON file (wiped on
// every free-tier redeploy — an account made between deploys can be lost
// until you set FIREBASE_SERVICE_ACCOUNT_JSON).
let fileUsers = loadFileUsers();
function loadFileUsers() {
  try {
    if (!fs.existsSync(USERS_PATH)) return {};
    return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8') || '{}');
  } catch (e) { return {}; }
}
function saveFileUsers() {
  fs.mkdirSync(path.dirname(USERS_PATH), { recursive: true });
  fs.writeFileSync(USERS_PATH, JSON.stringify(fileUsers, null, 2));
}
function cleanUserId(id) {
  return String(id || '').toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
}
async function getUser(cleanId) {
  if (useFirestore) {
    const doc = await fsDb.collection('users').doc(cleanId).get();
    return doc.exists ? doc.data() : null;
  }
  return fileUsers[cleanId] || null;
}
async function saveUser(cleanId, userData) {
  if (useFirestore) {
    await fsDb.collection('users').doc(cleanId).set(userData);
    return;
  }
  fileUsers[cleanId] = userData;
  saveFileUsers();
}
// token -> id, in memory. Resets on restart/redeploy, meaning a logged-in
// session has to log in again once after a redeploy — the account itself
// (id + password hash) is unaffected, since that's stored separately above.
const activeTokens = new Map();
function issueToken(cleanId) {
  const token = crypto.randomBytes(24).toString('hex');
  activeTokens.set(token, cleanId);
  return token;
}
function ownerOfToken(req) {
  const auth = req.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token ? activeTokens.get(token) || null : null;
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 10 }); // 10 attempts/min/IP — brute-force guard

// ── App ──
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.set('trust proxy', true); // so req.ip reflects the real client on Render

app.get('/health', (req, res) => res.json({ 
  ok: true, 
  time: Date.now(), 
  fcmEnabled: firebaseReady, 
  storage: useFirestore ? 'firestore' : 'file' 
}));

app.get('/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

// Create a new Vahin ID + password. Fails if the ID is already taken —
// this is what stops anyone else from claiming an ID that's already in use.
app.post('/auth/register', authLimiter, async (req, res) => {
  const cleanId = cleanUserId(req.body && req.body.id);
  const password = (req.body && req.body.password) || '';
  if (!cleanId || cleanId.length < 2) return res.status(400).json({ error: 'Invalid ID' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  const existing = await getUser(cleanId);
  if (existing) return res.status(409).json({ error: 'That ID is already taken' });
  const passwordHash = await bcrypt.hash(password, 10);
  await saveUser(cleanId, { passwordHash, createdAt: Date.now() });
  res.json({ ok: true, token: issueToken(cleanId) });
});

// Log back into an existing ID with its password — this is how someone
// gets their ID back after reinstalling the app or switching phones.
app.post('/auth/login', authLimiter, async (req, res) => {
  const cleanId = cleanUserId(req.body && req.body.id);
  const password = (req.body && req.body.password) || '';
  if (!cleanId || !password) return res.status(400).json({ error: 'ID and password required' });
  const user = await getUser(cleanId);
  if (!user) return res.status(401).json({ error: 'Wrong ID or password' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Wrong ID or password' });
  res.json({ ok: true, token: issueToken(cleanId) });
});

// Requires a valid bearer token whose owner matches the id the request is
// acting as — stops someone who never logged in from planting an FCM token
// or triggering /notify under an ID that isn't theirs.
function requireOwnId(idField) {
  return (req, res, next) => {
    const owner = ownerOfToken(req);
    const claimedId = cleanUserId((req.body && req.body[idField]) || '');
    if (!owner || owner !== claimedId) {
      return res.status(401).json({ error: 'Not authorized for this ID — please log in again' });
    }
    next();
  };
}

// Register / update a browser Web Push subscription for a given Vahin ID.
app.post('/subscribe', requireApiKey, registerLimiter, requireOwnId('id'), async (req, res) => {
  const { id, subscription } = req.body || {};
  if (!id || !subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'id and subscription required' });
  }
  const { cleanId, entry } = await getEntry(id);
  entry.push = entry.push.filter(s => s.endpoint !== subscription.endpoint);
  entry.push.push(subscription);
  await saveEntry(cleanId, entry);
  res.json({ ok: true, devices: entry.push.length });
});

app.post('/unsubscribe', requireApiKey, requireOwnId('id'), async (req, res) => {
  const { id, endpoint } = req.body || {};
  if (!id || !endpoint) return res.status(400).json({ error: 'id and endpoint required' });
  const { cleanId, entry } = await getEntry(id);
  entry.push = entry.push.filter(s => s.endpoint !== endpoint);
  await saveEntry(cleanId, entry);
  res.json({ ok: true });
});

// Register / update a native FCM registration token for a given Vahin ID.
app.post('/register-fcm', requireApiKey, registerLimiter, requireOwnId('id'), async (req, res) => {
  const { id, token } = req.body || {};
  if (!id || !token) return res.status(400).json({ error: 'id and token required' });
  const { cleanId, entry } = await getEntry(id);
  if (!entry.fcm.includes(token)) entry.fcm.push(token);
  await saveEntry(cleanId, entry);
  res.json({ ok: true, devices: entry.fcm.length, fcmEnabled: firebaseReady });
});

app.post('/unregister-fcm', requireApiKey, requireOwnId('id'), async (req, res) => {
  const { id, token } = req.body || {};
  if (!id || !token) return res.status(400).json({ error: 'id and token required' });
  const { cleanId, entry } = await getEntry(id);
  entry.fcm = entry.fcm.filter(t => t !== token);
  await saveEntry(cleanId, entry);
  res.json({ ok: true });
});

// Trigger a push notification to a target Vahin ID.
// Body: { to, type: 'call'|'voice-call'|'message'|'group'|'conf', from, text? }
app.post('/notify', requireApiKey, notifyLimiter, requireOwnId('from'), async (req, res) => {
  const { to, type, from, text } = req.body || {};
  if (!to || !type || !from) return res.status(400).json({ error: 'to, type, from required' });
  const { cleanId: cleanTo, entry } = await getEntry(to);

  if (!entry.push.length && !entry.fcm.length) {
    return res.json({ ok: true, delivered: 0, reason: 'no subscriptions for this id' });
  }

  let fcmDelivered = 0;
  const stillValidFcm = [];
  if (firebaseReady && entry.fcm.length) {
    for (const token of entry.fcm) {
      try {
        // Data-only message: no "notification" field, so it reaches
        // VahinMessagingService.onMessageReceived() even when the app is killed.
        await admin.messaging().send({
          token,
          data: { type: String(type), from: String(from), text: String(text || '') },
          android: { priority: 'high' },
        });
        fcmDelivered++;
        stillValidFcm.push(token);
      } catch (err) {
        const code = err && err.errorInfo && err.errorInfo.code;
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
  await saveEntry(cleanTo, entry);

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
      ws.send(JSON.stringify({ type: 'roster', ids: Array.from(liveSockets.keys()) }));
    }
    if (msg.type === 'ping') ws.send(JSON.stringify({ type: 'pong' }));
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
  console.log(`Storage: ${useFirestore ? 'Firestore (persistent)' : 'local JSON file (NOT persistent across redeploys)'}`);
  console.log(`API key auth: ${API_SHARED_SECRET ? 'ENABLED' : 'DISABLED — set API_SHARED_SECRET'}`);
});
