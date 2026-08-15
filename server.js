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
const { ExpressPeerServer } = require('peer');

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
// Self-hosted PeerJS broker (call signaling / WebRTC handshake). Previously
// the app pointed at PeerJS's public cloud broker (0.peerjs.com) — that
// service isn't ours, so a stale ID left behind by a killed-not-closed app
// could only be evicted on ITS eviction policy/timeline, not ours. Hosting
// our own PeerServer here (see /peerjs below and patches/peer+*.patch) is
// what makes the "evict a dead socket immediately, don't make the new
// client wait/retry" fix possible at all.
const PEERJS_KEY = process.env.PEERJS_KEY || 'vahin-peerjs';
const API_SHARED_SECRET = process.env.API_SHARED_SECRET || '';
function requireApiKey(req, res, next) {
  if (!API_SHARED_SECRET) return next();
  if (req.get('x-vahin-key') !== API_SHARED_SECRET) {
    return res.status(401).json({ error: 'missing or invalid x-vahin-key header' });
  }
  next();
}

// ── Minimal in-memory rate limiter (no extra dependency) ────────────────
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  return function (req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) {
      return res.status(429).json({ error: 'too many requests, slow down' });
    }
    arr.push(now);
    hits.set(ip, arr);
    if (hits.size > 5000) hits.clear();
    next();
  };
}
const notifyLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const registerLimiter = rateLimit({ windowMs: 60_000, max: 30 });

// ── Firebase Admin (FCM + Firestore) ────────────────────────────────────
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
      'NOT ring when the app is closed/killed. See .env.example.'
    );
  }
} catch (e) {
  console.error('Failed to initialize Firebase Admin (check FIREBASE_SERVICE_ACCOUNT_JSON):', e.message);
}

// ── Storage layer ────────────────────────────────────────────────────────
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

// ── Mailbox (store-and-forward for offline messages) ────────────────────
// The frontend already calls POST /mailbox/fetch on every app launch
// (fetchQueuedMailbox() in index.html) expecting queued messages back —
// that endpoint never existed here, so it always 404'd, was swallowed by
// an empty catch(), and every message sent to an offline/killed recipient
// was gone the moment the FCM wake-up ping failed to land. This section
// makes that endpoint real: /notify durably stores every chat message
// here regardless of whether the live wake-up attempt succeeded, and the
// client fetches + acks against it — same store-and-forward shape as
// WhatsApp/Signal use.
const MAILBOX_PATH = path.join(__dirname, 'data', 'mailbox.json');
const MAILBOX_MAX_PER_USER = 200; // hard cap so one abandoned account can't grow unbounded

let fileMailbox = loadFileMailbox();
function loadFileMailbox() {
  try {
    if (!fs.existsSync(MAILBOX_PATH)) return {};
    return JSON.parse(fs.readFileSync(MAILBOX_PATH, 'utf8') || '{}');
  } catch (e) { return {}; }
}
function saveFileMailbox() {
  fs.mkdirSync(path.dirname(MAILBOX_PATH), { recursive: true });
  fs.writeFileSync(MAILBOX_PATH, JSON.stringify(fileMailbox, null, 2));
}

async function queueMailboxMessage(toCleanId, msg) {
  if (useFirestore) {
    const ref = fsDb.collection('mailbox').doc(toCleanId);
    const doc = await ref.get();
    const list = doc.exists ? (doc.data().messages || []) : [];
    list.push(msg);
    while (list.length > MAILBOX_MAX_PER_USER) list.shift();
    await ref.set({ messages: list });
    return;
  }
  if (!fileMailbox[toCleanId]) fileMailbox[toCleanId] = [];
  fileMailbox[toCleanId].push(msg);
  while (fileMailbox[toCleanId].length > MAILBOX_MAX_PER_USER) fileMailbox[toCleanId].shift();
  saveFileMailbox();
}
async function getMailboxMessages(cleanId) {
  if (useFirestore) {
    const doc = await fsDb.collection('mailbox').doc(cleanId).get();
    return doc.exists ? (doc.data().messages || []) : [];
  }
  return fileMailbox[cleanId] || [];
}
async function ackMailboxMessages(cleanId, ackIds) {
  const idSet = new Set(ackIds.map(String));
  if (useFirestore) {
    const ref = fsDb.collection('mailbox').doc(cleanId);
    const doc = await ref.get();
    const list = doc.exists ? (doc.data().messages || []) : [];
    const remaining = list.filter(m => !idSet.has(String(m.id)));
    await ref.set({ messages: remaining });
    return;
  }
  if (!fileMailbox[cleanId]) return;
  fileMailbox[cleanId] = fileMailbox[cleanId].filter(m => !idSet.has(String(m.id)));
  saveFileMailbox();
}

// ── User accounts (ID + password) ───────────────────────────────────────
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

// ── Stateless signed login tokens ───────────────────────────────────────
// Previously, tokens were just random strings kept in an in-memory Map
// (id -> token). That Map lives inside the running Node process, so it is
// wiped every time Render restarts or redeploys the service (which happens
// often on the free tier — idle sleep/wake, new deploys, etc). Every
// logged-in user would then get "Not authorized for this ID — please log
// in again" out of nowhere, with no warning, even though their account
// itself was fine.
//
// Fix: tokens are now self-verifying. A token is
//   base64url(id + "." + expiryTimestamp) + "." + HMAC-SHA256(that, secret)
// Verifying a token just recomputes the HMAC and checks it matches, plus
// checks the expiry — no server memory involved at all, so it survives
// restarts/redeploys forever. Set TOKEN_SIGNING_SECRET in Render's
// Environment tab to any long random string (falls back to a default so
// this doesn't break before you've set it, same pattern as the other keys
// in this file — but you should set your own for real security).
const TOKEN_SIGNING_SECRET = process.env.TOKEN_SIGNING_SECRET || 'unifest-dev-default-secret-change-me';
const TOKEN_LIFETIME_MS = 1000 * 60 * 60 * 24 * 90; // 90 days

function issueToken(cleanId) {
  const expiresAt = Date.now() + TOKEN_LIFETIME_MS;
  const payload = `${cleanId}.${expiresAt}`;
  const sig = crypto.createHmac('sha256', TOKEN_SIGNING_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}.${sig}`).toString('base64url');
}
function ownerOfToken(req) {
  const auth = req.get('authorization') || '';
  const raw = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!raw) return null;
  let decoded;
  try {
    decoded = Buffer.from(raw, 'base64url').toString('utf8');
  } catch (e) { return null; }
  const parts = decoded.split('.');
  if (parts.length !== 3) return null;
  const [cleanId, expiresAtStr, sig] = parts;
  const expiresAt = Number(expiresAtStr);
  if (!cleanId || !expiresAt || !sig) return null;
  if (Date.now() > expiresAt) return null; // expired
  const expectedSig = crypto.createHmac('sha256', TOKEN_SIGNING_SECRET)
    .update(`${cleanId}.${expiresAtStr}`).digest('hex');
  // Constant-time compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return cleanId;
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 10 });

// ── App ──
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.set('trust proxy', true);

app.get('/health', (req, res) => res.json({
  ok: true,
  time: Date.now(),
  fcmEnabled: firebaseReady,
  storage: useFirestore ? 'firestore' : 'file'
}));

app.get('/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

app.post('/auth/register', authLimiter, async (req, res) => {
  const cleanId = cleanUserId(req.body && req.body.id);
  const password = (req.body && req.body.password) || '';
  if (!cleanId || cleanId.length < 2) return res.status(400).json({ error: 'Invalid ID' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  try {
    const existing = await getUser(cleanId);
    console.log(`[register] checked "${cleanId}" — existing=${JSON.stringify(existing)}`);
    if (existing) return res.status(409).json({ error: 'That ID is already taken' });
    const passwordHash = await bcrypt.hash(password, 10);
    await saveUser(cleanId, { passwordHash, createdAt: Date.now() });
    console.log(`[register] created "${cleanId}" successfully`);
    return res.json({ ok: true, token: issueToken(cleanId) });
  } catch (err) {
    console.error(`[register] REAL ERROR for "${cleanId}":`, err);
    return res.status(500).json({ error: 'Server error while checking/creating ID: ' + err.message });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  const cleanId = cleanUserId(req.body && req.body.id);
  const password = (req.body && req.body.password) || '';
  if (!cleanId || !password) return res.status(400).json({ error: 'ID and password required' });
  try {
    const user = await getUser(cleanId);
    if (!user) return res.status(401).json({ error: 'Wrong ID or password' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Wrong ID or password' });
    res.json({ ok: true, token: issueToken(cleanId) });
  } catch (err) {
    console.error(`[login] REAL ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: 'Server error while logging in: ' + err.message });
  }
});

// Temporary diagnostic route — lists every ID currently in the users
// collection, so we can see exactly what the database actually contains
// instead of guessing. Remove this once the "ID always taken" bug is fixed.
app.get('/__debug/list-users', async (req, res) => {
  try {
    if (useFirestore) {
      const snap = await fsDb.collection('users').get();
      const ids = snap.docs.map(d => d.id);
      return res.json({ storage: 'firestore', count: ids.length, ids });
    }
    return res.json({ storage: 'file', count: Object.keys(fileUsers).length, ids: Object.keys(fileUsers) });
  } catch (err) {
    console.error('[debug list-users] ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

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

app.post('/notify', requireApiKey, notifyLimiter, requireOwnId('from'), async (req, res) => {
  const { to, type, from, text } = req.body || {};
  if (!to || !type || !from) return res.status(400).json({ error: 'to, type, from required' });
  const { cleanId: cleanTo, entry } = await getEntry(to);

  // Queued unconditionally, before any early return below — a message must
  // survive even when the recipient has zero push/FCM subscriptions
  // registered (fresh install, reinstall, notification permission never
  // granted, etc). Previously the "no subscriptions" branch returned before
  // any queuing logic ran at all, so those messages vanished with no trace.
  if (type === 'message' && text) {
    try {
      await queueMailboxMessage(cleanTo, {
        id: crypto.randomUUID(),
        from: String(from),
        text: String(text),
        ts: Date.now(),
      });
    } catch (err) {
      console.error(`[notify] failed to queue mailbox message for "${cleanTo}":`, err.message);
    }
  }

  // FIX (ring delivery): grab this BEFORE the "no subscriptions" early return below —
  // a live SignalService WebSocket is a delivery channel in its own right, same as a
  // push subscription or FCM token. The old check only looked at entry.push/entry.fcm
  // and returned early with zero delivery attempts even when the recipient had an
  // active WS connection open, which defeated the entire point of the WS ring path
  // (it exists specifically to cover devices where FCM/push registration hasn't
  // succeeded yet or has gone stale).
  const sockets = liveSockets.get(cleanTo);
  const hasLiveSocket = !!(sockets && sockets.size);

  if (!entry.push.length && !entry.fcm.length && !hasLiveSocket) {
    return res.json({ ok: true, delivered: 0, wsDelivered: 0, queued: type === 'message', reason: 'no subscriptions for this id' });
  }

  let fcmDelivered = 0;
  const stillValidFcm = [];
  if (firebaseReady && entry.fcm.length) {
    for (const token of entry.fcm) {
      try {
        await admin.messaging().send({
          token,
          data: { type: String(type), from: String(from), text: String(text || '') },
          android: { priority: 'high' },
        });
        fcmDelivered++;
        stillValidFcm.push(token);
      } catch (err) {
        const code = err && err.errorInfo && err.errorInfo.code;
        const isDeadToken = code === 'messaging/registration-token-not-registered' ||
                            code === 'messaging/invalid-registration-token';
        if (!isDeadToken) {
          // Not a dead token — network error, quota hit, credential issue, etc.
          // Keep the token (it may still be valid) but surface it in Render logs.
          console.error(`[notify] FCM send error (non-fatal, keeping token) for "${cleanTo}": ${code || err.message}`);
          stillValidFcm.push(token);
        } else {
          // Dead/unregistered token — prune it so it doesn't clog future sends.
          console.warn(`[notify] pruning dead FCM token for "${cleanTo}": ${code}`);
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

  // ── WebSocket ring delivery (SignalService.java's backup path) ──────────
  // BUG (found 2026-08-04): this route never touched `liveSockets`, so the
  // always-on WebSocket connection SignalService.java holds open was 100%
  // decorative for ringing — it only ever received {type:'presence'} and
  // {type:'roster'}, never {type:'ring'}. SignalService.java's whole
  // `if ("ring".equals(type))` branch was dead code. Every "backup path"
  // ring depended entirely on FCM, with zero actual redundancy, which is
  // why calls stopped ringing once FCM alone couldn't wake a killed
  // process (e.g. OnePlus/OxygenOS auto-launch kills). Fixed by actually
  // forwarding the ring over any open socket for `to`, mirroring the FCM
  // payload.
  let wsDelivered = 0;
  if (hasLiveSocket) {
    const ringMsg = JSON.stringify({ type: 'ring', callType: type, from, text: text || '' });
    for (const ws of sockets) {
      if (ws.readyState === ws.OPEN) {
        try {
          ws.send(ringMsg);
          wsDelivered++;
        } catch (err) {
          console.error(`[notify] WS ring send FAILED for "${cleanTo}":`, err.message);
        }
      }
    }
  }
  if (wsDelivered === 0 && fcmDelivered === 0 && pushDelivered === 0) {
    console.error(
      `[notify] RING NOT DELIVERED to "${cleanTo}" via ANY channel ` +
      `(ws=0, fcm=0, push=0) — from="${from}" type="${type}". ` +
      `The callee will not ring.`
    );
  }

  res.json({
    ok: true,
    delivered: fcmDelivered + pushDelivered + wsDelivered,
    fcmDelivered,
    pushDelivered,
    wsDelivered,
    total: entry.fcm.length + entry.push.length,
    fcmEnabled: firebaseReady,
  });
});

app.post('/mailbox/fetch', requireApiKey, requireOwnId('id'), async (req, res) => {
  const cleanId = cleanUserId((req.body && req.body.id) || '');
  if (!cleanId) return res.status(400).json({ error: 'id required' });
  try {
    const messages = await getMailboxMessages(cleanId);
    res.json({ ok: true, messages });
  } catch (err) {
    console.error(`[mailbox/fetch] ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/mailbox/ack', requireApiKey, requireOwnId('id'), async (req, res) => {
  const cleanId = cleanUserId((req.body && req.body.id) || '');
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : [];
  if (!cleanId || !ids.length) return res.status(400).json({ error: 'id and ids[] required' });
  try {
    await ackMailboxMessages(cleanId, ids);
    res.json({ ok: true, acked: ids.length });
  } catch (err) {
    console.error(`[mailbox/ack] ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── DP (profile picture) ─────────────────────────────────────────────────
// Stored as a data URL on the user record itself (reuses the existing
// users store — no new storage layer needed). Capped well under Firestore's
// 1MB document limit; the client is expected to downscale before upload
// (index.html does this via canvas before calling this route), but the
// cap is enforced here too since the client can't be trusted.
const DP_MAX_CHARS = 300_000; // ~220KB of actual image data once base64 overhead is backed out

app.post('/profile/dp', requireApiKey, requireOwnId('id'), async (req, res) => {
  const cleanId = cleanUserId((req.body && req.body.id) || '');
  const dataUrl = (req.body && req.body.dataUrl) || '';
  if (!cleanId || !dataUrl) return res.status(400).json({ error: 'id and dataUrl required' });
  if (!/^data:image\/(png|jpe?g|webp);base64,/.test(dataUrl)) {
    return res.status(400).json({ error: 'dataUrl must be a base64 png/jpeg/webp data URL' });
  }
  if (dataUrl.length > DP_MAX_CHARS) {
    return res.status(413).json({ error: `Image too large — keep it under ~${Math.round(DP_MAX_CHARS / 1.37 / 1024)}KB` });
  }
  try {
    const user = await getUser(cleanId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    user.dp = dataUrl;
    await saveUser(cleanId, user);
    res.json({ ok: true });
  } catch (err) {
    console.error(`[profile/dp POST] ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/profile/dp', requireApiKey, requireOwnId('id'), async (req, res) => {
  const cleanId = cleanUserId((req.body && req.body.id) || '');
  if (!cleanId) return res.status(400).json({ error: 'id required' });
  try {
    const user = await getUser(cleanId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    delete user.dp;
    await saveUser(cleanId, user);
    res.json({ ok: true });
  } catch (err) {
    console.error(`[profile/dp DELETE] ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: err.message });
  }
});

// Public read (no owner check — any logged-in client needs to be able to
// show any contact's DP, not just their own), but still requires the shared
// API key so it's not a fully open scrape endpoint.
app.get('/profile/dp/:id', requireApiKey, async (req, res) => {
  const cleanId = cleanUserId(req.params.id || '');
  if (!cleanId) return res.status(400).json({ error: 'id required' });
  try {
    const user = await getUser(cleanId);
    res.json({ ok: true, dp: (user && user.dp) || null });
  } catch (err) {
    console.error(`[profile/dp GET] ERROR for "${cleanId}":`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── Presence (lightweight WebSocket hub) ──
const server = http.createServer(app);
// NOTE: `noServer: true` here (not `server`) is deliberate — see the shared
// upgrade router below. Two `ws` WebSocketServers both bound directly via
// `server` on the same http.Server will fight over every upgrade request
// (whichever registers first 400s anything that isn't its own path, before
// the other ever gets a look), which silently broke the peer server the
// first time this was wired up. Passing `noServer: true` to both and
// routing upgrades ourselves by pathname avoids that entirely.
const wss = new WebSocketServer({ noServer: true });
const PRESENCE_WS_PATH = '/presence';
const liveSockets = new Map();

// ── PeerJS broker (WebRTC call signaling) ────────────────────────────────
// Mounted on the same HTTP server/port as everything else — Render (and
// most PaaS hosts) only route one port per service, so this rides along
// with Express/the /presence WS instead of needing its own listener.
// The eviction-on-stale-id behavior lives in patches/peer+1.0.2.patch
// (applied to node_modules/peer via `postinstall: patch-package`) — see
// that patch for the actual fix; this is just wiring it up.
//
// `createWebSocketServer` is peer's own escape hatch for this exact
// problem: it lets us hand back a `noServer: true` WebSocketServer instead
// of letting peer create one bound straight to `server` (which is what
// caused the 400s above). We still need to know the *path* peer expects,
// so we capture it off the options peer passes in and route to it below.
let peerWsPath = null;
let peerWss = null;
const peerServer = ExpressPeerServer(server, {
  path: '/',
  key: PEERJS_KEY,
  allow_discovery: false,
  createWebSocketServer: (options) => {
    peerWsPath = options.path; // e.g. '/peerjs/peerjs'
    peerWss = new WebSocketServer({ noServer: true });
    return peerWss;
  },
});
app.use('/peerjs', peerServer);

peerServer.on('connection', (client) => {
  console.log(`[peerjs] connected: ${client.getId()}`);
});
peerServer.on('disconnect', (client) => {
  console.log(`[peerjs] disconnected: ${client.getId()}`);
});
peerServer.on('error', (err) => {
  console.error('[peerjs] server error:', err && err.message);
});

// Single shared upgrade router — dispatches by pathname to whichever
// WebSocketServer actually owns that path, instead of each server fighting
// over every request (see note above).
server.on('upgrade', (req, socket, head) => {
  const pathname = (() => {
    try { return new URL(req.url, 'http://localhost').pathname; }
    catch (e) { return req.url; }
  })();

  if (pathname === PRESENCE_WS_PATH) {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
    return;
  }
  if (peerWss && pathname === peerWsPath) {
    peerWss.handleUpgrade(req, socket, head, (ws) => peerWss.emit('connection', ws, req));
    return;
  }
  socket.destroy();
});

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
  console.log(`Login tokens: stateless, signed, survive redeploys (90-day expiry)`);
});
