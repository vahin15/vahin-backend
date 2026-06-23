// ═══════════════════════════════════════════════════════════════
//  VAHIN CONNECT — Secure Notification & Presence Backend
//  Express + ws (WebSocket) + web-push + Security Hardening
//  ✅ Input validation (Joi)
//  ✅ Rate limiting
//  ✅ Environment-based secrets
//  ✅ CORS security
//  ✅ Error handling
//  ✅ Helmet security headers
// ═══════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const webpush = require('web-push');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');

// ═══════════════════════════════════════════════════════════════
//  ENVIRONMENT & CONFIG
// ═══════════════════════════════════════════════════════════════

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = parseInt(process.env.PORT, 10) || 8787;
const DB_PATH = path.join(__dirname, 'data', 'subscriptions.json');

// ⚠️ CRITICAL: Secrets MUST come from environment, never hardcoded
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@vahinconnect.example';

// Validate required secrets on startup
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error('❌ FATAL: VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY must be set in environment variables');
  console.error('   Set these in .env file or your deployment platform (Render, Heroku, etc.)');
  process.exit(1);
}

console.log(`✅ Backend starting in ${NODE_ENV} mode on port ${PORT}`);

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// ═══════════════════════════════════════════════════════════════
//  RATE LIMITING
// ═══════════════════════════════════════════════════════════════

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100, // 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true, // Return rate limit info in RateLimit-* headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  keyGenerator: (req) => {
    // Rate limit by IP, or by user ID if authenticated
    return req.body?.id || req.ip || req.connection.remoteAddress;
  },
});

const notifyLimiter = rateLimit({
  windowMs: 60000,
  max: 50, // Tighter limit for notify endpoint (potential abuse vector)
  keyGenerator: (req) => req.body?.to || req.ip,
});

// ═══════════════════════════════════════════════════════════════
//  VALIDATION SCHEMAS (Joi)
// ═══════════════════════════════════════════════════════════════

const subscriptionSchema = Joi.object({
  id: Joi.string().alphanum().min(1).max(50).required(),
  subscription: Joi.object({
    endpoint: Joi.string().uri().required(),
    keys: Joi.object({
      p256dh: Joi.string().required(),
      auth: Joi.string().required(),
    }).required(),
  }).required(),
});

const unsubscribeSchema = Joi.object({
  id: Joi.string().alphanum().min(1).max(50).required(),
  endpoint: Joi.string().uri().required(),
});

const notifySchema = Joi.object({
  to: Joi.string().alphanum().min(1).max(50).required(),
  type: Joi.string().valid('call', 'message', 'group', 'conf').required(),
  from: Joi.string().alphanum().min(1).max(50).required(),
  text: Joi.string().max(500).optional(),
});

const batchCheckSchema = Joi.object({
  hashes: Joi.array().items(Joi.string().hex().length(64)).min(1).max(100).required(),
});

// ═══════════════════════════════════════════════════════════════
//  DATABASE (Flat JSON file for MVP, migrate to PostgreSQL later)
// ═══════════════════════════════════════════════════════════════

function loadDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return {};
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8') || '{}');
  } catch (e) {
    console.error('⚠️  DB load error:', e.message);
    return {};
  }
}

function saveDB(db) {
  try {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error('❌ DB save error:', e.message);
  }
}

let db = loadDB();

// ═══════════════════════════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════════════════════════

const app = express();

// Security middleware
app.use(helmet()); // Set various HTTP headers for security
app.use(morgan('combined')); // Request logging

// CORS configuration
const corsOptions = {
  origin: NODE_ENV === 'production' 
    ? ['https://yourfrontend.com'] // Whitelist production domain
    : ['http://localhost:3000', 'http://localhost:8000', 'http://127.0.0.1:*'],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
};
app.use(cors(corsOptions));

// Body parser with size limit
app.use(express.json({ limit: '2mb' }));

// Apply rate limiting to all routes
app.use(limiter);

// ═══════════════════════════════════════════════════════════════
//  ENDPOINTS
// ═══════════════════════════════════════════════════════════════

// Health check
app.get('/health', (req, res) => {
  res.json({ ok: true, time: Date.now(), env: NODE_ENV });
});

// Public VAPID key (safe to expose)
app.get('/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});

// Subscribe: register a push subscription for a user
app.post('/subscribe', async (req, res) => {
  try {
    // Validate input
    const { error, value } = subscriptionSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { id, subscription } = value;
    const cleanId = String(id).toLowerCase().trim();

    // Deduplicate: remove if endpoint already exists
    db[cleanId] = (db[cleanId] || []).filter(s => s.endpoint !== subscription.endpoint);
    db[cleanId].push({
      ...subscription,
      subscribedAt: new Date().toISOString(),
      deviceId: uuidv4(),
    });

    saveDB(db);
    res.json({ ok: true, devices: db[cleanId].length });
  } catch (err) {
    console.error('Subscribe error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unsubscribe: remove a push subscription
app.post('/unsubscribe', async (req, res) => {
  try {
    const { error, value } = unsubscribeSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { id, endpoint } = value;
    const cleanId = String(id).toLowerCase().trim();

    if (db[cleanId]) {
      db[cleanId] = db[cleanId].filter(s => s.endpoint !== endpoint);
      if (!db[cleanId].length) delete db[cleanId];
      saveDB(db);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Unsubscribe error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Notify: send push notification to a user
app.post('/notify', notifyLimiter, async (req, res) => {
  try {
    const { error, value } = notifySchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { to, type, from, text } = value;
    const cleanTo = String(to).toLowerCase().trim();
    const subs = db[cleanTo];

    if (!subs || !subs.length) {
      return res.json({ ok: true, delivered: 0, reason: 'no subscriptions for this id' });
    }

    const payload = JSON.stringify({
      type,
      from,
      text: text || '',
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
        // 404/410 = subscription expired; drop it
        if (err.statusCode !== 404 && err.statusCode !== 410) {
          stillValid.push(sub); // keep on transient errors
        } else {
          console.log(`Removed expired subscription for ${cleanTo}`);
        }
      }
    }

    db[cleanTo] = stillValid;
    if (!stillValid.length) delete db[cleanTo];
    saveDB(db);

    res.json({ ok: true, delivered, total: subs.length });
  } catch (err) {
    console.error('Notify error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Batch check: given hashed phone numbers, return who has Unifest
// Hashes must be SHA-256 hex strings (client-side hashing for privacy)
app.post('/contacts/batch-check', async (req, res) => {
  try {
    const { error, value } = batchCheckSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { hashes } = value;

    // Map hashes to vahin IDs (in production, use a dedicated contacts table)
    // For MVP, we use a simple in-memory approach
    const results = {};

    // TODO: In production, query a contacts_hash table:
    // SELECT hash, vahin_id FROM contacts_hash WHERE hash IN ($1)

    hashes.forEach(hash => {
      results[hash] = null; // null = not on Unifest, or vahin_id if found
    });

    res.json({ ok: true, results });
  } catch (err) {
    console.error('Batch check error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════════
//  WEBSOCKET: Presence & Real-time Updates
// ═══════════════════════════════════════════════════════════════

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/presence' });

const liveSockets = new Map(); // id -> Set<WebSocket>

function broadcastPresence(id, online) {
  const msg = JSON.stringify({ type: 'presence', id, online, ts: Date.now() });
  for (const sockets of liveSockets.values()) {
    for (const ws of sockets) {
      if (ws.readyState === ws.OPEN) {
        try {
          ws.send(msg);
        } catch (e) {
          // Ignore send errors
        }
      }
    }
  }
}

wss.on('connection', (ws) => {
  let myId = null;
  const connectionId = uuidv4();

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);

      if (msg.type === 'hello' && msg.id) {
        myId = String(msg.id).toLowerCase().trim();

        // Validate ID format
        if (!/^[a-z0-9]{1,50}$/.test(myId)) {
          ws.close(1008, 'Invalid ID format');
          return;
        }

        if (!liveSockets.has(myId)) liveSockets.set(myId, new Set());
        liveSockets.get(myId).add(ws);
        broadcastPresence(myId, true);

        // Send current roster to new client
        const onlineIds = Array.from(liveSockets.keys());
        ws.send(JSON.stringify({ type: 'roster', ids: onlineIds, ts: Date.now() }));
      }

      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
      }
    } catch (e) {
      console.error('WebSocket message error:', e.message);
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

  ws.on('error', (err) => {
    console.error(`WebSocket error (${connectionId}):`, err.message);
  });
});

// ═══════════════════════════════════════════════════════════════
//  ERROR HANDLING & STARTUP
// ═══════════════════════════════════════════════════════════════

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

server.listen(PORT, () => {
  console.log(`✅ Vahin Connect backend listening on :${PORT}`);
  console.log(`   Environment: ${NODE_ENV}`);
  console.log(`   VAPID public key: ${VAPID_PUBLIC_KEY.substring(0, 20)}...`);
  console.log(`   WebSocket: ws://localhost:${PORT}/presence`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
