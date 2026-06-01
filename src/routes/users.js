/**
 * Users Routes - INTENTIONALLY VULNERABLE
 * Covers: IDOR, NoSQL Injection, XSS, Insecure Deserialization,
 *         Prototype Pollution, Sensitive Data Exposure
 *
 * ====================================================================
 * MULTI-FILE SOURCE-TO-SINK FLOW C: Stored XSS (3 files)
 * ====================================================================
 *
 *  [1] SOURCE   src/routes/users.js (POST /:id/bio)  ← YOU ARE HERE
 *               req.body.bio / req.body.website / req.body.avatar
 *               stored unsanitized to MongoDB
 *                    │
 *                    │  tainted values persist in DB; fetched on GET
 *                    ▼
 *  [2] TRANSIT  src/utils/helpers.js  → helpers.generateUserCard()
 *               interpolates user fields into HTML template literals
 *               no HTML-escaping applied — taint survives in markup
 *                    │
 *                    │  unsafe HTML string returned to caller
 *                    ▼
 *  [3] SINK     src/routes/users.js (GET /:id/bio)  ← YOU ARE HERE
 *               res.send(html) — browser receives and executes XSS payload
 *
 * Attack payload example:
 *   POST /users/123/bio  { "bio": "<img src=x onerror=alert(document.cookie)>" }
 *   GET  /users/123/bio  → browser executes the stored script
 * ====================================================================
 */

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const helpers = require('../utils/helpers'); // used by Flow C

// ============================================================
// VULNERABILITY: NoSQL Injection via MongoDB
// CWE-943: Improper Neutralization of Special Elements in Data Query
// ============================================================
router.post('/find', async (req, res) => {
  const { username, password } = req.body;

  // Direct object injection - attacker can pass { $gt: "" }
  // POST body: { "username": {"$gt": ""}, "password": {"$gt": ""} }
  const user = await mongoose.connection.db.collection('users').findOne({
    username: username,   // No sanitization - object injection possible
    password: password    // No sanitization
  });

  if (user) {
    res.json({ success: true, user });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ============================================================
// VULNERABILITY: NoSQL injection via $where operator
// CWE-943: NoSQL Injection
// ============================================================
router.get('/search', async (req, res) => {
  const searchTerm = req.query.q;

  // $where with user input allows arbitrary JS execution
  const users = await mongoose.connection.db.collection('users').find({
    $where: `this.username.includes('${searchTerm}')` // JS injection
  }).toArray();

  res.json(users);
});

// ============================================================
// VULNERABILITY: IDOR - Insecure Direct Object Reference
// CWE-639: Authorization Bypass Through User-Controlled Key
// ============================================================
router.get('/:id', async (req, res) => {
  const userId = req.params.id;

  // No authorization check - any user can access any profile
  const user = await mongoose.connection.db.collection('users').findOne({
    _id: new mongoose.Types.ObjectId(userId)
  });

  if (!user) return res.status(404).json({ error: 'User not found' });

  // VULNERABILITY: Returns sensitive fields
  res.json(user); // Returns password hash, tokens, PII, etc.
});

// ============================================================
// VULNERABILITY: IDOR in update
// CWE-284: Improper Access Control
// ============================================================
router.put('/:id', async (req, res) => {
  const userId = req.params.id;
  const updateData = req.body;

  // No auth check - attacker can update any user including admins
  // Also: Mass assignment - no field whitelist
  await mongoose.connection.db.collection('users').updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    { $set: updateData }  // Allows setting role: 'admin', etc.
  );

  res.json({ success: true });
});

// ============================================================
// MULTI-FILE FLOW C — Step 1/3 (Source / Store)
// CWE-79: Stored XSS via cross-file taint propagation
//
// Taint originates here: req.body.bio, req.body.website, req.body.avatar
// Values stored to MongoDB without sanitization.
// Taint then flows via GET handler → helpers.generateUserCard() → res.send()
// ============================================================
router.post('/:id/bio', async (req, res) => {
  const { bio, website, avatar, errorHandler } = req.body; // SOURCE (all fields)

  // No HTML sanitization — XSS payloads stored verbatim.
  // FLOW C: tainted bio, website, avatar, errorHandler persist in DB.
  await mongoose.connection.db.collection('users').updateOne(
    { _id: new mongoose.Types.ObjectId(req.params.id) },
    {
      $set: {
        bio:          bio,          // TAINT stored
        website:      website,      // TAINT stored
        avatar:       avatar,       // TAINT stored
        errorHandler: errorHandler  // TAINT stored (flows into onerror attr)
      }
    }
  );

  res.json({ success: true });
});

// ============================================================
// MULTI-FILE FLOW C — Step 2/3 (Transit) + Step 3/3 (Sink)
// CWE-79: Stored XSS — taint fetched from DB and passed to helper
//
// Transit: helpers.generateUserCard() in src/utils/helpers.js
//   - interpolates user.bio, user.website, user.avatar, user.errorHandler
//     into an HTML template string without escaping
//   - returns tainted HTML
//
// Sink: res.send(html) below
//   - browser receives and renders the tainted markup
// ============================================================
router.get('/:id/bio', async (req, res) => {
  const user = await mongoose.connection.db.collection('users').findOne(
    { _id: new mongoose.Types.ObjectId(req.params.id) }
  );

  if (!user) return res.status(404).json({ error: 'User not found' });

  // FLOW C Step 2: tainted fields sourced from POST /:id/bio passed to
  // helpers.generateUserCard() which builds an unsafe HTML template.
  // ─── FLOW C hops to helpers.js ────────────────────────────────────────────
  const html = helpers.generateUserCard({
    id:           user._id,
    name:         user.username,              // may contain XSS
    bio:          user.bio,                   // TAINT from stored POST body
    website:      user.website      || '#',   // TAINT from stored POST body
    avatar:       user.avatar       || '',    // TAINT from stored POST body
    errorHandler: user.errorHandler || ''     // TAINT — injected into onerror=""
  });

  // FLOW C Step 3: SINK — tainted HTML sent to browser with no CSP or escaping
  // ─── FLOW C sink: browser executes any stored script ──────────────────────
  res.setHeader('Content-Type', 'text/html');
  res.send(html); // SINK
});

// ============================================================
// VULNERABILITY: Insecure Deserialization
// CWE-502: Deserialization of Untrusted Data
// ============================================================
router.post('/deserialize', (req, res) => {
  const nodeSerialize = require('node-serialize');
  const data = req.body.data;

  // node-serialize with IIFE allows RCE
  // Payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
  const obj = nodeSerialize.unserialize(data);
  res.json(obj);
});

// ============================================================
// VULNERABILITY: Prototype Pollution via lodash merge (old version)
// CWE-1321: Improperly Controlled Modification of Object Prototype
// ============================================================
router.post('/preferences', (req, res) => {
  const _ = require('lodash');
  const userPrefs = {};
  const incoming = req.body;

  // lodash.merge is vulnerable to prototype pollution in older versions
  // Payload: {"__proto__": {"admin": true}}
  _.merge(userPrefs, incoming);

  res.json({ preferences: userPrefs });
});

// ============================================================
// VULNERABILITY: Template Injection via user-controlled template
// CWE-94: Code Injection
// ============================================================
router.post('/render-template', (req, res) => {
  const ejs = require('ejs');
  const template = req.body.template; // User-controlled template
  const data = req.body.data || {};

  // Rendering user-supplied EJS template
  // Payload: "<%= process.env.DB_PASSWORD %>"
  // Or: "<% require('child_process').exec('id') %>"
  try {
    const rendered = ejs.render(template, data);
    res.send(rendered);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: Mass assignment in profile update
// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object
// ============================================================
router.post('/update-profile', async (req, res) => {
  const sessionUserId = req.session.userId;
  const updates = req.body; // No whitelist - allows role, isAdmin, credits, etc.

  await mongoose.connection.db.collection('users').updateOne(
    { _id: new mongoose.Types.ObjectId(sessionUserId) },
    { $set: updates }
  );

  res.json({ success: true });
});

// ============================================================
// VULNERABILITY: Sensitive data in URL params (logged in access logs)
// CWE-598: Use of GET Request Method with Sensitive Query Strings
// ============================================================
router.get('/verify', (req, res) => {
  // Passwords and tokens passed in URL (end up in logs, browser history, referrer)
  const { userId, password, token } = req.query;
  res.json({ verified: true });
});

// ============================================================
// VULNERABILITY: Uncontrolled Resource Consumption (DoS)
// CWE-400: Uncontrolled Resource Consumption
// ============================================================
router.post('/bulk-create', async (req, res) => {
  const users = req.body.users; // No limit on array size

  // No pagination / rate limiting - can create millions of users
  const results = await Promise.all(
    users.map(u => mongoose.connection.db.collection('users').insertOne(u))
  );

  res.json({ created: results.length });
});

module.exports = router;
