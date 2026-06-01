/**
 * Search Routes - INTENTIONALLY VULNERABLE
 *
 * ====================================================================
 * MULTI-FILE SOURCE-TO-SINK FLOW A: SQL Injection (3 files)
 * ====================================================================
 *
 *  [1] SOURCE   src/routes/search.js  ← YOU ARE HERE
 *               req.query.q / req.query.category / req.query.role
 *                    │
 *                    │  tainted string passed as `conditions` object
 *                    ▼
 *  [2] TRANSIT  src/utils/helpers.js  → helpers.buildQuery()
 *               concatenates column='{value}' pairs into raw SQL WHERE clause
 *               returns un-parameterized SQL string (taint survives)
 *                    │
 *                    │  raw SQL string passed to db layer
 *                    ▼
 *  [3] SINK     src/models/db.js      → db.executeRaw()
 *               calls connection.query(sql) — SQL executes against MySQL
 *
 * Attack payload example:
 *   GET /search/products?q=widget&category=' OR '1'='1
 *   helpers.buildQuery returns:
 *     SELECT * FROM products WHERE name = 'widget' AND category = '' OR '1'='1'
 * ====================================================================
 */

const express = require('express');
const router = express.Router();
const helpers = require('../utils/helpers');
const db = require('../models/db');

// ============================================================
// MULTI-FILE FLOW A — Step 1/3 (Source)
// CWE-89: SQL Injection via cross-file taint propagation
//
// Taint originates here: req.query.q, req.query.category
// Flows to: helpers.buildQuery() [helpers.js] → db.executeRaw() [db.js]
// ============================================================
router.get('/products', (req, res) => {
  const q        = req.query.q;        // SOURCE — user-controlled search term
  const category = req.query.category; // SOURCE — user-controlled category filter

  // No sanitization before passing to helper.
  // helpers.buildQuery() in src/utils/helpers.js maps each key-value pair to
  // `col = 'val'` without parameterization, returning a raw SQL string.
  // ─── FLOW A hops to helpers.js ────────────────────────────────────────────
  const rawSql = helpers.buildQuery('products', { name: q, category: category });

  // Raw SQL passed directly to the database layer.
  // ─── FLOW A hops to db.js (sink) ──────────────────────────────────────────
  db.executeRaw(rawSql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message, query: rawSql }); // also leaks SQL
    res.json(results);
  });
});

// ============================================================
// MULTI-FILE FLOW A (variant) — chained helper calls
// Source: req.query.search, req.query.role
// Same path: buildQuery [helpers.js] → executeRaw [db.js]
// Demonstrates taint surviving multiple hops before reaching sink
// ============================================================
router.get('/users', (req, res) => {
  const search = req.query.search; // SOURCE
  const role   = req.query.role;   // SOURCE

  // ─── FLOW A hops to helpers.js ────────────────────────────────────────────
  const rawSql = helpers.buildQuery('users', { username: search, role: role });

  // ─── FLOW A hops to db.js (sink) ──────────────────────────────────────────
  db.executeRaw(rawSql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ============================================================
// MULTI-FILE FLOW A (async variant)
// Demonstrates taint flowing through a Promise-based sink path
// Source: req.query.orderId, req.query.status
// ============================================================
router.get('/orders', async (req, res) => {
  const orderId = req.query.orderId; // SOURCE
  const status  = req.query.status;  // SOURCE

  // ─── FLOW A hops to helpers.js ────────────────────────────────────────────
  const rawSql = helpers.buildQuery('orders', { id: orderId, status: status });

  try {
    // ─── FLOW A hops to db.js (async sink) ────────────────────────────────────
    const results = await db.executeRawAsync(rawSql);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
