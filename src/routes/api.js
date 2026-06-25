/**
 * API Routes - INTENTIONALLY VULNERABLE
 * Covers: XXE, SSTI, Insecure Crypto, Regex DoS,
 *         HTTP Header Injection, Business Logic Flaws
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');



// ============================================================
// VULNERABILITY: Insecure Cryptography
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// ============================================================
router.post('/encrypt', (req, res) => {
  const { data, key } = req.body;

  // MD5 for encryption - broken algorithm
  const hash = crypto.createHash('md5').update(data).digest('hex');

  // DES - deprecated, weak cipher
  const cipher = crypto.createCipher('des', key || 'weakkey');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // ECB mode - no IV, patterns preserved
  const ecbCipher = crypto.createCipheriv('aes-128-ecb', 
    Buffer.alloc(16, key || 'key'), 
    ''
  );
  let ecbEncrypted = ecbCipher.update(data, 'utf8', 'hex');
  ecbEncrypted += ecbCipher.final('hex');

  res.json({ md5: hash, des: encrypted, aes_ecb: ecbEncrypted });
});

// ============================================================
// VULNERABILITY: Weak random number generation
// CWE-338: Use of Cryptographically Weak PRNG
// ============================================================
router.post('/generate-token', (req, res) => {
  // Math.random() - not cryptographically secure
  const weakToken = Math.random().toString(36).substring(2);

  // Timestamp-based token
  const timeToken = Date.now().toString(16);

  // Sequential token
  let counter = global.tokenCounter = (global.tokenCounter || 0) + 1;
  const sequentialToken = `TOKEN_${counter}`;

  res.json({ weakToken, timeToken, sequentialToken });
});

// ============================================================
// VULNERABILITY: Insecure YAML parsing (arbitrary code execution)
// CWE-502: Deserialization of Untrusted Data
// ============================================================
router.post('/parse-yaml', (req, res) => {
  const yaml = require('js-yaml');
  const yamlData = req.body.yaml;

  // js-yaml.load() allows arbitrary JS execution in older versions
  // Use safeLoad() or yaml.load() with schema: DEFAULT_SAFE_SCHEMA
  try {
    const parsed = yaml.load(yamlData); // Unsafe load
    res.json(parsed);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: Server-Side Template Injection (SSTI) with Handlebars
// CWE-94: Code Injection
// ============================================================
router.post('/render', (req, res) => {
  const handlebars = require('handlebars');
  const template = req.body.template;
  const data = req.body.data || {};

  // User-controlled Handlebars template
  // Payload: {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}
  //           {{this.pop}}{{this.push (lookup string.sub "constructor")}}
  //           {{this.pop}}{{#with string.split as |codelist|}}
  //           {{this.pop}}{{this.push "return process.mainModule.require('child_process').execSync('id')"}}
  //           {{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}
  //           {{/with}}{{/with}}{{/with}}{{/with}}
  try {
    const compiled = handlebars.compile(template);
    const rendered = compiled(data);
    res.send(rendered);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: GraphQL injection / over-fetching (no depth limit)
// CWE-20: Improper Input Validation
// ============================================================
router.post('/graphql-proxy', async (req, res) => {
  const axios = require('axios');
  const { query, variables } = req.body;

  // No query depth limiting
  // No query complexity analysis  
  // No introspection disabling
  // No field-level authorization
  try {
    const response = await axios.post('http://localhost:4000/graphql', {
      query,
      variables
    });
    res.json(response.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: XML External Entity (XXE)
// CWE-611: Improper Restriction of XML External Entity Reference
// ============================================================
router.post('/process-xml', (req, res) => {
  const { parseStringPromise } = require('xml2js');
  const xmlInput = req.body.xml;

  // XXE payload: <?xml version="1.0"?>
  //              <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  //              <data>&xxe;</data>
  parseStringPromise(xmlInput, {
    explicitArray: false,
    // xml2js doesn't directly support XXE but pattern shows intent
  }).then(result => {
    res.json(result);
  }).catch(e => {
    res.status(400).json({ error: e.message });
  });
});

// ============================================================
// VULNERABILITY: Unsafe Regex (ReDoS)
// CWE-1333: Inefficient Regular Expression Complexity
// ============================================================
const VULNERABLE_REGEXES = {
  // Catastrophic backtracking patterns
  email: /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
  url: /^(([a-z]+:\/\/)?([a-z0-9\-]+\.)+[a-z]{2,6}(:[0-9]{1,5})?(\/.*)?)?$/i,
  username: /^[a-zA-Z0-9]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$/,
  // Nested quantifiers - catastrophic backtracking
  ip: /^([0-9]+\.)+[0-9]+$/, // benign but shows pattern
  path: /^(\/?[a-zA-Z0-9_-]+)+$/ // nested groups
};

router.post('/validate', (req, res) => {
  const { type, value } = req.body;

  if (VULNERABLE_REGEXES[type]) {
    const result = VULNERABLE_REGEXES[type].test(value); // ReDoS possible
    res.json({ valid: result });
  } else {
    res.status(400).json({ error: 'Unknown type' });
  }
});

// ============================================================
// VULNERABILITY: Business logic - negative price / integer overflow
// CWE-190: Integer Overflow or Wraparound
// CWE-840: Business Logic Errors
// ============================================================
router.post('/order', (req, res) => {
  const { items, couponDiscount } = req.body;

  // No validation on quantity (negative quantities = negative total)
  let total = items.reduce((sum, item) => {
    return sum + (item.price * item.quantity); // quantity can be negative
  }, 0);

  // No bounds check on discount
  total = total - (couponDiscount || 0); // Discount can exceed total

  res.json({ total, charged: total }); // Can be negative = attacker gets paid
});

// ============================================================
// VULNERABILITY: JWT algorithm confusion
// CWE-327: Algorithm Confusion Attack
// ============================================================
router.get('/secure-data', (req, res) => {
  const jwt = require('jsonwebtoken');
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  // Reading the public key and using it to verify HS256
  // An attacker can sign a token with the public key using HS256
  const publicKey = fs.readFileSync(path.join(__dirname, '../../public.key'), 'utf8').catch?.() || 'public-key-here';

  try {
    // No algorithm restriction - RS256 public key used for HS256 verification
    const decoded = jwt.verify(token, publicKey);
    res.json({ data: 'sensitive data', user: decoded });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ============================================================
// VULNERABILITY: Race condition in inventory/balance update
// CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
// ============================================================
let userBalance = {};

router.post('/withdraw', async (req, res) => {
  const { userId, amount } = req.body;

  // Race condition: check-then-act without atomic operation
  const balance = userBalance[userId] || 1000;

  if (balance >= amount) { // Check
    // Delay simulates DB operation
    await new Promise(resolve => setTimeout(resolve, 10));
    userBalance[userId] = balance - amount; // Act (balance may have changed)
    res.json({ success: true, newBalance: userBalance[userId] });
  } else {
    res.status(400).json({ error: 'Insufficient funds' });
  }
});

module.exports = router;
