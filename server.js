/**
 * VULNERABLE NODE.JS APPLICATION
 * Intentionally insecure for SAST tool testing
 * DO NOT USE IN PRODUCTION
 */

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const app = express();

// ============================================================
// VULNERABILITY: Overly permissive CORS
// CWE-346: Origin Validation Error
// ============================================================
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: '*'
}));

// ============================================================
// VULNERABILITY: Missing security headers (no helmet)
// CWE-693: Protection Mechanism Failure
// ============================================================

// ============================================================
// VULNERABILITY: Verbose logging exposes sensitive data
// CWE-532: Insertion of Sensitive Information into Log File
// ============================================================
app.use(morgan('combined'));

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// ============================================================
// VULNERABILITY: Weak session configuration
// CWE-614: Sensitive Cookie Without 'Secure' Attribute
// CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
// ============================================================
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-weak-secret',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,      // No HTTPS enforcement
    httpOnly: false,    // Accessible via JS (XSS risk)
    maxAge: 999999999,  // Never expires
    sameSite: false     // No CSRF protection
  }
}));

// ============================================================
// VULNERABILITY: Exposing stack traces in error handler
// CWE-209: Generation of Error Message Containing Sensitive Info
// ============================================================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,         // Exposes full stack trace
    path: req.path,
    body: req.body            // Echoes back request body
  });
});

// ============================================================
// VULNERABILITY: Static file serving with directory listing
// CWE-548: Exposure of Information Through Directory Listing
// ============================================================
app.use('/static', express.static(path.join(__dirname, 'uploads'), {
  dotfiles: 'allow',   // Serves .env, .git etc.
  index: true          // Enables directory listing
}));

// ============================================================
// VULNERABILITY: Serving sensitive files publicly
// CWE-538: File and Directory Information Exposure
// ============================================================
app.get('/config', (req, res) => {
  const config = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
  res.send(config);
});

// Routes
const authRoutes   = require('./src/routes/auth');
const userRoutes   = require('./src/routes/users');
const fileRoutes   = require('./src/routes/files');
const apiRoutes    = require('./src/routes/api');
const adminRoutes  = require('./src/routes/admin');
const searchRoutes = require('./src/routes/search'); // Multi-file Flow A

app.use('/auth',   authRoutes);
app.use('/users',  userRoutes);
app.use('/files',  fileRoutes);
app.use('/api',    apiRoutes);
app.use('/admin',  adminRoutes);
app.use('/search', searchRoutes); // Flow A: search.js → helpers.js → db.js

// ============================================================
// VULNERABILITY: Reflecting user input directly in HTML
// CWE-79: Improper Neutralization of Input (XSS)
// ============================================================
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <!-- Results here -->
      </body>
    </html>
  `);
});

// ============================================================
// VULNERABILITY: Open redirect
// CWE-601: URL Redirection to Untrusted Site
// ============================================================
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

// ============================================================
// VULNERABILITY: Information disclosure via /debug endpoint
// CWE-215: Insertion of Sensitive Information Into Debugging Code
// ============================================================
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    cwd: process.cwd(),
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    pid: process.pid
  });
});

// ============================================================
// VULNERABILITY: Eval of user-supplied input
// CWE-95: Improper Neutralization of Directives in Code
// ============================================================
app.post('/calculate', (req, res) => {
  const expression = req.body.expression;
  try {
    // Direct eval - arbitrary code execution
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: prototype pollution via merge
// CWE-1321: Improperly Controlled Modification of Object Prototype
// ============================================================
app.post('/merge', (req, res) => {
  const target = {};
  const source = req.body;

  // Unsafe recursive merge
  function merge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key]; // __proto__ pollution possible
      }
    }
    return target;
  }

  const result = merge(target, source);
  res.json(result);
});

// ============================================================
// VULNERABILITY: ReDoS - catastrophic backtracking regex
// CWE-1333: Inefficient Regular Expression Complexity
// ============================================================
app.post('/validate-email', (req, res) => {
  const email = req.body.email;
  // ReDoS vulnerable regex
  const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

// ============================================================
// VULNERABILITY: XML External Entity (XXE)
// CWE-611: Improper Restriction of XML External Entity Reference
// ============================================================
app.post('/parse-xml', (req, res) => {
  const xml2js = require('xml2js');
  const xmlData = req.body.xml;

  // XXE vulnerable parser options
  const parser = new xml2js.Parser({
    explicitArray: false,
    // No entity resolution disabled
  });

  parser.parseString(xmlData, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(result);
  });
});

// ============================================================
// VULNERABILITY: Zip Slip via tar extraction
// CWE-22: Path Traversal in Archive Extraction
// ============================================================
app.post('/extract', async (req, res) => {
  const tar = require('tar');
  const filePath = req.body.filePath;

  // No path validation - zip slip possible
  await tar.extract({
    file: filePath,
    cwd: '/tmp/extracted'
  });

  res.json({ message: 'Extracted successfully' });
});

// ============================================================
// VULNERABILITY: HTTP Response Splitting
// CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
// ============================================================
app.get('/set-lang', (req, res) => {
  const lang = req.query.lang;
  // User input directly in header - CRLF injection
  res.setHeader('Content-Language', lang);
  res.send('Language set');
});

// ============================================================
// VULNERABILITY: Timing attack on string comparison
// CWE-208: Observable Timing Discrepancy
// ============================================================
app.post('/verify-token', (req, res) => {
  const token = req.body.token;
  const validToken = process.env.INTERNAL_API_TOKEN;

  // Non-constant-time comparison
  if (token === validToken) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`DB Password: ${process.env.DB_PASSWORD}`); // Logging credentials
});

module.exports = app;
