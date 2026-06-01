/**
 * Admin Routes - INTENTIONALLY VULNERABLE
 * Covers: Broken Access Control, Code Injection, SSRF,
 *         Unsafe eval, Subprocess injection, Info disclosure
 */

const express = require('express');
const router = express.Router();
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ============================================================
// VULNERABILITY: No authentication on admin routes
// CWE-306: Missing Authentication for Critical Function
// CWE-862: Missing Authorization
// ============================================================
// No auth middleware applied to admin router

router.get('/dashboard', (req, res) => {
  // Accessible by anyone - no auth check
  res.json({
    dbPassword: process.env.DB_PASSWORD,
    jwtSecret: process.env.JWT_SECRET,
    awsKeys: {
      accessKey: process.env.AWS_ACCESS_KEY_ID,
      secretKey: process.env.AWS_SECRET_ACCESS_KEY
    },
    adminCredentials: {
      username: process.env.ADMIN_USERNAME,
      password: process.env.ADMIN_PASSWORD
    }
  });
});

// ============================================================
// VULNERABILITY: Remote Code Execution via vm2 escape
// CWE-94: Improper Control of Generation of Code
// ============================================================
router.post('/run-script', (req, res) => {
  const { VM } = require('vm2');
  const script = req.body.script;

  // vm2 has known escapes, also running untrusted code
  const vm2 = new VM({
    timeout: 1000,
    sandbox: { console }
  });

  try {
    const result = vm2.run(script); // vm2 sandbox escape possible
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: Direct eval in admin context
// CWE-95: Improper Neutralization of Directives in Evaluated Code
// ============================================================
router.post('/eval', (req, res) => {
  const code = req.body.code;
  try {
    // eval() with full access to server context
    const result = eval(code);
    res.json({ result: String(result) });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

// ============================================================
// VULNERABILITY: OS Command Injection
// CWE-78: OS Command Injection
// ============================================================
router.get('/ping', (req, res) => {
  const host = req.query.host;

  // Payload: host=127.0.0.1; cat /etc/passwd
  exec(`ping -c 4 ${host}`, (err, stdout, stderr) => {
    res.json({ output: stdout, error: stderr });
  });
});

router.get('/dig', (req, res) => {
  const domain = req.query.domain;

  // Payload: google.com && id
  const result = execSync(`dig ${domain}`).toString();
  res.json({ result });
});

router.post('/backup', (req, res) => {
  const { dbName, backupPath } = req.body;

  // Both parameters injectable
  const cmd = `mysqldump -u root -proot ${dbName} > ${backupPath}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ success: true, output: stdout });
  });
});

// ============================================================
// VULNERABILITY: Path Traversal in config read/write
// CWE-22: Path Traversal
// ============================================================
router.get('/config/:name', (req, res) => {
  const configName = req.params.name;

  // Path traversal: /admin/config/../../../etc/passwd
  const configPath = path.join('/app/config/', configName);
  const content = fs.readFileSync(configPath, 'utf8');

  res.json({ config: content });
});

router.post('/config/:name', (req, res) => {
  const configName = req.params.name;
  const content = req.body.content;

  // Arbitrary file write
  const configPath = '/app/config/' + configName;
  fs.writeFileSync(configPath, content);

  res.json({ saved: true });
});

// ============================================================
// VULNERABILITY: SSRF via webhook URL
// CWE-918: Server-Side Request Forgery
// ============================================================
router.post('/webhook-test', async (req, res) => {
  const axios = require('axios');
  const { url, payload } = req.body;

  // No URL validation - internal service access possible
  // http://169.254.169.254/latest/meta-data/iam/security-credentials/
  // http://kubernetes.default.svc/api/v1/secrets
  // file:///etc/passwd
  try {
    const response = await axios.post(url, payload);
    res.json({ status: response.status, data: response.data });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

// ============================================================
// VULNERABILITY: Insecure deserialization via cookie
// CWE-502: Deserialization of Untrusted Data
// ============================================================
router.get('/session-info', (req, res) => {
  const nodeSerialize = require('node-serialize');
  const sessionData = req.cookies['admin-session'];

  if (sessionData) {
    // Deserializing untrusted cookie data
    try {
      const decoded = Buffer.from(sessionData, 'base64').toString();
      const session = nodeSerialize.unserialize(decoded); // RCE possible
      res.json({ session });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  } else {
    res.json({ session: null });
  }
});

// ============================================================
// VULNERABILITY: Server info disclosure
// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
// ============================================================
router.get('/server-info', (req, res) => {
  res.json({
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    pid: process.pid,
    cwd: process.cwd(),
    env: process.env,           // Full environment variables
    argv: process.argv,
    execPath: process.execPath,
    memoryUsage: process.memoryUsage(),
    cpuUsage: process.cpuUsage(),
    uptime: process.uptime(),
    versions: process.versions
  });
});

// ============================================================
// VULNERABILITY: SQL Injection with UNION attack
// CWE-89: SQL Injection
// ============================================================
const mysql = require('mysql2');
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'appdb'
});

router.get('/users', (req, res) => {
  const { search, role, limit } = req.query;

  // Multiple injection points
  // UNION attack: search=' UNION SELECT username,password,3 FROM users--
  const query = `SELECT id, username, email FROM users
                 WHERE username LIKE '%${search}%'
                 AND role = '${role}'
                 LIMIT ${limit}`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ============================================================
// VULNERABILITY: Arbitrary module require (code injection)
// CWE-706: Use of Incorrectly-Resolved Name or Reference
// ============================================================
router.post('/load-plugin', (req, res) => {
  const pluginName = req.body.plugin;

  // Arbitrary require() - can load any module or path
  // Payload: ../../../../tmp/malicious-module
  try {
    const plugin = require(pluginName);
    const result = plugin.execute?.(req.body.args);
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: Log injection
// CWE-117: Improper Output Neutralization for Logs
// ============================================================
router.post('/log-event', (req, res) => {
  const { event, user, data } = req.body;

  // Log injection via newline characters
  // Payload: user=admin\n[CRITICAL] Fake security event injected
  console.log(`[ADMIN EVENT] User: ${user} | Event: ${event} | Data: ${JSON.stringify(data)}`);
  fs.appendFileSync('/var/log/admin.log',
    `${new Date().toISOString()} | ${user} | ${event} | ${data}\n`
  );

  res.json({ logged: true });
});

module.exports = router;
