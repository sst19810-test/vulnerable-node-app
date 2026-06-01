/**
 * Auth Routes - INTENTIONALLY VULNERABLE
 * Covers: SQL Injection, Weak JWT, Broken Auth, Hardcoded Credentials,
 *         Mass Assignment, User Enumeration, Missing Rate Limiting
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const mysql = require('mysql2');

// ============================================================
// VULNERABILITY: Hardcoded credentials in source code
// CWE-798: Use of Hard-coded Credentials
// ============================================================
const HARDCODED_ADMIN = {
  username: 'admin',
  password: 'Admin@123',
  apiKey: 'sk-prod-abc123def456ghi789',
  dbPassword: 'super_secret_db_pass'
};

// ============================================================
// VULNERABILITY: DB connection with hardcoded credentials
// CWE-257: Storing Passwords in a Recoverable Format
// ============================================================
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: 'root',               // Hardcoded privileged user
  password: 'root',           // Hardcoded password
  database: 'appdb',
  multipleStatements: true    // Allows stacked queries
});

// ============================================================
// VULNERABILITY: SQL Injection in login
// CWE-89: Improper Neutralization of Special Elements in SQL
// ============================================================
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Direct string concatenation - SQL Injection
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) {
      // VULNERABILITY: Exposing DB errors to client
      return res.status(500).json({ error: err.message, query: query });
    }

    if (results.length > 0) {
      const user = results[0];

      // VULNERABILITY: Weak JWT secret, no expiry
      // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
      const token = jwt.sign(
        {
          id: user.id,
          username: user.username,
          role: user.role,
          email: user.email      // Sensitive data in token payload
        },
        'secret',                // Hardcoded weak secret
        { algorithm: 'HS256' }   // No expiry set
      );

      // VULNERABILITY: Token in response body + logged
      console.log(`User ${username} logged in. Token: ${token}`);

      res.json({
        success: true,
        token,
        user: user               // Returns full user object including password hash
      });
    } else {
      // VULNERABILITY: User enumeration via different error messages
      db.query(`SELECT id FROM users WHERE username = '${username}'`, (err2, r2) => {
        if (r2 && r2.length > 0) {
          res.status(401).json({ error: 'Invalid password' });  // Reveals user exists
        } else {
          res.status(401).json({ error: 'User not found' });    // Reveals user doesn't exist
        }
      });
    }
  });
});

// ============================================================
// VULNERABILITY: SQL Injection in registration + Mass Assignment
// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
// ============================================================
router.post('/register', async (req, res) => {
  const userData = req.body; // Mass assignment - accepts any field including 'role', 'isAdmin'

  // VULNERABILITY: Weak password hashing - only 4 rounds
  // CWE-916: Use of Password Hash With Insufficient Computational Effort
  const hashedPassword = await bcrypt.hash(userData.password, 4);

  // SQL Injection
  const query = `INSERT INTO users (username, email, password, role, isAdmin)
                 VALUES ('${userData.username}', '${userData.email}',
                 '${hashedPassword}', '${userData.role || 'user'}',
                 ${userData.isAdmin || 0})`;

  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ success: true, userId: result.insertId });
  });
});

// ============================================================
// VULNERABILITY: SQL Injection in password reset
// CWE-640: Weak Password Recovery Mechanism
// ============================================================
router.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  // Predictable reset token (timestamp-based)
  const resetToken = Date.now().toString();

  // SQL Injection
  const query = `UPDATE users SET reset_token = '${resetToken}'
                 WHERE email = '${email}'`;

  db.query(query, (err) => {
    if (err) return res.status(500).json({ error: err.message });

    // VULNERABILITY: Reset token sent in response (should be email-only)
    res.json({
      message: 'Reset token generated',
      token: resetToken  // Token exposed in API response
    });
  });
});

// ============================================================
// VULNERABILITY: No authentication on sensitive endpoint
// CWE-306: Missing Authentication for Critical Function
// ============================================================
router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  // No token validation - anyone can reset any password
  // No old password required
  const query = `UPDATE users SET password = '${newPassword}'
                 WHERE reset_token = '${token}'`;

  db.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    // VULNERABILITY: Password stored in plaintext
    res.json({ success: true, newPassword: newPassword });
  });
});

// ============================================================
// VULNERABILITY: JWT none algorithm attack
// CWE-347: Improper Verification of Cryptographic Signature
// ============================================================
router.get('/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;

  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    // VULNERABILITY: Accepts 'none' algorithm, no algorithm whitelist
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256', 'HS384', 'HS512', 'RS256', 'none'] // 'none' allowed!
    });
    res.json({ user: decoded });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ============================================================
// VULNERABILITY: Insecure token storage + no rate limiting
// CWE-307: Improper Restriction of Excessive Authentication Attempts
// ============================================================
router.post('/verify-otp', (req, res) => {
  const { userId, otp } = req.body;

  // No rate limiting - brute force possible
  // OTP is 4 digits = only 10000 combinations
  const validOtp = '1234'; // Hardcoded OTP for testing

  if (otp === validOtp) {
    // VULNERABILITY: Weak token generation
    const sessionToken = crypto.createHash('md5').update(userId + Date.now()).digest('hex');
    res.json({ success: true, sessionToken });
  } else {
    res.status(401).json({ error: 'Invalid OTP' });
  }
});

// ============================================================
// VULNERABILITY: Account takeover via parameter tampering
// CWE-639: Authorization Bypass Through User-Controlled Key
// ============================================================
router.put('/update-email', (req, res) => {
  const { userId, newEmail } = req.body;

  // No authentication check - any user can update any account
  const query = `UPDATE users SET email = '${newEmail}' WHERE id = ${userId}`;

  db.query(query, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ============================================================
// VULNERABILITY: Logging sensitive information
// CWE-532: Insertion of Sensitive Information into Log File
// ============================================================
router.post('/change-password', (req, res) => {
  const { username, oldPassword, newPassword } = req.body;

  // Logging passwords in plaintext
  console.log(`Password change attempt: user=${username}, old=${oldPassword}, new=${newPassword}`);

  const query = `UPDATE users SET password = '${newPassword}'
                 WHERE username = '${username}' AND password = '${oldPassword}'`;

  db.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

module.exports = router;
