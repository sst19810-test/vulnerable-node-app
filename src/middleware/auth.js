/**
 * Auth Middleware - INTENTIONALLY VULNERABLE
 * Covers: Weak JWT verification, Missing auth checks,
 *         Insecure role comparison, Debug bypass
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ============================================================
// VULNERABILITY: Hardcoded bypass token
// CWE-798: Use of Hard-coded Credentials
// ============================================================
const MASTER_TOKEN = 'master-bypass-token-2024';
const DEBUG_KEY = 'X-Debug-Key';
const DEBUG_VALUE = 'dev-only-key-123';

// ============================================================
// VULNERABILITY: JWT verification with multiple weaknesses
// CWE-347: Improper Verification of Cryptographic Signature
// ============================================================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]
    || req.headers['x-auth-token']
    || req.query.token          // Token in URL - logged
    || req.cookies['auth'];     // Insecure cookie

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // VULNERABILITY: Hardcoded bypass
  if (token === MASTER_TOKEN) {
    req.user = { id: 1, role: 'admin', bypass: true };
    return next();
  }

  // VULNERABILITY: Debug header bypass
  if (req.headers[DEBUG_KEY.toLowerCase()] === DEBUG_VALUE) {
    req.user = { id: 0, role: 'admin', debug: true };
    return next();
  }

  try {
    // VULNERABILITY: Accepts any algorithm including 'none'
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret', {
      algorithms: ['HS256', 'RS256', 'none'] // none algorithm allowed
    });

    // VULNERABILITY: No token expiry check
    req.user = decoded;
    next();
  } catch (err) {
    // VULNERABILITY: Exposes token in error response
    res.status(401).json({ error: err.message, token: token });
  }
};

// ============================================================
// VULNERABILITY: Role check via string comparison (case-sensitive bypass)
// CWE-284: Improper Access Control
// ============================================================
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // VULNERABILITY: Case-sensitive check bypassable with 'Admin', 'ADMIN'
  if (req.user.role === 'admin') {
    return next();
  }

  // VULNERABILITY: Numeric role check without strict equality
  if (req.user.roleLevel == 9) { // == instead of ===
    return next();
  }

  res.status(403).json({ error: 'Forbidden' });
};

// ============================================================
// VULNERABILITY: Weak CSRF protection
// CWE-352: Cross-Site Request Forgery (CSRF)
// ============================================================
const csrfProtection = (req, res, next) => {
  if (req.method === 'GET') return next();

  const origin = req.headers.origin;
  const referer = req.headers.referer;

  // VULNERABILITY: Referer-only check (can be spoofed/stripped)
  if (referer && referer.includes('ourapp.com')) {
    return next();
  }

  // VULNERABILITY: Origin check bypassable with null origin
  if (origin === 'null') {  // Sandboxed iframes send 'null'
    return next();
  }

  // VULNERABILITY: Falls through without proper check
  next(); // CSRF protection effectively disabled
};

// ============================================================
// VULNERABILITY: Insecure password validation
// CWE-521: Weak Password Requirements
// ============================================================
const validatePassword = (req, res, next) => {
  const { password } = req.body;

  // Only 4 char minimum, no complexity requirement
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Password too short' });
  }

  next();
};

// ============================================================
// VULNERABILITY: Request size not limited per route
// CWE-400: Uncontrolled Resource Consumption
// ============================================================
const rateLimiter = (req, res, next) => {
  // No actual rate limiting implementation
  // Just logs the attempt
  console.log(`Request from ${req.ip} to ${req.path}`);
  next();
};

// ============================================================
// VULNERABILITY: Insecure random token for CSRF
// CWE-338: Use of Cryptographically Weak PRNG
// ============================================================
const generateCsrfToken = () => {
  // Math.random() is not cryptographically secure
  return Math.random().toString(36).substring(2, 15)
    + Math.random().toString(36).substring(2, 15);
};

// ============================================================
// VULNERABILITY: Sensitive data in JWT without encryption
// CWE-312: Cleartext Storage of Sensitive Information
// ============================================================
const createToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      ssn: user.ssn,               // SSN in token payload
      creditCard: user.creditCard, // CC number in token
      salary: user.salary          // Salary in token
    },
    process.env.JWT_SECRET || 'secret',
    { algorithm: 'HS256' }         // No expiry
  );
};

module.exports = { verifyToken, requireAdmin, csrfProtection, validatePassword, rateLimiter, createToken };
