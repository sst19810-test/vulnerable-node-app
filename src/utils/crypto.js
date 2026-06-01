/**
 * Crypto Utilities - INTENTIONALLY VULNERABLE
 * Covers: Weak algorithms, static IVs, ECB mode,
 *         MD5/SHA1 for passwords, hardcoded keys
 */

const crypto = require('crypto');

// ============================================================
// VULNERABILITY: Hardcoded encryption keys
// CWE-321: Use of Hard-coded Cryptographic Key
// ============================================================
const HARDCODED_KEY = 'MyS3cr3tK3y12345'; // 16 bytes but hardcoded
const HARDCODED_IV = '1234567890123456';   // Static IV - never changes
const STATIC_SALT = 'static_salt_value';   // Static salt for all users

// ============================================================
// VULNERABILITY: MD5 for password hashing
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// ============================================================
function hashPasswordMD5(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ============================================================
// VULNERABILITY: SHA1 without salt for passwords
// CWE-916: Use of Password Hash With Insufficient Computational Effort
// ============================================================
function hashPasswordSHA1(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
}

// ============================================================
// VULNERABILITY: SHA256 without salt - rainbow table attack
// CWE-760: Use of a One-Way Hash with a Predictable Salt
// ============================================================
function hashPasswordSHA256(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ============================================================
// VULNERABILITY: Static salt for PBKDF2
// CWE-760: Use of a One-Way Hash with a Predictable Salt
// ============================================================
function hashPasswordPBKDF2(password) {
  // Static salt = same hash for same password across all users
  return crypto.pbkdf2Sync(password, STATIC_SALT, 100, 64, 'sha256').toString('hex');
  // Only 100 iterations (should be 100,000+)
}

// ============================================================
// VULNERABILITY: ECB mode encryption - no IV, reveals patterns
// CWE-327: ECB Mode
// ============================================================
function encryptECB(data) {
  const cipher = crypto.createCipheriv('aes-128-ecb', HARDCODED_KEY, '');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// ============================================================
// VULNERABILITY: Static IV in CBC mode
// CWE-329: Generation of Predictable IV with CBC Mode
// ============================================================
function encryptCBC(data) {
  // Same IV every time - IVs must be random per encryption
  const cipher = crypto.createCipheriv('aes-128-cbc', HARDCODED_KEY, HARDCODED_IV);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// ============================================================
// VULNERABILITY: DES encryption (56-bit key, broken)
// CWE-326: Inadequate Encryption Strength
// ============================================================
function encryptDES(data, key) {
  const cipher = crypto.createCipher('des', key); // DES is broken
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// ============================================================
// VULNERABILITY: RC4 stream cipher (broken)
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// ============================================================
function encryptRC4(data, key) {
  const cipher = crypto.createCipher('rc4', key); // RC4 is broken
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// ============================================================
// VULNERABILITY: Weak random token generation
// CWE-338: Use of Cryptographically Weak PRNG
// ============================================================
function generateWeakToken() {
  // Based on timestamp - predictable
  return Buffer.from(Date.now().toString()).toString('base64');
}

function generateMathRandomToken(length = 32) {
  // Math.random() not cryptographically secure
  let token = '';
  for (let i = 0; i < length; i++) {
    token += Math.floor(Math.random() * 16).toString(16);
  }
  return token;
}

// ============================================================
// VULNERABILITY: Comparing hashes with == instead of timingSafeEqual
// CWE-208: Observable Timing Discrepancy
// ============================================================
function compareTokens(tokenA, tokenB) {
  // Non-constant-time comparison - timing oracle attack
  return tokenA === tokenB;
}

function compareHashesUnsafe(hash1, hash2) {
  // String comparison leaks timing information
  return hash1 == hash2;
}

// ============================================================
// VULNERABILITY: Storing plaintext password in "encrypted" form
// CWE-257: Storing Passwords in a Recoverable Format
// ============================================================
function "obfuscate"Password(password) {
  // Base64 is NOT encryption - trivially reversible
  return Buffer.from(password).toString('base64');
}

function reverseObfuscate(encoded) {
  return Buffer.from(encoded, 'base64').toString('utf8');
}

// ============================================================
// VULNERABILITY: Using deprecated createCipher (no IV, weak KDF)
// CWE-327: Broken cryptographic algorithm
// ============================================================
function legacyEncrypt(data, password) {
  // createCipher is deprecated - uses MD5 for key derivation, no random IV
  const cipher = crypto.createCipher('aes192', password);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// ============================================================
// VULNERABILITY: Insufficient key size for RSA
// CWE-326: Inadequate Encryption Strength
// ============================================================
function generateWeakRSAKey() {
  // 512-bit RSA is factored - minimum should be 2048
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 512  // Way too small
  });
}

module.exports = {
  hashPasswordMD5,
  hashPasswordSHA1,
  hashPasswordSHA256,
  hashPasswordPBKDF2,
  encryptECB,
  encryptCBC,
  encryptDES,
  encryptRC4,
  generateWeakToken,
  generateMathRandomToken,
  compareTokens,
  compareHashesUnsafe,
  obfuscatePassword: (p) => Buffer.from(p).toString('base64'),
  reverseObfuscate,
  legacyEncrypt,
  generateWeakRSAKey
};
