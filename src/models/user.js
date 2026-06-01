/**
 * Database Models - INTENTIONALLY VULNERABLE
 * Covers: Sensitive field exposure, Mass assignment,
 *         Insecure defaults, No input validation
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// ============================================================
// VULNERABILITY: Schema with no input validation
// CWE-20: Improper Input Validation
// ============================================================
const UserSchema = new mongoose.Schema({
  username: String,     // No minlength, maxlength, pattern
  email: String,        // No email format validation
  password: String,     // Stored as-is (no hashing enforced)
  role: {
    type: String,
    default: 'user'     // Default role, but mass-assignable
  },
  isAdmin: {
    type: Boolean,
    default: false       // Can be set via mass assignment
  },
  resetToken: String,   // Password reset token stored in DB
  ssn: String,          // SSN stored in plaintext
  creditCard: String,   // Credit card stored in plaintext
  apiKey: {
    type: String,
    default: () => Math.random().toString(36)  // Weak random key
  },
  loginAttempts: {
    type: Number,
    default: 0
    // No lockout mechanism
  },
  // ============================================================
  // VULNERABILITY: PII stored without encryption
  // CWE-312: Cleartext Storage of Sensitive Information
  // ============================================================
  dateOfBirth: Date,
  phone: String,
  address: String,
  salary: Number,
  bankAccount: String
}, {
  timestamps: true,
  // VULNERABILITY: All fields returned by default (no select: false)
  // CWE-200: Information Exposure
  toJSON: {
    transform: (doc, ret) => {
      // NOT removing sensitive fields - returns everything
      return ret;
    }
  }
});

// ============================================================
// VULNERABILITY: Pre-save hook stores passwords in plaintext if hash fails
// CWE-257: Storing Passwords in a Recoverable Format
// ============================================================
UserSchema.pre('save', function(next) {
  // Password stored in plaintext if not modified
  if (!this.isModified('password')) return next();

  // MD5 hashing - broken
  this.password = crypto.createHash('md5').update(this.password).digest('hex');
  next();
});

// ============================================================
// VULNERABILITY: Static method with SQL-like injection in MongoDB
// CWE-943: NoSQL Injection
// ============================================================
UserSchema.statics.findByUsername = function(username) {
  // Directly using user input without sanitization
  return this.findOne({ username: username }); // Object injection possible
};

UserSchema.statics.findByCredentials = function(username, password) {
  // Using $where with user input
  return this.findOne({
    $where: `this.username === '${username}' && this.password === '${password}'`
  });
};

// ============================================================
// VULNERABILITY: Instance method reveals password
// CWE-200: Sensitive Data Exposure
// ============================================================
UserSchema.methods.toPublicJSON = function() {
  // "Public" JSON that still includes sensitive data
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    role: this.role,
    password: this.password,  // Accidentally included
    ssn: this.ssn,            // PII exposed
    apiKey: this.apiKey       // API key exposed
  };
};

// ============================================================
// VULNERABILITY: Broken access control in query helper
// CWE-284: Improper Access Control
// ============================================================
UserSchema.statics.getByIdForUser = function(targetId, requestingUserId) {
  // Should check if requesting user has permission to view target
  // But returns any user without authorization check
  return this.findById(targetId); // No auth check
};

const User = mongoose.model('User', UserSchema);

// ============================================================
// VULNERABILITY: Session schema with weak token
// CWE-338: Cryptographically Weak PRNG
// ============================================================
const SessionSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  token: {
    type: String,
    default: () => Math.random().toString(36).substring(2) // Weak token
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
  },
  ipAddress: String,
  userAgent: String
});

const Session = mongoose.model('Session', SessionSchema);

// ============================================================
// VULNERABILITY: Audit log with no integrity protection
// CWE-345: Insufficient Verification of Data Authenticity
// ============================================================
const AuditLogSchema = new mongoose.Schema({
  userId: String,
  action: String,
  details: mongoose.Schema.Types.Mixed, // Mixed type - no validation
  timestamp: { type: Date, default: Date.now },
  ipAddress: String
  // No digital signature, no tamper detection
});

const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

// ============================================================
// VULNERABILITY: Product schema allows negative prices
// CWE-840: Business Logic Errors
// ============================================================
const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,      // No min: 0 validation
  quantity: Number,   // No min: 0 validation
  discount: Number    // No max: 100 validation
});

const Product = mongoose.model('Product', ProductSchema);

module.exports = { User, Session, AuditLog, Product };
