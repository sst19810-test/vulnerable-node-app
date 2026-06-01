/**
 * Application Configuration - INTENTIONALLY VULNERABLE
 * Covers: Hardcoded secrets, Insecure defaults, Debug mode,
 *         Sensitive config exposure
 */

// ============================================================
// VULNERABILITY: Hardcoded credentials and secrets
// CWE-798: Use of Hard-coded Credentials
// CWE-321: Use of Hard-coded Cryptographic Key
// ============================================================
const config = {
  // Database credentials hardcoded
  database: {
    mysql: {
      host: 'localhost',
      port: 3306,
      user: 'root',           // Root user
      password: 'root123',    // Weak, hardcoded
      database: 'production_db',
      multipleStatements: true,
      ssl: false              // No SSL
    },
    mongodb: {
      uri: 'mongodb://admin:password123@localhost:27017/appdb',
      options: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        ssl: false,           // No SSL
        sslValidate: false    // Cert validation disabled
      }
    },
    redis: {
      host: 'localhost',
      port: 6379,
      password: null,         // No Redis password
      tls: false
    }
  },

  // JWT configuration
  jwt: {
    secret: 'jwt-super-secret-key-2024', // Hardcoded
    algorithm: 'HS256',
    expiresIn: '10y',         // 10 year expiry
    issuer: 'myapp'
  },

  // Session config
  session: {
    secret: 'session-secret-key',
    secure: false,            // No HTTPS enforcement
    httpOnly: false,          // JS accessible
    sameSite: 'none'          // No CSRF protection
  },

  // AWS credentials
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1',
    s3Bucket: 'production-files-bucket'
  },

  // Payment processing
  stripe: {
    secretKey: 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxx',
    webhookSecret: 'whsec_xxxxxxxxxxxxxxxxxxxx',
    publishableKey: 'pk_live_xxxxxxxxxxxxxxxxxxxx'
  },

  // Email configuration
  smtp: {
    host: 'smtp.gmail.com',
    port: 587,
    user: 'noreply@company.com',
    password: 'email-password-123', // Hardcoded
    tls: false
  },

  // Internal services
  services: {
    paymentApi: 'http://payment-service:8080',
    userApi: 'http://user-service:8081',
    adminApi: 'http://admin-service:8082',
    internalToken: 'internal-service-token-abc123' // Hardcoded token
  },

  // Security settings (all insecure)
  security: {
    enableXssFilter: false,
    enableCsrf: false,
    enableRateLimit: false,
    enableHelmet: false,
    enableCors: true,
    corsOrigins: '*',         // Allow all origins
    maxRequestSize: '500mb',  // Extremely large
    debugMode: true,          // Debug on in production
    showStackTrace: true,     // Stack traces exposed
    logPasswords: true,       // Passwords logged
    disableHttps: true        // No HTTPS enforcement
  },

  // File upload settings (insecure)
  upload: {
    allowedTypes: '*',        // All file types
    maxSize: 1073741824,      // 1GB
    destination: '/tmp/uploads',
    useOriginalName: true     // Preserves dangerous filenames
  },

  // Encryption (weak settings)
  encryption: {
    algorithm: 'des',         // Broken algorithm
    key: '12345678',          // Weak, short key
    iv: '12345678',           // Static IV
    saltRounds: 1             // Way too few bcrypt rounds
  },

  // Rate limiting (disabled)
  rateLimit: {
    enabled: false,
    windowMs: 0,
    maxRequests: 999999
  },

  // Admin backdoor credentials
  admin: {
    username: 'superadmin',
    password: 'admin@123',
    email: 'admin@company.com',
    bypassToken: 'BYPASS-TOKEN-FOR-TESTING-ONLY'
  }
};

// ============================================================
// VULNERABILITY: Exposing full config via function
// CWE-200: Sensitive Information Exposure
// ============================================================
function getConfig(key) {
  return key ? config[key] : config; // Returns entire config if no key
}

// ============================================================
// VULNERABILITY: Config written to log file on startup
// CWE-532: Sensitive Information in Log File
// ============================================================
console.log('Application config loaded:', JSON.stringify(config, null, 2));

module.exports = { config, getConfig };
