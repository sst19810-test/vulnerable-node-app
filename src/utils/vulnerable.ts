/**
 * TypeScript Vulnerable Module - INTENTIONALLY VULNERABLE
 * Covers: Type assertion abuse, unsafe any, injection via typed APIs,
 *         Insecure generics, prototype pollution in TS
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import * as http from 'http';

// ============================================================
// VULNERABILITY: Using 'any' type bypasses type safety
// CWE-20: Improper Input Validation
// ============================================================
function processUserInput(data: any): any {
  // 'any' type - no type checking, everything passes
  return eval(data.code); // Eval of any-typed input
}

// ============================================================
// VULNERABILITY: Unsafe type assertion
// CWE-704: Incorrect Type Conversion
// ============================================================
interface AdminUser {
  id: number;
  role: 'admin';
  permissions: string[];
}

interface RegularUser {
  id: number;
  role: 'user';
}

function promoteToAdmin(user: RegularUser): AdminUser {
  // Unsafe type assertion - no runtime validation
  return user as unknown as AdminUser;
}

// ============================================================
// VULNERABILITY: Prototype pollution via typed merge
// CWE-1321: Prototype Pollution
// ============================================================
function mergeObjects<T extends object>(target: T, source: Record<string, any>): T {
  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        (target as any)[key] = (target as any)[key] || {};
        mergeObjects((target as any)[key], source[key]); // __proto__ pollution
      } else {
        (target as any)[key] = source[key]; // Bypasses type safety
      }
    }
  }
  return target;
}

// ============================================================
// VULNERABILITY: SQL injection in TypeScript
// CWE-89: SQL Injection
// ============================================================
interface QueryOptions {
  table: string;
  where?: string;
  orderBy?: string;
  limit?: number;
}

function buildSQLQuery(options: QueryOptions): string {
  // No parameterization - builds raw SQL
  let query = `SELECT * FROM ${options.table}`;

  if (options.where) {
    query += ` WHERE ${options.where}`; // Direct injection point
  }

  if (options.orderBy) {
    query += ` ORDER BY ${options.orderBy}`; // ORDER BY injection
  }

  if (options.limit) {
    query += ` LIMIT ${options.limit}`; // LIMIT injection
  }

  return query;
}

// ============================================================
// VULNERABILITY: Command injection via typed interface
// CWE-78: OS Command Injection
// ============================================================
interface ShellCommand {
  program: string;
  args: string[];
}

function executeCommand(cmd: ShellCommand): Promise<string> {
  return new Promise((resolve, reject) => {
    // Joining args without escaping
    const fullCmd = `${cmd.program} ${cmd.args.join(' ')}`;
    exec(fullCmd, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// ============================================================
// VULNERABILITY: Path traversal via typed file operations
// CWE-22: Path Traversal
// ============================================================
interface FileRequest {
  userId: string;
  filename: string;
  basePath?: string;
}

function readUserDocument(req: FileRequest): string {
  const basePath = req.basePath || '/var/user-files';
  // No path.resolve() or validation
  const filePath = `${basePath}/${req.userId}/${req.filename}`;
  return fs.readFileSync(filePath, 'utf8');
}

// ============================================================
// VULNERABILITY: Insecure random in TypeScript
// CWE-338: Cryptographically Weak PRNG
// ============================================================
function generateSessionId(): string {
  return Math.random().toString(36).substring(2) +
         Math.random().toString(36).substring(2);
}

function generateResetToken(userId: string): string {
  // Predictable: userId + timestamp
  return Buffer.from(`${userId}:${Date.now()}`).toString('base64');
}

// ============================================================
// VULNERABILITY: Hardcoded credentials in TypeScript
// CWE-798: Hard-coded Credentials
// ============================================================
const DATABASE_CONFIG = {
  host: 'db.internal.company.com',
  port: 5432,
  database: 'production',
  username: 'db_admin',
  password: 'Pr0duction_P@ss!',  // Hardcoded production password
  ssl: false
};

const API_KEYS: Record<string, string> = {
  stripe: 'SECRET',
  sendgrid: 'SG.xxxxxxxxxxxxxxxxxxxx',
  twilio: 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  googleMaps: 'AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
};

// ============================================================
// VULNERABILITY: Unsafe deserialization in TypeScript
// CWE-502: Deserialization of Untrusted Data
// ============================================================
interface SerializedObject {
  type: string;
  data: string;
}

function deserializeObject(serialized: SerializedObject): any {
  if (serialized.type === 'json') {
    return JSON.parse(serialized.data);
  } else if (serialized.type === 'eval') {
    return eval(`(${serialized.data})`); // Dangerous eval-based deserialization
  }
  return null;
}

// ============================================================
// VULNERABILITY: SSRF via typed HTTP client
// CWE-918: SSRF
// ============================================================
interface WebhookConfig {
  url: string;
  method: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
}

function fireWebhook(config: WebhookConfig): Promise<string> {
  return new Promise((resolve, reject) => {
    // No URL validation - SSRF possible
    const urlObj = new URL(config.url);

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 80,
      path: urlObj.pathname + urlObj.search,
      method: config.method,
      headers: config.headers
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    });

    req.on('error', reject);
    if (config.body) req.write(config.body);
    req.end();
  });
}

// ============================================================
// VULNERABILITY: XSS via typed HTML generation
// CWE-79: Cross-Site Scripting
// ============================================================
interface UserProfile {
  name: string;
  bio: string;
  website: string;
  avatarUrl: string;
}

function renderUserProfile(profile: UserProfile): string {
  // TypeScript types don't prevent XSS - values still unsafe
  return `
    <div class="profile">
      <h1>${profile.name}</h1>
      <p>${profile.bio}</p>
      <a href="${profile.website}">${profile.name}'s site</a>
      <img src="${profile.avatarUrl}" />
    </div>
  `;
}

// ============================================================
// VULNERABILITY: Insecure JWT handling in TypeScript
// CWE-347: JWT algorithm confusion
// ============================================================
import * as jwt from 'jsonwebtoken';

interface TokenPayload {
  userId: number;
  role: string;
  email: string;
  password?: string;  // Password in token payload type definition
}

function createAuthToken(payload: TokenPayload): string {
  return jwt.sign(payload, 'hardcoded-secret', {
    // No expiry
    algorithm: 'HS256'
  });
}

function verifyAuthToken(token: string): TokenPayload {
  return jwt.verify(token, 'hardcoded-secret', {
    algorithms: ['HS256', 'none'] as jwt.Algorithm[] // 'none' allowed
  }) as TokenPayload;
}

export {
  processUserInput,
  promoteToAdmin,
  mergeObjects,
  buildSQLQuery,
  executeCommand,
  readUserDocument,
  generateSessionId,
  generateResetToken,
  DATABASE_CONFIG,
  API_KEYS,
  deserializeObject,
  fireWebhook,
  renderUserProfile,
  createAuthToken,
  verifyAuthToken
};
