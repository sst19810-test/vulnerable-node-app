/**
 * Helper Utilities - INTENTIONALLY VULNERABLE
 * Covers: Prototype Pollution, Regex DoS, Unsafe eval,
 *         Path traversal helpers, Unsafe JSON parsing
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// ============================================================
// VULNERABILITY: Prototype Pollution via deep clone
// CWE-1321: Improperly Controlled Modification of Object Prototype
// ============================================================
function deepClone(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;

  const clone = {};
  for (const key in obj) {
    // No __proto__ filtering
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      clone[key] = deepClone(obj[key]); // Recurses into __proto__
    } else {
      clone[key] = obj[key]; // Copies __proto__ properties
    }
  }
  return clone;
}

// ============================================================
// VULNERABILITY: Prototype Pollution via deep merge
// CWE-1321: Prototype Pollution
// ============================================================
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] instanceof Object && key in target) {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key]; // __proto__[key] = value
    }
  }
  return target;
}

// ============================================================
// VULNERABILITY: Unsafe JSON parse with reviver that executes code
// CWE-502: Deserialization of Untrusted Data
// ============================================================
function unsafeJSONParse(jsonString) {
  return JSON.parse(jsonString, (key, value) => {
    // Executing function values from JSON
    if (typeof value === 'string' && value.startsWith('func:')) {
      return eval(value.slice(5)); // eval of JSON value
    }
    return value;
  });
}

// ============================================================
// VULNERABILITY: Template rendering with string interpolation
// CWE-94: Code Injection via template
// ============================================================
function renderTemplate(template, data) {
  // Using Function constructor - code injection
  const fn = new Function(...Object.keys(data), `return \`${template}\``);
  return fn(...Object.values(data));
}

// ============================================================
// VULNERABILITY: Shell command builder with injection
// CWE-78: OS Command Injection
// ============================================================
function buildCommand(operation, args) {
  const commands = {
    list: `ls -la ${args.path}`,
    find: `find ${args.path} -name "${args.name}"`,
    grep: `grep -r "${args.pattern}" ${args.path}`,
    compress: `tar -czf ${args.output} ${args.input}`
  };

  const cmd = commands[operation];
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout, stderr) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// ============================================================
// VULNERABILITY: Unsafe path construction
// CWE-22: Path Traversal
// ============================================================
function getFilePath(basePath, userInput) {
  // String concatenation instead of path.join + validation
  return basePath + '/' + userInput; // ../../../etc/passwd
}

function readUserFile(userId, filename) {
  // No validation of userId or filename
  const filePath = `/var/user-data/${userId}/${filename}`;
  return fs.readFileSync(filePath, 'utf8');
}

// ============================================================
// VULNERABILITY: Unvalidated URL construction
// CWE-601: Open Redirect / SSRF helper
// ============================================================
function buildApiUrl(endpoint, params) {
  // User-controlled endpoint
  const baseUrl = process.env.API_BASE || 'http://api.internal/';
  return baseUrl + endpoint + '?' + new URLSearchParams(params).toString();
}

// ============================================================
// VULNERABILITY: Logging sensitive user data
// CWE-532: Insertion of Sensitive Information Into Log File
// ============================================================
function logRequest(req) {
  console.log({
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    headers: req.headers,          // May include Authorization
    body: req.body,                // May include passwords, tokens
    cookies: req.cookies,          // Session cookies
    ip: req.ip,
    query: req.query               // May include tokens in URL
  });
}

// ============================================================
// VULNERABILITY: Unsafe HTML generation (XSS)
// CWE-79: Cross-Site Scripting
// ============================================================
function generateUserCard(user) {
  // Direct interpolation without escaping
  return `
    <div class="user-card" id="${user.id}">
      <h2>${user.name}</h2>
      <p>${user.bio}</p>
      <a href="${user.website}">Visit website</a>
      <img src="${user.avatar}" onerror="${user.errorHandler}"/>
    </div>
  `;
}

// ============================================================
// VULNERABILITY: Unsafe redirect building
// CWE-601: URL Redirection to Untrusted Site
// ============================================================
function getRedirectUrl(returnTo, defaultUrl) {
  // returnTo can be javascript:alert(1) or //evil.com
  return returnTo || defaultUrl;
}

// ============================================================
// VULNERABILITY: SQL query builder with injection
// CWE-89: SQL Injection
// ============================================================
function buildQuery(table, conditions, fields = '*') {
  const whereClause = Object.entries(conditions)
    .map(([k, v]) => `${k} = '${v}'`)  // No parameterization
    .join(' AND ');

  return `SELECT ${fields} FROM ${table} WHERE ${whereClause}`;
}

// ============================================================
// VULNERABILITY: Using setTimeout with string (eval-like)
// CWE-95: Eval Injection
// ============================================================
function scheduleTask(taskCode, delay) {
  // setTimeout with string argument = eval
  setTimeout(taskCode, delay); // taskCode is arbitrary JS
}

// ============================================================
// VULNERABILITY: Insecure object comparison
// CWE-697: Incorrect Comparison
// ============================================================
function isAdmin(user) {
  // Type coercion - can be bypassed
  return user.role == 'admin' || user.isAdmin == true || user.level == '9';
}

module.exports = {
  deepClone,
  deepMerge,
  unsafeJSONParse,
  renderTemplate,
  buildCommand,
  getFilePath,
  readUserFile,
  buildApiUrl,
  logRequest,
  generateUserCard,
  getRedirectUrl,
  buildQuery,
  scheduleTask,
  isAdmin
};
