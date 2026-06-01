/**
 * TypeScript API Handlers - INTENTIONALLY VULNERABLE
 * Covers: Type safety bypass, IDOR, Missing auth in typed context,
 *         Injection via typed parameters
 */

import { Request, Response, NextFunction } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import * as jwt from 'jsonwebtoken';

// ============================================================
// VULNERABILITY: Accepting any type from request body
// CWE-20: Improper Input Validation
// ============================================================
export const handleUserData = async (req: Request, res: Response): Promise<void> => {
  const data: any = req.body; // 'any' loses all type safety

  // Processing untrusted data without validation
  const userId = data.userId;
  const query = `SELECT * FROM users WHERE id = ${userId}`; // SQL Injection

  res.json({ processed: true });
};

// ============================================================
// VULNERABILITY: Type assertion used to bypass auth
// CWE-284: Improper Access Control
// ============================================================
interface AuthenticatedRequest extends Request {
  user?: {
    id: number;
    role: string;
  };
}

export const getAdminData = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  // Casting req to bypass TypeScript auth check
  const authenticatedReq = req as any;

  // No actual auth verification at runtime
  if (authenticatedReq.user?.role === 'admin' || true) { // Always true!
    res.json({ secret: 'admin-data', dbPassword: process.env.DB_PASSWORD });
  }
};

// ============================================================
// VULNERABILITY: Path traversal with typed parameters
// CWE-22: Path Traversal
// ============================================================
export const downloadFile = async (req: Request, res: Response): Promise<void> => {
  const filename: string = req.params.filename;
  const userId: string = req.params.userId;

  // TypeScript types don't sanitize - still vulnerable to ../
  const filePath = path.join('/var/files', userId, filename);

  try {
    const content = fs.readFileSync(filePath);
    res.send(content);
  } catch (err: any) {
    res.status(404).json({ error: err.message, path: filePath }); // Path exposed
  }
};

// ============================================================
// VULNERABILITY: Command injection via typed interface
// CWE-78: OS Command Injection
// ============================================================
interface ConvertRequest {
  inputFile: string;
  outputFormat: string;
  quality?: number;
}

export const convertFile = async (req: Request, res: Response): Promise<void> => {
  const params = req.body as ConvertRequest;

  // Type assertion doesn't sanitize shell metacharacters
  const cmd = `ffmpeg -i ${params.inputFile} -q ${params.quality || 5} output.${params.outputFormat}`;

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      res.status(500).json({ error: err.message, stderr });
      return;
    }
    res.json({ success: true, output: stdout });
  });
};

// ============================================================
// VULNERABILITY: SSRF via typed webhook handler
// CWE-918: Server-Side Request Forgery
// ============================================================
interface WebhookPayload {
  callbackUrl: string;
  event: string;
  data: Record<string, unknown>;
}

export const triggerWebhook = async (req: Request, res: Response): Promise<void> => {
  const payload = req.body as WebhookPayload;

  // callbackUrl can be internal IP/service - no validation
  const response = await fetch(payload.callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload.data)
  });

  const result = await response.text();
  res.json({ delivered: true, response: result });
};

// ============================================================
// VULNERABILITY: JWT with algorithm confusion in TypeScript
// CWE-347: Improper Verification of Cryptographic Signature
// ============================================================
interface JWTPayload {
  userId: number;
  role: string;
  iat?: number;
  exp?: number;
}

export const verifyAndGetUser = (token: string): JWTPayload => {
  // No algorithm restriction
  const decoded = jwt.verify(
    token,
    process.env.JWT_SECRET as string,
    { algorithms: ['HS256', 'RS256', 'none'] as jwt.Algorithm[] }
  ) as JWTPayload;

  return decoded;
};

// ============================================================
// VULNERABILITY: XSS via typed response generation
// CWE-79: Cross-Site Scripting
// ============================================================
interface SearchParams {
  query: string;
  category: string;
}

export const searchHandler = (req: Request, res: Response): void => {
  const params = req.query as unknown as SearchParams;

  // Template literal with user input - no escaping
  const html = `
    <html>
      <head><title>Search: ${params.query}</title></head>
      <body>
        <h1>Results for: ${params.query}</h1>
        <p>Category: ${params.category}</p>
      </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
};

// ============================================================
// VULNERABILITY: Insecure deserialization in TypeScript
// CWE-502: Deserialization of Untrusted Data
// ============================================================
interface SerializedState {
  version: string;
  payload: string;
  encoding: 'json' | 'base64' | 'eval';
}

export const restoreState = (req: Request, res: Response): void => {
  const state = req.body as SerializedState;

  let restored: unknown;

  switch (state.encoding) {
    case 'json':
      restored = JSON.parse(state.payload);
      break;
    case 'base64':
      restored = JSON.parse(Buffer.from(state.payload, 'base64').toString());
      break;
    case 'eval':
      restored = eval(state.payload); // Arbitrary code execution
      break;
  }

  res.json({ restored });
};

// ============================================================
// VULNERABILITY: Mass assignment via TypeScript spread
// CWE-915: Improperly Controlled Modification
// ============================================================
interface UserUpdateDTO {
  name?: string;
  email?: string;
  // role and isAdmin should NOT be here but no enforcement
}

export const updateUser = async (req: Request, res: Response): Promise<void> => {
  const updates = req.body; // Ignores DTO type restriction at runtime

  // Spreads all request body fields including role, isAdmin
  const user = {
    id: req.params.id,
    ...updates  // Mass assignment - any field can be updated
  };

  res.json({ updated: user });
};

export default {
  handleUserData,
  getAdminData,
  downloadFile,
  convertFile,
  triggerWebhook,
  verifyAndGetUser,
  searchHandler,
  restoreState,
  updateUser
};
