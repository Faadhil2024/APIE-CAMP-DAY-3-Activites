import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import { vibeStore } from './server/store.ts';
import type { AnswerChoice } from './src/shared/questions.ts';

const PORT = Number(process.env.PORT || 3000);
const TA_PASSCODE = process.env.TA_PASSCODE || 'vibe-ta-2026';

function loadOrCreateAuthSecret(): string {
  if (process.env.TA_AUTH_SECRET && process.env.TA_AUTH_SECRET.trim().length >= 16) {
    return process.env.TA_AUTH_SECRET.trim();
  }
  const dataDir = path.resolve(process.cwd(), 'data');
  const secretPath = path.join(dataDir, 'ta-secret.key');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (fs.existsSync(secretPath)) {
    const existing = fs.readFileSync(secretPath, 'utf8').trim();
    if (existing.length >= 32) return existing;
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(secretPath, generated, 'utf8');
  return generated;
}

const AUTH_SECRET = loadOrCreateAuthSecret();

function signTaToken(): string {
  const payload = Buffer.from(
    JSON.stringify({
      role: 'ta',
      iat: Date.now(),
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
    })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyTaToken(token: string | undefined): boolean {
  if (!token || !token.includes('.')) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length) return false;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;

  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      role?: string;
      exp?: number;
    };
    return decoded.role === 'ta' && typeof decoded.exp === 'number' && decoded.exp > Date.now();
  } catch {
    return false;
  }
}

function extractTaToken(req: Request): string | undefined {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (typeof req.query.token === 'string' && req.query.token.trim()) {
    return req.query.token.trim();
  }
  return undefined;
}

function requireTaAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractTaToken(req);
  if (!verifyTaToken(token)) {
    res.status(401).json({ error: 'TA authentication required.' });
    return;
  }
  next();
}

const publicResultClients = new Set<Response>();
const taClients = new Set<Response>();

function sendSseEvent(res: Response, eventName: string, data: unknown): void {
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function broadcastPublicResults(eventName = 'results'): void {
  const payload = vibeStore.getPublicLiveResults();
  for (const client of publicResultClients) {
    try {
      sendSseEvent(client, eventName, payload);
    } catch {
      publicResultClients.delete(client);
    }
  }
}

function broadcastTaOverview(eventName = 'ta_overview'): void {
  const payload = vibeStore.getTaDashboardPayload();
  for (const client of taClients) {
    try {
      sendSseEvent(client, eventName, payload);
    } catch {
      taClients.delete(client);
    }
  }
}

async function createApp() {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  // Health & Active Session Info
  app.get('/api/session/active', (_req, res) => {
    res.json({ session: vibeStore.getActiveSessionPublic() });
  });

  // Student Join (Prevents duplicate participation via deviceId + token)
  app.post('/api/students/join', async (req, res) => {
    const body = req.body as {
      name?: unknown;
      deviceId?: unknown;
      joinCode?: unknown;
      existingToken?: unknown;
    };

    if (typeof body.name !== 'string' || typeof body.deviceId !== 'string') {
      res.status(400).json({ error: 'Name and browser identifier are required.' });
      return;
    }

    const result = await vibeStore.joinStudent({
      name: body.name,
      deviceId: body.deviceId,
      joinCode: typeof body.joinCode === 'string' ? body.joinCode : undefined,
      existingToken: typeof body.existingToken === 'string' ? body.existingToken : undefined,
    });

    if (!result.ok) {
      res.status(result.status).json({ error: result.error, code: result.code });
      return;
    }

    broadcastPublicResults();
    broadcastTaOverview();
    res.json({
      student: result.student,
      studentToken: result.studentToken,
      resumed: result.resumed,
    });
  });

  // Student Restore Own Progress (Requires studentId + studentToken)
  app.get('/api/students/me', (req, res) => {
    const studentId = typeof req.query.studentId === 'string' ? req.query.studentId : '';
    const studentToken = req.headers['x-student-token'];
    if (!studentId || typeof studentToken !== 'string') {
      res.status(401).json({ error: 'Missing student session credentials.' });
      return;
    }
    const student = vibeStore.getStudentSelf(studentId, studentToken);
    if (!student) {
      res.status(404).json({ error: 'Active student session not found.' });
      return;
    }
    res.json({ student, session: vibeStore.getActiveSessionPublic() });
  });

  // Student Save Single Answer (Auto-save)
  app.patch('/api/students/:id/answer', async (req, res) => {
    const studentId = String(req.params.id);
    const studentToken = req.headers['x-student-token'];
    if (typeof studentToken !== 'string') {
      res.status(401).json({ error: 'Missing student session token.' });
      return;
    }

    const body = req.body as { questionId?: unknown; choice?: unknown };
    if (typeof body.questionId !== 'string' || (body.choice !== 'A' && body.choice !== 'B')) {
      res.status(400).json({ error: 'Valid questionId and choice (A or B) are required.' });
      return;
    }

    const result = await vibeStore.saveAnswer({
      studentId,
      studentToken,
      questionId: body.questionId,
      choice: body.choice as AnswerChoice,
    });

    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }

    broadcastTaOverview();
    res.json({ student: result.student });
  });

  // Student Complete Questionnaire
  app.post('/api/students/:id/complete', async (req, res) => {
    const studentId = String(req.params.id);
    const studentToken = req.headers['x-student-token'];
    if (typeof studentToken !== 'string') {
      res.status(401).json({ error: 'Missing student session token.' });
      return;
    }

    const result = await vibeStore.completeStudent({
      studentId,
      studentToken,
    });

    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }

    broadcastPublicResults();
    broadcastTaOverview();
    res.json({ student: result.student });
  });

  // Public Aggregated Live Results (NO individual names or answers)
  app.get('/api/results/live', (_req, res) => {
    res.json(vibeStore.getPublicLiveResults());
  });

  // Public SSE Stream for Live Results
  app.get('/api/stream/results', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    publicResultClients.add(res);
    sendSseEvent(res, 'results', vibeStore.getPublicLiveResults());

    const keepAlive = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(keepAlive);
        publicResultClients.delete(res);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(keepAlive);
      publicResultClients.delete(res);
    });
  });

  // TA Authentication
  app.post('/api/ta/login', (req, res) => {
    const body = req.body as { passcode?: unknown };
    if (typeof body.passcode !== 'string') {
      res.status(400).json({ error: 'Passcode is required.' });
      return;
    }

    const providedBuf = Buffer.from(body.passcode.trim());
    const expectedBuf = Buffer.from(TA_PASSCODE);
    const match =
      providedBuf.length === expectedBuf.length &&
      crypto.timingSafeEqual(providedBuf, expectedBuf);

    if (!match) {
      res.status(401).json({ error: 'Incorrect TA passcode.' });
      return;
    }

    const token = signTaToken();
    res.json({ token });
  });

  app.get('/api/ta/verify', requireTaAuth, (_req, res) => {
    res.json({ authenticated: true });
  });

  // TA Protected Overview
  app.get('/api/ta/overview', requireTaAuth, (_req, res) => {
    res.json(vibeStore.getTaDashboardPayload());
  });

  // TA Protected Individual Student Details
  app.get('/api/ta/students/:id', requireTaAuth, (req, res) => {
    const student = vibeStore.getTaStudentById(String(req.params.id));
    if (!student) {
      res.status(404).json({ error: 'Student not found in active session.' });
      return;
    }
    res.json({ student });
  });

  // TA Protected CSV Export
  app.get('/api/ta/export.csv', requireTaAuth, (_req, res) => {
    const csv = vibeStore.buildCsvExport();
    const session = vibeStore.getActiveSessionPublic();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="class-vibe-check-${session.joinCode.toLowerCase()}.csv"`
    );
    res.send(csv);
  });

  // TA Protected Session Management: Start New Session
  app.post('/api/ta/session/new', requireTaAuth, async (req, res) => {
    const body = req.body as { label?: unknown };
    const label = typeof body.label === 'string' ? body.label : undefined;
    const session = await vibeStore.startNewSession(label);
    broadcastPublicResults('session_reset');
    broadcastTaOverview('session_reset');
    res.json({ session });
  });

  // TA Protected Session Management: Reset Current Session
  app.post('/api/ta/session/reset', requireTaAuth, async (_req, res) => {
    const session = await vibeStore.resetCurrentSession();
    broadcastPublicResults('session_reset');
    broadcastTaOverview('session_reset');
    res.json({ session });
  });

  // TA Protected SSE Stream
  app.get('/api/stream/ta', requireTaAuth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    taClients.add(res);
    sendSseEvent(res, 'ta_overview', vibeStore.getTaDashboardPayload());

    const keepAlive = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(keepAlive);
        taClients.delete(res);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(keepAlive);
      taClients.delete(res);
    });
  });

  // Vite Dev Middleware or Production Static Serving
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`The Class Vibe Check server running on http://0.0.0.0:${PORT}`);
  });
}

createApp().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
