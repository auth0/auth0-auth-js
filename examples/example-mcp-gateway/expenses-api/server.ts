import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { ApiClient } from '@auth0/auth0-api-js';
import { createRoutes } from './routes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN!;
const EXPENSES_AUDIENCE = process.env.EXPENSES_API_AUDIENCE!;
const PORT = Number(process.env.EXPENSES_API_PORT ?? 4000);

const apiClient = new ApiClient({
  domain: AUTH0_DOMAIN,
  audience: EXPENSES_AUDIENCE,
});

const app = express();
app.use(express.json());

app.use(async (req, res, next) => {
  console.log(`[Expenses API] ${req.method} ${req.path}`);

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log(`[Expenses API]   ❌ 401 - Missing or invalid Authorization header`);
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  try {
    const token = authHeader.slice(7);
    const claims = await apiClient.verifyAccessToken({
      accessToken: token,
      scheme: 'bearer',
      headers: req.headers as Record<string, string | string[] | undefined>,
      httpUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
    });
    res.locals.claims = claims;
    console.log(`[Expenses API]   ✓ Authenticated as ${claims.sub}`);
    next();
  } catch (err) {
    console.log(`[Expenses API]   ❌ 401 - ${(err as Error).message}`);
    res.status(401).json({ error: 'Invalid access token', details: (err as Error).message });
  }
});

const expenses = JSON.parse(readFileSync(resolve(__dirname, 'data/expenses.json'), 'utf-8'));
app.use(createRoutes(expenses));

app.listen(PORT, () => {
  console.log(`[Expenses API] listening on http://localhost:${PORT}`);
  console.log(`  Audience: ${EXPENSES_AUDIENCE}`);
});
