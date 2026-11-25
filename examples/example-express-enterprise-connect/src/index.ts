import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import {
  ServerClient,
  CookieTransactionStore,
  isFederatedDomain,
} from '@auth0/auth0-server-js';
import { StoreOptions } from './types.js';
import { ExpressCookieHandler } from './store/express-cookie-handler.js';

const domain = process.env.AUTH0_DOMAIN!;
const clientId = process.env.AUTH0_CLIENT_ID!;
const clientSecret = process.env.AUTH0_CLIENT_SECRET!;
const sessionSecret = process.env.AUTH0_SESSION_SECRET!;
const appBaseUrl = process.env.APP_BASE_URL || 'http://localhost:3000';

// ─── Enterprise Connect ServerClient ───────────────────────────────────────────
// No stateStore — Auth0 is a pure SSO relay, the app owns its session.

const auth0 = new ServerClient<StoreOptions>({
  domain,
  clientId,
  clientSecret,
  enterpriseConnect: true,
  authorizationParams: {
    redirect_uri: `${appBaseUrl}/auth/callback`,
    scope: 'openid profile email',
  },
  transactionStore: new CookieTransactionStore(
    { secret: sessionSecret },
    new ExpressCookieHandler()
  ),
});

// ─── App session helpers ───────────────────────────────────────────────────────

interface AppSession {
  sub: string;
  email: string;
  orgId: string;
  name?: string;
}

const enc = new TextEncoder();

const key = () =>
  crypto.subtle.importKey(
    'raw',
    enc.encode(sessionSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

async function getAppSession(req: Request): Promise<AppSession | null> {
  const raw = req.cookies['app_session'];
  if (!raw) return null;
  const [body, signature] = raw.split('.');
  if (!body || !signature) return null;
  try {
    const valid = await crypto.subtle.verify(
      'HMAC',
      await key(),
      Buffer.from(signature, 'base64url'),
      enc.encode(body)
    );
    return valid ? (JSON.parse(Buffer.from(body, 'base64url').toString()) as AppSession) : null;
  } catch {
    return null;
  }
}

async function setAppSession(res: Response, session: AppSession): Promise<void> {
  const body = Buffer.from(JSON.stringify(session)).toString('base64url');
  const signature = Buffer.from(
    await crypto.subtle.sign('HMAC', await key(), enc.encode(body))
  ).toString('base64url');
  res.cookie('app_session', `${body}.${signature}`, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

function clearAppSession(res: Response): void {
  res.clearCookie('app_session', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

async function requireSession(req: Request, res: Response, next: NextFunction) {
  const session = await getAppSession(req);
  if (!session) return res.redirect('/login');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (req as any).appUser = session;
  next();
}

// ─── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Root — redirect to dashboard or login
app.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const session = await getAppSession(req);
    res.redirect(session ? '/dashboard' : '/login');
  } catch (err) {
    next(err);
  }
});

// Login form
app.get('/login', (_req: Request, res: Response) => {
  res.send(`
    <h1>Enterprise Connect Example</h1>
    <form method="POST" action="/login">
      <label>Email: <input type="email" name="email" required placeholder="user@enterprise.com" /></label>
      <button type="submit">Continue</button>
    </form>
  `);
});

// Step 1: Domain discovery + redirect to Auth0 (or redirect for non-federated login)
app.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = req.body.email as string;

    const authUrl = await auth0.startEnterpriseLogin(
      { email, returnTo: '/dashboard' },
      { request: req, response: res }
    );

    if (authUrl) {
      return res.redirect(authUrl.href);
    }

    // Domain is not federated — replace '/login?mode=password' with your existing login route
    res.redirect('/login?mode=password');
  } catch (err) {
    next(err);
  }
});

// Step 2: Callback — exchange code for tokens, create app session
app.get('/auth/callback', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await auth0.completeInteractiveLogin<{ returnTo?: string }>(
      new URL(req.url, appBaseUrl),
      { request: req, response: res }
    );

    const user = result.user;

    if (!user) {
      return res.redirect('/login?error=no-session');
    }

    // Create the app-owned session (Auth0 writes nothing)
    // Optional: validate org_id against an application allowlist before trusting it.
    // if (user['org_id'] !== expectedOrgId) throw new Error('Unexpected organization');
    await setAppSession(res, {
      sub: user.sub as string,
      email: user.email as string,
      orgId: (user['org_id'] ?? '') as string,
      name: user.name as string | undefined,
    });

    const returnTo = result.appState?.returnTo ?? '/';
    res.redirect(returnTo);
  } catch (err) {
    next(err);
  }
});

// Dashboard — protected
app.get('/dashboard', requireSession as express.RequestHandler, (req: Request, res: Response) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const user = (req as any).appUser as AppSession;
  res.send(`
    <h1>Dashboard</h1>
    <p><strong>Email:</strong> ${user.email}</p>
    <p><strong>Sub:</strong> ${user.sub}</p>
    <p><strong>Org ID:</strong> ${user.orgId}</p>
    <p><strong>Name:</strong> ${user.name ?? '(not provided)'}</p>
    <hr>
    <a href="/auth/logout">Sign out (federated)</a>
  `);
});

// Step 3: Logout — clear app session + federated logout at Auth0/IdP
app.get('/auth/logout', async (req: Request, res: Response, next: NextFunction) => {
  try {
    clearAppSession(res);

    const logoutUrl = await auth0.logout(
      { returnTo: `${appBaseUrl}/login`, federated: true },
      { request: req, response: res }
    );

    res.redirect(logoutUrl.href);
  } catch (err) {
    next(err);
  }
});

// ─── Utility: standalone isFederatedDomain check ───────────────────────────────
app.get('/check-domain', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = String(req.query.email ?? '');
    const emailDomain = email.split('@')[1];
    if (!emailDomain) {
      res.status(400).send('?email= required');
      return;
    }

    const federated = await isFederatedDomain(domain, emailDomain);
    res.json({ domain: emailDomain, federated });
  } catch (err) {
    next(err);
  }
});

// ─── Error handler ─────────────────────────────────────────────────────────────

// Express 5 error handler — must have exactly 4 params
app.use(function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error(err);
  res.status(500).send(`<pre>${err.stack ?? err.message}</pre>`);
});

// ─── Start ─────────────────────────────────────────────────────────────────────

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`Enterprise Connect example running at ${appBaseUrl}`);
  console.log(`  POST /login           — submit email for domain discovery`);
  console.log(`  GET  /auth/callback   — code exchange, creates app session`);
  console.log(`  GET  /auth/logout     — clears app session + federated logout`);
  console.log(`  GET  /check-domain?email=user@acme.com — standalone WebFinger check`);
});
